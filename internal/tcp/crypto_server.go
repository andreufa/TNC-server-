package tcp

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"tnc-server/internal/hub"
	"tnc-server/internal/store"
)

// CryptoServer accepts TCP connections and dispatches frames to command handlers.
type CryptoServer struct {
	addr     string
	devices  *store.DeviceStore
	hub      *hub.Hub
	logChan  chan<- string
	handlers map[byte]HandlerFactory // cmd → factory (creates per-connection handler)

	ln   net.Listener
	wg   sync.WaitGroup
	quit chan struct{}
}

// NewCryptoServer creates a new crypto TCP server with the given command handler factories.
func NewCryptoServer(addr string, devices *store.DeviceStore, h *hub.Hub, logChan chan<- string, handlers map[byte]HandlerFactory) *CryptoServer {
	return &CryptoServer{
		addr:     addr,
		devices:  devices,
		hub:      h,
		logChan:  logChan,
		handlers: handlers,
		quit:     make(chan struct{}),
	}
}

// ListenAndServe starts accepting connections.
func (s *CryptoServer) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	log.Printf("crypto-tcp: listening on %s", s.addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return nil
			default:
				return err
			}
		}
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// Shutdown gracefully stops the server.
func (s *CryptoServer) Shutdown() {
	close(s.quit)
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
}

func padDeviceID(id string) []byte {
	buf := make([]byte, DeviceIDSize)
	copy(buf, id)
	return buf
}

// TrimDeviceID strips trailing null bytes and spaces from a device ID buffer.
func TrimDeviceID(b []byte) string {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0 && b[i] != ' ' {
			return string(b[:i+1])
		}
	}
	return ""
}

func (s *CryptoServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	log.Printf("crypto-tcp: [%s] new connection", remote)
	s.logEvent("connect", remote, "new connection")

	connDone := make(chan struct{})
	defer close(connDone)

	reader := bufio.NewReader(conn)
	frameReader := NewFrameReader(reader)

	// Per-connection context shared across command handlers.
	ctx := &CmdContext{
		Devices: s.devices,
		Hub:     s.hub,
		LogChan: s.logChan,
	}

	var (
		subscribed bool
		sub        *hub.Subscriber
	)

	// Per-connection handler instances created from factories on first use.
	perConnHandlers := make(map[byte]CmdHandler)

	// --- Per-connection read loop ---
	// Before authentication, only command 0x65 (AT) is allowed.
	// After authentication, all registered commands are dispatched.
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		fr, raw, err := frameReader.ReadFrame()
		if err != nil {
			if errNet, ok := err.(net.Error); ok && errNet.Timeout() {
				log.Printf("crypto-tcp: [%s] idle timeout for %q", remote, ctx.DeviceID)
				s.logEvent("disconnect", ctx.DeviceID, "idle timeout")
			} else {
				log.Printf("crypto-tcp: [%s] read error for %q: %v", remote, ctx.DeviceID, err)
				s.logEvent("disconnect", ctx.DeviceID, fmt.Sprintf("disconnected: %v", err))
			}
			return
		}

		log.Printf("crypto-tcp: [%s] frame from %q: Addr=0x%02x Cmd=0x%02x data=%x crc=0x%02x",
			remote, ctx.DeviceID, fr.Addr, fr.Cmd, fr.Data, raw[len(raw)-1])
		s.logRawFrame(ctx.DeviceID, raw)

		// Before authentication is complete, only command 0x65 is allowed.
		if !ctx.Authenticated && fr.Cmd != CmdAuth {
			log.Printf("crypto-tcp: [%s] refused Cmd=0x%02x before auth", remote, fr.Cmd)
			continue
		}

		handler := perConnHandlers[fr.Cmd]
		if handler == nil {
			factory, ok := s.handlers[fr.Cmd]
			if !ok {
				log.Printf("crypto-tcp: [%s] no handler for Cmd=0x%02x", remote, fr.Cmd)
				continue
			}
			handler = factory()
			perConnHandlers[fr.Cmd] = handler
		}

		broadcastData, err := handler.Handle(fr, conn, ctx)
		if err != nil {
			log.Printf("crypto-tcp: [%s] handler error for Cmd=0x%02x: %v", remote, fr.Cmd, err)
			// If auth failed (cmd 0x65 returned error before auth complete), close connection.
			// Ensure the error status frame is flushed before closing.
			if !ctx.Authenticated {
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetLinger(1) // wait up to 1s for pending writes
				}
				return
			}
			continue
		}

		// After authorization is fully complete (two statuses sent), subscribe to hub.
		if ctx.Authenticated && !subscribed {
			subscribed = true
			sub = s.hub.Subscribe()
			go func() {
				defer s.hub.Unsubscribe(sub)
				for {
					select {
					case <-connDone:
						return
					case data, ok := <-sub.C:
						if !ok {
							return
						}
						// Broadcast data format: [Addr(1), Cmd(1), Payload(N)]
						var bcAddr, bcCmd byte
						var bcData []byte
						if len(data) >= 2 {
							bcAddr = data[0]
							bcCmd = data[1]
							bcData = data[2:]
						} else {
							bcAddr = AddrServerStatus
							bcCmd = CmdAuth
							bcData = data
						}
						bcFrame := Frame{
							Addr: bcAddr,
							Cmd:  bcCmd,
							Data: bcData,
						}
						if _, err := conn.Write(EncodeFrame(bcFrame)); err != nil {
							return
						}
					}
				}
			}()
			log.Printf("crypto-tcp: [%s] device %q subscribed to hub (id=%d)", remote, ctx.DeviceID, sub.ID())
		}

		// Broadcast to other subscribers.
		if broadcastData != nil {
			// Build full frame for logging.
			bcFrame := Frame{
				Addr: broadcastData[0],
				Cmd:  broadcastData[1],
				Data: broadcastData[2:],
			}
			s.logEvent("broadcast", ctx.DeviceID, "→ "+hex.EncodeToString(EncodeFrame(bcFrame)))
			senderID := uint64(0)
			if sub != nil {
				senderID = sub.ID()
			}
			s.hub.Broadcast(broadcastData, senderID)
		}

		if ctx.DeviceID != "" {
			if err := s.devices.UpdateLastSeen(context.Background(), ctx.DeviceID); err != nil {
				log.Printf("crypto-tcp: [%s] update last seen for %q: %v", remote, ctx.DeviceID, err)
			}
		}
	}
}

func (s *CryptoServer) logRawFrame(deviceID string, raw []byte) {
	if s.logChan == nil {
		return
	}
	select {
	case s.logChan <- FormatLog("message", deviceID, "← RAW "+hex.EncodeToString(raw)):
	default:
	}
}

func (s *CryptoServer) logEvent(eventType, deviceID, message string) {
	if s.logChan == nil {
		return
	}
	select {
	case s.logChan <- FormatLog(eventType, deviceID, message):
	default:
	}
}

// FrameReader reads and decodes binary frames from a buffered reader.
type FrameReader struct {
	rd *bufio.Reader
}

// NewFrameReader creates a FrameReader wrapping the given reader.
func NewFrameReader(rd *bufio.Reader) *FrameReader {
	return &FrameReader{rd: rd}
}

// ReadFrame reads one complete frame. It scans for the preamble byte, then
// reads the header, data, and CRC. Returns the decoded Frame, the raw frame
// bytes, and any error.
func (fr *FrameReader) ReadFrame() (Frame, []byte, error) {
	// Scan for preamble
	for {
		b, err := fr.rd.ReadByte()
		if err != nil {
			return Frame{}, nil, fmt.Errorf("read preamble: %w", err)
		}
		if b == FramePreamble {
			break
		}
	}

	// Read the next 4 bytes: addr + cmd + len(2)
	header := make([]byte, 4)
	if _, err := io.ReadFull(fr.rd, header); err != nil {
		return Frame{}, nil, fmt.Errorf("read header: %w", err)
	}

	addr := header[0]
	cmd := header[1]
	dataLen := binary.LittleEndian.Uint16(header[2:4])

	if dataLen > FrameMaxDataLen {
		return Frame{}, nil, fmt.Errorf("data length %d exceeds max %d", dataLen, FrameMaxDataLen)
	}

	// Read data + CRC
	rest := make([]byte, int(dataLen)+1) // +1 for CRC
	if _, err := io.ReadFull(fr.rd, rest); err != nil {
		return Frame{}, nil, fmt.Errorf("read data+crc: %w", err)
	}

	// Reconstruct the full frame for CRC verification
	total := FrameMinLen + int(dataLen)
	full := make([]byte, total)
	full[0] = FramePreamble
	full[1] = addr
	full[2] = cmd
	binary.LittleEndian.PutUint16(full[3:5], dataLen)
	copy(full[5:5+dataLen], rest[:dataLen])
	full[total-1] = rest[dataLen]

	f, err := DecodeFrame(full)
	return f, full, err
}

// FormatLog creates a JSON log entry string for the web log viewer.
func FormatLog(eventType, deviceID, message string) string {
	logEntry := struct {
		Timestamp string `json:"timestamp"`
		Type      string `json:"type"`
		DeviceID  string `json:"deviceId"`
		Message   string `json:"message"`
	}{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Type:      eventType,
		DeviceID:  deviceID,
		Message:   message,
	}

	data, _ := json.Marshal(logEntry)
	return string(data)
}
