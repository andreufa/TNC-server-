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

// CryptoServer handles the RSA challenge-response handshake over TCP.
type CryptoServer struct {
	addr    string
	devices *store.DeviceStore
	hub     *hub.Hub
	logChan chan<- string

	ln   net.Listener
	wg   sync.WaitGroup
	quit chan struct{}
}

// NewCryptoServer creates a new crypto handshake server.
func NewCryptoServer(addr string, devices *store.DeviceStore, h *hub.Hub, logChan chan<- string) *CryptoServer {
	return &CryptoServer{
		addr:    addr,
		devices: devices,
		hub:     h,
		logChan: logChan,
		quit:    make(chan struct{}),
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

func trimDeviceID(b []byte) string {
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

	reader := bufio.NewReader(conn)
	frameReader := NewFrameReader(reader)

	// === Step 1: Read Hello (Addr=0x60, Cmd=0x65) ===
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	fr, raw, err := frameReader.ReadFrame()
	if err != nil {
		log.Printf("crypto-tcp: [%s] read hello: %v", remote, err)
		return
	}
	s.logRawFrame("", raw)
	if fr.Addr != AddrDeviceHello || fr.Cmd != CmdAuth {
		s.sendResult(conn, ResultSpecError, fr.Addr, fr.Cmd, "expected Addr=0x60 Cmd=0x65")
		return
	}
	deviceID := trimDeviceID(fr.Data)
	log.Printf("crypto-tcp: [%s] hello from device %q", remote, deviceID)
	s.logEvent("auth", deviceID, fmt.Sprintf("hello (Addr=0x%02x Cmd=0x%02x)", fr.Addr, fr.Cmd))

	// === Step 2: Look up device in DB ===
	pubKeyPEM, err := s.devices.GetPublicKey(context.Background(), deviceID)
	if err != nil {
		log.Printf("crypto-tcp: [%s] device %q not found: %v", remote, deviceID, err)
		s.sendResult(conn, ResultAuthError, 0, 0, "device not found")
		s.logEvent("auth", deviceID, "denied: device not found")
		return
	}

	inService, err := s.devices.IsInService(context.Background(), deviceID)
	if err != nil || !inService {
		log.Printf("crypto-tcp: [%s] device %q not in service", remote, deviceID)
		s.sendResult(conn, ResultAuthError, 0, 0, "device not in service")
		s.logEvent("auth", deviceID, "denied: not in service")
		return
	}

	// === Step 3: Generate and send challenge (Addr=0x61, Cmd=0x65) ===
	challenge, err := GenerateChallenge()
	if err != nil {
		log.Printf("crypto-tcp: [%s] generate challenge: %v", remote, err)
		s.sendResult(conn, ResultDecodeError, 0, 0, "internal error")
		return
	}
	log.Printf("crypto-tcp: [%s] sending challenge to %q (len=%d)", remote, deviceID, len(challenge))
	s.logEvent("message", deviceID, fmt.Sprintf("challenge sent (time=%x key=%x)", challenge[:8], challenge[8:]))

	challengeFrame := Frame{
		Addr: AddrServerChallenge,
		Cmd:  CmdAuth,
		Data: challenge,
	}
	if _, err := conn.Write(EncodeFrame(challengeFrame)); err != nil {
		log.Printf("crypto-tcp: [%s] send challenge: %v", remote, err)
		return
	}

	// === Step 4: Read authorization request (Addr=0x62, Cmd=0x65) ===
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	fr, _, err = frameReader.ReadFrame()
	if err != nil {
		log.Printf("crypto-tcp: [%s] read auth request: %v", remote, err)
		return
	}
	if fr.Addr != AddrDeviceAuth || fr.Cmd != CmdAuth {
		s.sendResult(conn, ResultSpecError, fr.Addr, fr.Cmd, "expected Addr=0x62 Cmd=0x65")
		return
	}

	// Parse: 10 bytes Device ID + 256 bytes RSA signature = 266 bytes
	respData := fr.Data
	if len(respData) < DeviceIDSize {
		s.sendResult(conn, ResultDecodeError, 0, 0, "response too short")
		return
	}
	respDeviceID := trimDeviceID(respData[:DeviceIDSize])
	signature := respData[DeviceIDSize:]

	if respDeviceID != deviceID {
		log.Printf("crypto-tcp: [%s] device ID mismatch: hello=%q, response=%q", remote, deviceID, respDeviceID)
		s.sendResult(conn, ResultAuthError, 0, 0, "device ID mismatch")
		return
	}

	log.Printf("crypto-tcp: [%s] received auth request from %q (sig len=%d)", remote, deviceID, len(signature))
	s.logEvent("message", deviceID, fmt.Sprintf("auth request (Addr=0x%02x Cmd=0x%02x sig=%d)", fr.Addr, fr.Cmd, len(signature)))

	// === Step 5: Check TTL ===
	expired, err := IsChallengeExpired(challenge)
	if err != nil {
		log.Printf("crypto-tcp: [%s] check TTL: %v", remote, err)
		s.sendResult(conn, ResultDecodeError, 0, 0, "internal error")
		return
	}
	if expired {
		log.Printf("crypto-tcp: [%s] challenge expired for %q", remote, deviceID)
		s.sendResult(conn, ResultAuthError, 0, 0, "challenge expired")
		s.logEvent("auth", deviceID, "denied: challenge expired")
		return
	}

	// === Step 6: Verify signature ===
	pubKey, err := ParsePublicKey(pubKeyPEM)
	if err != nil {
		log.Printf("crypto-tcp: [%s] parse public key for %q: %v", remote, deviceID, err)
		s.sendResult(conn, ResultDecodeError, 0, 0, "internal error")
		return
	}

	if err := VerifyChallengeResponse(pubKey, challenge, signature); err != nil {
		log.Printf("crypto-tcp: [%s] signature verification failed for %q: %v", remote, deviceID, err)
		s.sendResult(conn, ResultAuthError, 0, 0, "signature verification failed")
		s.logEvent("auth", deviceID, "denied: signature verification failed")
		return
	}

	// === Step 7: Success — subscribe to hub ===
	log.Printf("crypto-tcp: [%s] device %q authenticated successfully", remote, deviceID)
	s.logEvent("auth", deviceID, "authorized")

	if err := s.devices.UpdateLastSeen(context.Background(), deviceID); err != nil {
		log.Printf("crypto-tcp: [%s] update last seen for %q: %v", remote, deviceID, err)
	}

	// Subscribe to hub for broadcast
	sub := s.hub.Subscribe()
	defer s.hub.Unsubscribe(sub)
	log.Printf("crypto-tcp: [%s] device %q subscribed (id=%d)", remote, deviceID, sub.ID())

	// Build result: 10 bytes device ID + 1 byte code
	resultData := make([]byte, DeviceIDSize+1)
	copy(resultData[:DeviceIDSize], padDeviceID(deviceID))
	resultData[DeviceIDSize] = ResultAuthorized

	resultFrame := Frame{
		Addr: AddrServerResult,
		Cmd:  CmdAuth,
		Data: resultData,
	}
	if _, err := conn.Write(EncodeFrame(resultFrame)); err != nil {
		log.Printf("crypto-tcp: [%s] send result: %v", remote, err)
		return
	}

	log.Printf("crypto-tcp: [%s] handshake complete for %q", remote, deviceID)

	// Start writer goroutine: forward broadcast data to this device.
	// Stops when sub.C is closed (on unsubscribe) or conn write fails.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for data := range sub.C {
			// Wrap broadcast data in a frame and send to device
			bcFrame := Frame{
				Addr: AddrServerResult,
				Cmd:  CmdAuth,
				Data: data,
			}
			if _, err := conn.Write(EncodeFrame(bcFrame)); err != nil {
				return
			}
		}
	}()

	// === Post-handshake: read loop with broadcast ===
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		fr, _, err := frameReader.ReadFrame()
		if err != nil {
			if errNet, ok := err.(net.Error); ok && errNet.Timeout() {
				log.Printf("crypto-tcp: [%s] idle timeout for %q", remote, deviceID)
				s.logEvent("disconnect", deviceID, "idle timeout")
			} else {
				log.Printf("crypto-tcp: [%s] read error for %q: %v", remote, deviceID, err)
				s.logEvent("disconnect", deviceID, fmt.Sprintf("disconnected: %v", err))
			}
			return
		}
		log.Printf("crypto-tcp: [%s] message from %q: Addr=0x%02x Cmd=0x%02x data=%x",
			remote, deviceID, fr.Addr, fr.Cmd, fr.Data)
		s.logEvent("message", deviceID, fmt.Sprintf("Addr=0x%02x Cmd=0x%02x data=%x", fr.Addr, fr.Cmd, fr.Data))

		if err := s.devices.UpdateLastSeen(context.Background(), deviceID); err != nil {
			log.Printf("crypto-tcp: [%s] update last seen for %q: %v", remote, deviceID, err)
		}

		// Process command and broadcast to other subscribers
		broadcastData := s.processCommand(fr, deviceID)
		if broadcastData != nil {
			s.logEvent("broadcast", deviceID, hex.EncodeToString(broadcastData))
			s.hub.Broadcast(broadcastData, sub.ID())
		}
	}
}

// processCommand handles a post-auth command frame from a device.
// Returns data to broadcast to other subscribers, or nil to skip broadcast.
// Override this method or extend it for command-specific preprocessing.
func (s *CryptoServer) processCommand(fr Frame, deviceID string) []byte {
	// Default: broadcast the raw frame data to other subscribers.
	// Different commands can be handled with different preprocessing.
	switch fr.Addr {
	// Future: add command-specific cases here, e.g.:
	// case 0x70:
	//     return preprocessTelemetry(fr.Data, deviceID)
	default:
		// Broadcast the full frame (Addr + Cmd + Data) to others
		out := make([]byte, 1+1+len(fr.Data))
		out[0] = fr.Addr
		out[1] = fr.Cmd
		copy(out[2:], fr.Data)
		return out
	}
}

func (s *CryptoServer) sendResult(conn net.Conn, code byte, gotAddr, gotCmd byte, reason string) {
	resultData := []byte(fmt.Sprintf("err:%s", reason))
	frame := Frame{
		Addr: AddrServerResult,
		Cmd:  CmdAuth,
		Data: resultData,
	}
	conn.Write(EncodeFrame(frame))
	log.Printf("crypto-tcp: sendResult code=0x%02x reason=%s", code, reason)
}

func (s *CryptoServer) logRawFrame(deviceID string, raw []byte) {
	if s.logChan == nil {
		return
	}
	select {
	case s.logChan <- formatLog("message", deviceID, "RAW "+hex.EncodeToString(raw)):
	default:
	}
}

func (s *CryptoServer) logEvent(eventType, deviceID, message string) {
	if s.logChan == nil {
		return
	}
	select {
	case s.logChan <- formatLog(eventType, deviceID, message):
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
	dataLen := binary.BigEndian.Uint16(header[2:4])

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
	binary.BigEndian.PutUint16(full[3:5], dataLen)
	copy(full[5:5+dataLen], rest[:dataLen])
	full[total-1] = rest[dataLen]

	f, err := DecodeFrame(full)
	return f, full, err
}

// formatLog creates a JSON log entry string for the web log viewer.
func formatLog(eventType, deviceID, message string) string {
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
