package tcp

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"tnc-server/internal/store"
)

// CryptoServer handles the RSA challenge-response handshake over TCP.
type CryptoServer struct {
	addr    string
	devices *store.DeviceStore
	logChan chan<- string

	ln   net.Listener
	wg   sync.WaitGroup
	quit chan struct{}
}

// NewCryptoServer creates a new crypto handshake server.
func NewCryptoServer(addr string, devices *store.DeviceStore, logChan chan<- string) *CryptoServer {
	return &CryptoServer{
		addr:    addr,
		devices: devices,
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

func (s *CryptoServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	log.Printf("crypto-tcp: [%s] new connection", remote)
	s.logEvent("connect", remote, "new connection")

	reader := bufio.NewReader(conn)
	frameReader := NewFrameReader(reader)

	// === Step 1: Read Hello (device sends its ID) ===
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	fr, err := frameReader.ReadFrame()
	if err != nil {
		log.Printf("crypto-tcp: [%s] read hello: %v", remote, err)
		return
	}
	if fr.Cmd != CmdHello {
		s.sendDenied(conn, fmt.Sprintf("expected hello (0x%02x), got 0x%02x", CmdHello, fr.Cmd))
		return
	}
	deviceID := string(fr.Data)
	log.Printf("crypto-tcp: [%s] hello from device %q", remote, deviceID)
	s.logEvent("auth", deviceID, fmt.Sprintf("hello from %s", remote))

	// === Step 2: Look up device in DB, get public key ===
	pubKeyPEM, err := s.devices.GetPublicKey(context.Background(), deviceID)
	if err != nil {
		log.Printf("crypto-tcp: [%s] device %q not found or no public key: %v", remote, deviceID, err)
		s.sendDenied(conn, "device not found")
		s.logEvent("auth", deviceID, "denied: device not found")
		return
	}

	// === Step 3: Check device is in service ===
	inService, err := s.devices.IsInService(context.Background(), deviceID)
	if err != nil || !inService {
		log.Printf("crypto-tcp: [%s] device %q not in service", remote, deviceID)
		s.sendDenied(conn, "device not in service")
		s.logEvent("auth", deviceID, "denied: not in service")
		return
	}

	// === Step 4: Generate challenge ===
	challenge, err := GenerateChallenge()
	if err != nil {
		log.Printf("crypto-tcp: [%s] generate challenge: %v", remote, err)
		s.sendDenied(conn, "internal error")
		return
	}
	log.Printf("crypto-tcp: [%s] sending challenge to %q (len=%d)", remote, deviceID, len(challenge))

	// === Step 5: Send challenge to device ===
	challengeFrame := Frame{
		Addr: AddrServer,
		Cmd:  CmdChallenge,
		Data: challenge,
	}
	if _, err := conn.Write(EncodeFrame(challengeFrame)); err != nil {
		log.Printf("crypto-tcp: [%s] send challenge: %v", remote, err)
		return
	}

	// === Step 6: Read response (device ID + signature) ===
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	fr, err = frameReader.ReadFrame()
	if err != nil {
		log.Printf("crypto-tcp: [%s] read response: %v", remote, err)
		return
	}
	if fr.Cmd != CmdResponse {
		s.sendDenied(conn, fmt.Sprintf("expected response (0x%02x), got 0x%02x", CmdResponse, fr.Cmd))
		return
	}

	// Parse response: [2 bytes: deviceID length] [deviceID] [signature]
	respData := fr.Data
	if len(respData) < 2 {
		s.sendDenied(conn, "response too short")
		return
	}
	idLen := binary.BigEndian.Uint16(respData[:2])
	if len(respData) < int(2+idLen) {
		s.sendDenied(conn, "response truncated")
		return
	}
	respDeviceID := string(respData[2 : 2+idLen])
	signature := respData[2+idLen:]

	if respDeviceID != deviceID {
		log.Printf("crypto-tcp: [%s] device ID mismatch: hello=%q, response=%q", remote, deviceID, respDeviceID)
		s.sendDenied(conn, "device ID mismatch")
		return
	}

	log.Printf("crypto-tcp: [%s] received response from %q (sig len=%d)", remote, deviceID, len(signature))

	// === Step 7: Check challenge TTL ===
	expired, err := IsChallengeExpired(challenge)
	if err != nil {
		log.Printf("crypto-tcp: [%s] check TTL: %v", remote, err)
		s.sendDenied(conn, "internal error")
		return
	}
	if expired {
		log.Printf("crypto-tcp: [%s] challenge expired for %q", remote, deviceID)
		s.sendDenied(conn, "challenge expired")
		s.logEvent("auth", deviceID, "denied: challenge expired")
		return
	}

	// === Step 8: Parse public key and verify signature ===
	pubKey, err := ParsePublicKey(pubKeyPEM)
	if err != nil {
		log.Printf("crypto-tcp: [%s] parse public key for %q: %v", remote, deviceID, err)
		s.sendDenied(conn, "internal error")
		return
	}

	if err := VerifyChallengeResponse(pubKey, challenge, signature); err != nil {
		log.Printf("crypto-tcp: [%s] signature verification failed for %q: %v", remote, deviceID, err)
		s.sendDenied(conn, "signature verification failed")
		s.logEvent("auth", deviceID, "denied: signature verification failed")
		return
	}

	// === Step 9: Success! ===
	log.Printf("crypto-tcp: [%s] device %q authenticated successfully", remote, deviceID)

	// Update last seen
	if err := s.devices.UpdateLastSeen(context.Background(), deviceID); err != nil {
		log.Printf("crypto-tcp: [%s] update last seen for %q: %v", remote, deviceID, err)
	}

	successFrame := Frame{
		Addr: AddrServer,
		Cmd:  CmdSuccess,
		Data: []byte("Success"),
	}
	if _, err := conn.Write(EncodeFrame(successFrame)); err != nil {
		log.Printf("crypto-tcp: [%s] send success: %v", remote, err)
		return
	}

	log.Printf("crypto-tcp: [%s] handshake complete for %q", remote, deviceID)
	s.logEvent("auth", deviceID, "handshake complete")

	// === Post-handshake: read loop ===
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		fr, err := frameReader.ReadFrame()
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
		log.Printf("crypto-tcp: [%s] message from %q: cmd=0x%02x data=%x", remote, deviceID, fr.Cmd, fr.Data)
		s.logEvent("message", deviceID, fmt.Sprintf("cmd=0x%02x data=%x", fr.Cmd, fr.Data))

		if err := s.devices.UpdateLastSeen(context.Background(), deviceID); err != nil {
			log.Printf("crypto-tcp: [%s] update last seen for %q: %v", remote, deviceID, err)
		}
	}
}

func (s *CryptoServer) sendDenied(conn net.Conn, reason string) {
	deniedFrame := Frame{
		Addr: AddrServer,
		Cmd:  CmdDenied,
		Data: []byte("Denied: " + reason),
	}
	conn.Write(EncodeFrame(deniedFrame))
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
// reads the header, data, and CRC. Returns the decoded Frame or an error.
func (fr *FrameReader) ReadFrame() (Frame, error) {
	// Scan for preamble
	for {
		b, err := fr.rd.ReadByte()
		if err != nil {
			return Frame{}, fmt.Errorf("read preamble: %w", err)
		}
		if b == FramePreamble {
			break
		}
	}

	// Read the next 4 bytes: addr + cmd + len(2)
	header := make([]byte, 4)
	if _, err := io.ReadFull(fr.rd, header); err != nil {
		return Frame{}, fmt.Errorf("read header: %w", err)
	}

	addr := header[0]
	cmd := header[1]
	dataLen := binary.BigEndian.Uint16(header[2:4])

	if dataLen > FrameMaxDataLen {
		return Frame{}, fmt.Errorf("data length %d exceeds max %d", dataLen, FrameMaxDataLen)
	}

	// Read data + CRC
	rest := make([]byte, int(dataLen)+1) // +1 for CRC
	if _, err := io.ReadFull(fr.rd, rest); err != nil {
		return Frame{}, fmt.Errorf("read data+crc: %w", err)
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

	return DecodeFrame(full)
}
