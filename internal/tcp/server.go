package tcp

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"net"
	"sync"
	"time"

	"tnc-server/internal/hub"
	"tnc-server/internal/store"
)

// idleTimeout closes a connection that sends nothing for this long (0 disables).
const idleTimeout = 5 * time.Minute

// handshake is the first line a device must send after connecting.
type handshake struct {
	DeviceID string `json:"device_id"`
	Password string `json:"password"`
}

// statusMsg is the server's reply to the handshake.
type statusMsg struct {
	Status string `json:"status"` // "ok" | "denied"
}

// Server is the TCP frontend that devices connect to.
type Server struct {
	addr    string
	devices *store.DeviceStore
	hub     *hub.Hub

	ln   net.Listener
	wg   sync.WaitGroup
	quit chan struct{}
}

func NewServer(addr string, devices *store.DeviceStore, h *hub.Hub) *Server {
	return &Server{
		addr:    addr,
		devices: devices,
		hub:     h,
		quit:    make(chan struct{}),
	}
}

// ListenAndServe starts accepting connections. It blocks until Shutdown is
// called or the listener fails.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	log.Printf("tcp: listening on %s", s.addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return nil // clean shutdown
			default:
				return err
			}
		}
		s.wg.Add(1)
		go s.handle(conn)
	}
}

// Shutdown stops the listener and waits for active connections to finish.
func (s *Server) Shutdown() {
	close(s.quit)
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
}

func (s *Server) handle(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	reader := bufio.NewReader(conn)

	// --- handshake ---
	if idleTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
	}
	line, err := reader.ReadBytes('\n')
	if err != nil {
		log.Printf("tcp: %s handshake read error: %v", remote, err)
		return
	}
	var hs handshake
	if err := json.Unmarshal(line, &hs); err != nil {
		writeJSON(conn, statusMsg{Status: "denied"})
		log.Printf("tcp: %s bad handshake json: %v", remote, err)
		return
	}

	ok, err := s.devices.VerifyDevice(context.Background(), hs.DeviceID, hs.Password)
	if err != nil {
		writeJSON(conn, statusMsg{Status: "denied"})
		log.Printf("tcp: %s verify error: %v", remote, err)
		return
	}
	if !ok {
		writeJSON(conn, statusMsg{Status: "denied"})
		log.Printf("tcp: %s denied (device %q)", remote, hs.DeviceID)
		return
	}
	if err := writeJSON(conn, statusMsg{Status: "ok"}); err != nil {
		return
	}
	log.Printf("tcp: %s verified as device %q", remote, hs.DeviceID)

	// --- subscribe & pump ---
	sub := s.hub.Subscribe()

	// writer goroutine: forward broadcast messages to this client.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for msg := range sub.C {
			if _, err := conn.Write(append(msg, '\n')); err != nil {
				return
			}
		}
	}()

	// reader loop: read \n-delimited JSON lines and broadcast them.
	for {
		if idleTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}
		trimmed := trimLine(line)
		if len(trimmed) == 0 {
			continue
		}
		if !json.Valid(trimmed) {
			log.Printf("tcp: %s ignoring non-json message", remote)
			continue
		}
		// Copy the payload; the buffer is reused by the reader.
		payload := make([]byte, len(trimmed))
		copy(payload, trimmed)
		s.hub.Broadcast(payload, sub.ID())
	}

	log.Printf("tcp: %s (device %q) disconnected", remote, hs.DeviceID)
	// Unsubscribe closes sub.C, which ends the writer goroutine.
	s.hub.Unsubscribe(sub)
	conn.Close()
	<-writerDone
}

func writeJSON(conn net.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(b, '\n'))
	return err
}

// trimLine removes a trailing \n and optional \r.
func trimLine(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
