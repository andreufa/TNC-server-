package tcp

import (
	"log"
	"net"
	"sync"
	"time"

	"tnc-server/internal/hub"
	"tnc-server/internal/store"
)

const idleTimeout = 5 * time.Minute

// handshake - формат сообщения от устройства
type handshake struct {
	Protocol string `json:"protocol"`
	LsnCmd   string `json:"lsncmd"`
	DeviceID string `json:"deviceId"`
	Password string `json:"password"`
}

const (
	expectedProtocol = "progress_konsul_bin"
	expectedLsnCmd   = "104"
	msgOk            = "Msg100Ok\n"
	msgDenied        = "Msg100Denied\n"
)

type Server struct {
	addr    string
	devices *store.DeviceStore
	hub     *hub.Hub

	ln      net.Listener
	wg      sync.WaitGroup
	quit    chan struct{}
	logChan chan<- string
}

func NewServer(addr string, devices *store.DeviceStore, h *hub.Hub, logChan chan<- string) *Server {
	return &Server{
		addr:    addr,
		devices: devices,
		hub:     h,
		quit:    make(chan struct{}),
		logChan: logChan,
	}
}

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
				return nil
			default:
				return err
			}
		}
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) Shutdown() {
	close(s.quit)
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
}
