package tcp

import (
	"net"

	"tnc-server/internal/hub"
	"tnc-server/internal/store"
)

// CmdContext provides command handlers with access to shared server resources.
type CmdContext struct {
	Devices       *store.DeviceStore
	Hub           *hub.Hub
	LogChan       chan<- string
	DeviceID      string // set when device is identified (param request)
	Authenticated bool   // set after authorization is fully complete (two status responses sent)
}

// CmdHandler processes an incoming frame for a specific command.
// The handler may write responses directly to conn.
// Returns broadcast data (nil if none) to be distributed via the hub.
type CmdHandler interface {
	Handle(fr Frame, conn net.Conn, ctx *CmdContext) (broadcast []byte, err error)
}

// HandlerFactory creates a fresh CmdHandler instance for each new connection.
// Stateful handlers (like cmd0x65) must use this to avoid cross-connection state leaks.
type HandlerFactory func() CmdHandler
