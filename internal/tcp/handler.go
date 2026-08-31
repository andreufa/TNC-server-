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
//
// The handler may write responses directly to conn (e.g. multi-step auth
// handshake) and return nil or DeliverNone to signal «I've already handled it».
//
// Return a *Message with a non-none DeliveryMode to tell CryptoServer to
// distribute the result (broadcast, unicast, direct).  CryptoServer serialises
// the Message via WireBytes() and either publishes it to the Hub or writes it
// back to conn, depending on Mode.
//
// Returning an error before authentication is complete will cause the
// connection to be closed (the device failed the handshake).
type CmdHandler interface {
	Handle(fr Frame, conn net.Conn, ctx *CmdContext) (msg *Message, err error)
}

// HandlerFactory creates a fresh CmdHandler instance for each new connection.
// Stateful handlers (like cmd0x65) must use this to avoid cross-connection state leaks.
type HandlerFactory func() CmdHandler
