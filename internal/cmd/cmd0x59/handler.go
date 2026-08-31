// Package cmd0x59 implements the regular data message command handler.
//
// Device sends:  $ | 0x76 | 0x59 | len(44 LE) | 44 bytes data | CRC
// Server broadcasts: $ | 0x70 | 0x59 | len(44 LE) | 44 bytes data | CRC
package cmd0x59

import (
	"log"
	"net"

	"tnc-server/internal/cmd"
	"tnc-server/internal/tcp"
)

// init auto-registers this command handler in the central registry.
// The blank import in cmd/server/main.go triggers this init().
func init() {
	cmd.Register(tcp.CmdRegular, func() tcp.CmdHandler { return &Handler{} })
}

// Handler implements tcp.CmdHandler for command 0x59 (regular data messages).
type Handler struct{}

// Handle processes a regular data frame.
//
// Device → Server frame:  [Addr=0x76 | Cmd=0x59 | payload]
// Server → all others:    [Addr=0x70 | Cmd=0x59 | payload]
//
// Returns DeliverBroadcast — CryptoServer publishes the transformed
// message to the Hub, which fans it out to every other connected device.
func (h *Handler) Handle(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) (*tcp.Message, error) {
	if fr.Addr != tcp.AddrDeviceRegular {
		return nil, nil // ignore unexpected addr
	}

	log.Printf("cmd0x59: message from %q: Addr=0x%02x data=%x",
		ctx.DeviceID, fr.Addr, fr.Data)

	// Return a typed message — the server handles serialisation and routing.
	return &tcp.Message{
		Mode:    tcp.DeliverBroadcast,
		Addr:    tcp.AddrBroadcast, // 0x76 → 0x70
		Cmd:     fr.Cmd,
		Payload: fr.Data,
	}, nil
}
