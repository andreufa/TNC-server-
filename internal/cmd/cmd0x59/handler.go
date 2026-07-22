// Package cmd0x59 implements the regular data message command handler.
//
// Device sends:  $ | 0x76 | 0x59 | len(44 LE) | 44 bytes data | CRC
// Server broadcasts: $ | 0x70 | 0x59 | len(44 LE) | 44 bytes data | CRC
package cmd0x59

import (
	"log"
	"net"

	"tnc-server/internal/tcp"
)

// Handler implements tcp.CmdHandler for command 0x59 (regular data messages).
type Handler struct{}

// Handle processes a regular data frame.
// Changes Addr from 0x76 to 0x70 and returns broadcast data.
func (h *Handler) Handle(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) ([]byte, error) {
	if fr.Addr != tcp.AddrDeviceRegular {
		return nil, nil // ignore unexpected addr
	}

	log.Printf("cmd0x59: message from %q: Addr=0x%02x data=%x",
		ctx.DeviceID, fr.Addr, fr.Data)

	// Build broadcast payload: new addr + cmd + data
	out := make([]byte, 1+1+len(fr.Data))
	out[0] = tcp.AddrBroadcast
	out[1] = fr.Cmd
	copy(out[2:], fr.Data)

	return out, nil
}
