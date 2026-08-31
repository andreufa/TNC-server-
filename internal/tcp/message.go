// Package tcp — wire-level types for the crypto TCP protocol.
package tcp

// DeliveryMode tells CryptoServer how to distribute the handler's result.
//
// ┌─────────────────┬──────────────────────────────────────────────┐
// │ Mode            │ Behaviour                                    │
// ├─────────────────┼──────────────────────────────────────────────┤
// │ DeliverNone     │ Handler already sent response(s) via conn.   │
// │                 │ Server does nothing with the Message.        │
// ├─────────────────┼──────────────────────────────────────────────┤
// │ DeliverBroadcast│ Publish to Hub → all OTHER connected devices │
// │                 │ receive a frame [Addr|Cmd|Payload].          │
// ├─────────────────┼──────────────────────────────────────────────┤
// │ DeliverUnicast  │ Send frame back to the originating device    │
// │                 │ only (not through Hub).                      │
// ├─────────────────┼──────────────────────────────────────────────┤
// │ DeliverDirect   │ Send frame to specific device(s) listed in   │
// │                 │ Targets. Future: Hub topic-based routing.    │
// └─────────────────┴──────────────────────────────────────────────┘
type DeliveryMode int

const (
	DeliverNone      DeliveryMode = iota // no further action
	DeliverBroadcast                     // fan-out to all other devices via Hub
	DeliverUnicast                       // echo back to sender only
	DeliverDirect                        // deliver to specific Targets
)

// Message is the typed contract between a command handler and the CryptoServer.
//
// Instead of returning an opaque []byte that the server must re-parse to
// extract Addr/Cmd/Payload, the handler returns a structured Message.  This
// makes the handler's intent explicit and decouples business logic from wire
// format assembly.
//
//	 Handler               CryptoServer               Hub
//	┌──────────┐          ┌──────────────┐          ┌─────┐
//	│ Handle() │──Msg──→  │ switch Mode: │          │     │
//	│          │          │  Broadcast →─┼─[A|C|P]→│ Hub │──→ subscribers
//	│          │          │  Unicast  →──┼──conn.Write()     │
//	│          │          │  None     →──┼──(skip)          │
//	└──────────┘          └──────────────┘          └─────┘
type Message struct {
	Mode    DeliveryMode // what to do with this message
	Addr    byte         // target address byte (e.g. AddrBroadcast)
	Cmd     byte         // command byte (e.g. CmdRegular)
	Payload []byte       // command-specific data

	// Targets is used when Mode == DeliverDirect.
	// Each entry is a device ID that should receive this frame.
	// (Reserved for future Hub routing — currently unused.)
	Targets []string
}

// String returns a human-readable label for logging.
func (m DeliveryMode) String() string {
	switch m {
	case DeliverNone:
		return "DeliverNone"
	case DeliverBroadcast:
		return "DeliverBroadcast"
	case DeliverUnicast:
		return "DeliverUnicast"
	case DeliverDirect:
		return "DeliverDirect"
	default:
		return "DeliverUnknown"
	}
}

// WireBytes serialises the message into the format expected by the Hub and
// subscriber goroutines: [Addr(1) | Cmd(1) | Payload(N)].
//
// This is the stable wire format shared between CryptoServer → Hub →
// subscriber goroutine → EncodeFrame → conn.Write.
func (m *Message) WireBytes() []byte {
	out := make([]byte, 1+1+len(m.Payload))
	out[0] = m.Addr
	out[1] = m.Cmd
	copy(out[2:], m.Payload)
	return out
}
