// Package tcp — middleware chain for command handlers.
//
// Middleware wraps a CmdHandler to inject cross-cutting behaviour *before*
// and *after* the actual business logic.  Think of it as an onion:
//
//	                     ┌─────────────────────────┐
//	                     │     AuthGate (outer)     │
//	                     │  ┌───────────────────┐   │
//	 Frame ─────────────→│  │  Logging (inner)  │   │
//	                     │  │  ┌─────────────┐  │   │
//	                     │  │  │  Handler    │  │   │──→ *Message
//	                     │  │  └─────────────┘  │   │
//	                     │  └───────────────────┘   │
//	                     └─────────────────────────┘
//
// Middleware is applied via Pipeline(), which chains them from outermost to
// innermost so that the first middleware in the argument list runs first on
// the way in (and last on the way out, if it wraps the return).
package tcp

import (
	"log"
	"net"
)

// Middleware wraps a CmdHandler, adding behaviour before/after Handle().
//
// Typical pattern:
//
//	func MyMiddleware() Middleware {
//	    return func(next CmdHandler) CmdHandler {
//	        return &myWrapper{next: next}
//	    }
//	}
type Middleware func(next CmdHandler) CmdHandler

// Pipeline chains middlewares into a single CmdHandler.
//
//	mw1, mw2, mw3 — applied order: mw1(mw2(mw3(handler)))
//
//	mw1 runs first (outermost), mw3 runs closest to the handler.
//
// Usage in CryptoServer:
//
//	piped := Pipeline(rawHandler, AuthGate(), Logging())
func Pipeline(handler CmdHandler, mws ...Middleware) CmdHandler {
	// Apply in reverse so the first argument is outermost.
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}
	return handler
}

// ——— Built-in middlewares ———————————————————————————————————————

// authGateHandler is a CmdHandler that refuses all commands except 0x65
// (auth) before the device has been authenticated.
type authGateHandler struct {
	next CmdHandler
}

// Handle delegates to next only if the device is authenticated or is currently
// authenticating (CmdAuth).  Otherwise silently drops the frame.
//
// This replaces the inline check that previously lived in
// crypto_server.go:handleConnection.
func (h *authGateHandler) Handle(fr Frame, conn net.Conn, ctx *CmdContext) (*Message, error) {
	// Before authentication: only CmdAuth (0x65) is allowed.
	// After authentication: all commands pass through.
	if !ctx.Authenticated && fr.Cmd != CmdAuth {
		log.Printf("tcp: auth gate refused Cmd=0x%02x for device=%q (not yet authenticated)", fr.Cmd, ctx.DeviceID)
		return nil, nil
	}
	return h.next.Handle(fr, conn, ctx)
}

// AuthGate creates a middleware that enforces the authentication gate.
//
//	Frame arrives ──→ AuthGate ──→ (authenticated?) ──yes──→ next Handler
//	                                   │
//	                                   no (and Cmd != 0x65)
//	                                   │
//	                                   └──→ drop frame, return nil
//
// This is the first middleware in the chain — it must be outermost.
func AuthGate() Middleware {
	return func(next CmdHandler) CmdHandler {
		return &authGateHandler{next: next}
	}
}

// loggingHandler wraps a CmdHandler and logs dispatch + result.
type loggingHandler struct {
	next CmdHandler
}

func (h *loggingHandler) Handle(fr Frame, conn net.Conn, ctx *CmdContext) (*Message, error) {
	log.Printf("tcp: dispatching Cmd=0x%02x Addr=0x%02x device=%q", fr.Cmd, fr.Addr, ctx.DeviceID)

	msg, err := h.next.Handle(fr, conn, ctx)

	if err != nil {
		log.Printf("tcp: handler error Cmd=0x%02x device=%q: %v", fr.Cmd, ctx.DeviceID, err)
	} else if msg != nil && msg.Mode != DeliverNone {
		log.Printf("tcp: Cmd=0x%02x → %s (addr=0x%02x payload=%d bytes)",
			fr.Cmd, msg.Mode, msg.Addr, len(msg.Payload))
	}

	return msg, err
}

// Logging creates a middleware that logs dispatch and handler outcome.
//
// Runs after AuthGate (inner in the chain) so we only log frames that
// actually reach the handler.
func Logging() Middleware {
	return func(next CmdHandler) CmdHandler {
		return &loggingHandler{next: next}
	}
}
