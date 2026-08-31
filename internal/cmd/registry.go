// Package cmd — central command registry and middleware pipeline.
//
// # How to add a new command
//
//  1. Create a sub-package: internal/cmd/cmd0xNN/
//  2. Implement tcp.CmdHandler in your Handler struct.
//  3. In an init() function, call cmd.Register(0xNN, factory).
//  4. Add a blank import in cmd/server/main.go:
//     _ "tnc-server/internal/cmd/cmd0xNN"
//
// No other wiring is needed — the registry and pipeline pick it up
// automatically.
package cmd

import (
	"fmt"
	"log"

	"tnc-server/internal/tcp"
)

// ——— Registry —————————————————————————————————————————————————————

// registry holds command handler factories indexed by command byte.
// Packages register themselves via init() → Register().
var registry = make(map[byte]tcp.HandlerFactory)

// Register adds a HandlerFactory for the given command byte.
// Panics on duplicate registration — two packages registering the same command
// byte is a programmer error that should fail fast at startup.
//
// Called from sub-package init() functions, e.g.:
//
//	func init() { cmd.Register(tcp.CmdRegular, func() tcp.CmdHandler { return &Handler{} }) }
func Register(cmd byte, factory tcp.HandlerFactory) {
	if _, exists := registry[cmd]; exists {
		panic(fmt.Sprintf("cmd: duplicate registration for 0x%02x — did you import two handlers for the same command?", cmd))
	}
	registry[cmd] = factory
	log.Printf("cmd: registered handler for 0x%02x", cmd)
}

// GetAll returns a snapshot of the full registry.
// Used by main.go to pass handlers to CryptoServer's constructor.
func GetAll() map[byte]tcp.HandlerFactory {
	m := make(map[byte]tcp.HandlerFactory, len(registry))
	for k, v := range registry {
		m[k] = v
	}
	return m
}

// Has reports whether a handler is registered for the given command.
func Has(cmd byte) bool {
	_, ok := registry[cmd]
	return ok
}
