// Package cmd0x65 implements the AT (Device Authorization) command handler.
//
// Protocol flow for command 0x65:
//  1. Device sends Parameter Request (Addr=0x61): DID (10 bytes)
//  2. Server responds with challenge (Addr=0x64): timestamp (8B) + nonce (8B)
//  3. Device sends Authorization (Addr=0x60): DID (10B) + RSA signature (256B)
//  4. Server responds with two status frames (Addr=0x63):
//     a. Status 0x00 — input processed
//     b. Status 0x01 (authorized) or 0x06 (data field value error)
package cmd0x65

import (
	"context"
	"fmt"
	"log"
	"net"

	"tnc-server/internal/tcp"
)

// authStep tracks the authorization state machine.
type authStep int

const (
	stepWaitParam authStep = iota // waiting for parameter request (Addr=0x61)
	stepWaitAuth                   // waiting for authorization (Addr=0x60)
	stepDone                       // authorization complete
)

// Handler implements tcp.CmdHandler for command 0x65 (AT Authorization).
type Handler struct {
	step      authStep
	deviceID  string
	challenge []byte
	pubKeyPEM string
}

// Handle processes one frame of the AT authorization flow.
func (h *Handler) Handle(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) ([]byte, error) {
	switch h.step {
	case stepWaitParam:
		return h.handleParamRequest(fr, conn, ctx)
	case stepWaitAuth:
		return h.handleAuth(fr, conn, ctx)
	default:
		return nil, fmt.Errorf("cmd0x65: unexpected frame in step %d", h.step)
	}
}

func (h *Handler) handleParamRequest(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) ([]byte, error) {
	if fr.Addr != tcp.AddrParamRequest {
		h.sendStatus(conn, ctx, tcp.StatusSpecError)
		return nil, fmt.Errorf("expected Addr=0x%02x, got 0x%02x", tcp.AddrParamRequest, fr.Addr)
	}
	if len(fr.Data) < tcp.DeviceIDSize {
		h.sendStatus(conn, ctx, tcp.StatusDataLenError)
		return nil, fmt.Errorf("data too short: %d", len(fr.Data))
	}

	h.deviceID = tcp.TrimDeviceID(fr.Data[:tcp.DeviceIDSize])
	log.Printf("cmd0x65: param request from %q", h.deviceID)
	ctx.DeviceID = h.deviceID
	logEvent(ctx, "auth", "← "+fmt.Sprintf("param request (Addr=0x%02x)", fr.Addr))

	// Look up device
	pubKeyPEM, err := ctx.Devices.GetPublicKey(context.Background(), h.deviceID)
	if err != nil {
		log.Printf("cmd0x65: device %q not found", h.deviceID)
		h.sendStatus(conn, ctx, tcp.StatusCmdExecError)
		logEvent(ctx, "auth", "denied: device not found")
		return nil, err
	}

	inService, err := ctx.Devices.IsInService(context.Background(), h.deviceID)
	if err != nil || !inService {
		h.sendStatus(conn, ctx, tcp.StatusCmdExecError)
		logEvent(ctx, "auth", "denied: not in service")
		return nil, fmt.Errorf("device not in service")
	}

	h.pubKeyPEM = pubKeyPEM

	// Generate and send challenge
	challenge, err := tcp.GenerateChallenge()
	if err != nil {
		h.sendStatus(conn, ctx, tcp.StatusTimeoutError)
		return nil, err
	}
	h.challenge = challenge

	challengeFrame := tcp.Frame{
		Addr: tcp.AddrChallengeResponse,
		Cmd:  tcp.CmdAuth,
		Data: challenge,
	}
	if _, err := conn.Write(tcp.EncodeFrame(challengeFrame)); err != nil {
		return nil, err
	}
	log.Printf("cmd0x65: sent challenge to %q", h.deviceID)
	logEvent(ctx, "message", "→ "+fmt.Sprintf("challenge sent (time=%x key=%x)", challenge[:8], challenge[8:]))

	h.step = stepWaitAuth
	return nil, nil
}

func (h *Handler) handleAuth(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) ([]byte, error) {
	if fr.Addr != tcp.AddrAuthCommand {
		h.sendStatus(conn, ctx, tcp.StatusSpecError)
		return nil, fmt.Errorf("expected Addr=0x%02x, got 0x%02x", tcp.AddrAuthCommand, fr.Addr)
	}

	// Parse: 10 bytes DID + 256 bytes signature
	if len(fr.Data) < tcp.DeviceIDSize {
		h.sendStatus(conn, ctx, tcp.StatusDataLenError)
		return nil, fmt.Errorf("auth data too short")
	}
	respDID := tcp.TrimDeviceID(fr.Data[:tcp.DeviceIDSize])
	signature := fr.Data[tcp.DeviceIDSize:]

	if respDID != h.deviceID {
		log.Printf("cmd0x65: DID mismatch: expected %q, got %q", h.deviceID, respDID)
		h.sendTwoStatuses(conn, ctx, tcp.StatusDataValueError)
		logEvent(ctx, "auth", "denied: DID mismatch")
		return nil, fmt.Errorf("DID mismatch")
	}

	// Check TTL
	expired, err := tcp.IsChallengeExpired(h.challenge)
	if err != nil {
		h.sendTwoStatuses(conn, ctx, tcp.StatusTimeoutError)
		return nil, err
	}
	if expired {
		h.sendTwoStatuses(conn, ctx, tcp.StatusCmdExecError)
		logEvent(ctx, "auth", "denied: challenge expired")
		return nil, fmt.Errorf("challenge expired")
	}

	// Verify signature
	pubKey, err := tcp.ParsePublicKey(h.pubKeyPEM)
	if err != nil {
		h.sendTwoStatuses(conn, ctx, tcp.StatusTimeoutError)
		return nil, err
	}
	if err := tcp.VerifyChallengeResponse(pubKey, h.challenge, signature); err != nil {
		log.Printf("cmd0x65: signature verification failed for %q", h.deviceID)
		h.sendTwoStatuses(conn, ctx, tcp.StatusDataValueError)
		logEvent(ctx, "auth", "denied: signature verification failed")
		return nil, err
	}

	// Authorization successful — send two responses
	// First: status 0x00 (input processed)
	// Second: status 0x01 (authorized)
	h.sendTwoStatuses(conn, ctx, tcp.StatusAuthorized)

	// Mark as fully authenticated — hub subscription happens after this.
	ctx.Authenticated = true

	log.Printf("cmd0x65: device %q authorized", h.deviceID)
	logEvent(ctx, "auth", "→ authorized")

	if err := ctx.Devices.UpdateLastSeen(context.Background(), h.deviceID); err != nil {
		log.Printf("cmd0x65: update last seen for %q: %v", h.deviceID, err)
	}

	h.step = stepDone
	return nil, nil
}

// sendTwoStatuses sends the standard two-response pattern:
// first 0x00 (input processed), then the result code.
func (h *Handler) sendTwoStatuses(conn net.Conn, ctx *tcp.CmdContext, resultCode byte) {
	h.sendStatus(conn, ctx, tcp.StatusOK)      // 0x00 — input processed
	h.sendStatus(conn, ctx, resultCode)         // result (0x01 authorized, 0x06 failure, etc.)
}

// IsDone returns true when authorization is complete.
func (h *Handler) IsDone() bool { return h.step == stepDone }

// sendStatus sends a status response frame (Addr=0x63, Cmd=0x65, 1-byte status).
func (h *Handler) sendStatus(conn net.Conn, ctx *tcp.CmdContext, code byte) {
	fr := tcp.Frame{
		Addr: tcp.AddrServerStatus,
		Cmd:  tcp.CmdAuth,
		Data: []byte{code},
	}
	raw := tcp.EncodeFrame(fr)
	log.Printf("cmd0x65: sending status 0x%02x to %q (%x)", code, h.deviceID, raw)
	logEvent(ctx, "message", "→ "+fmt.Sprintf("status 0x%02x → %x", code, raw))
	conn.Write(raw)
}

func logEvent(ctx *tcp.CmdContext, eventType, message string) {
	if ctx.LogChan == nil {
		return
	}
	select {
	case ctx.LogChan <- tcp.FormatLog(eventType, ctx.DeviceID, message):
	default:
	}
}
