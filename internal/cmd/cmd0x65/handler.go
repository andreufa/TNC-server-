// Package cmd0x65 implements the AT (Device Authorization) command handler.
//
// Protocol flow for command 0x65:
//  1. Device sends Parameter Request (Addr=0x61): DID (14 bytes)
//  2. Server responds with challenge (Addr=0x64): Status(1) + nonce(32B) + timestamp(8B)
//  3. Device sends Authorization (Addr=0x60): DID(14B) + version(1B) + RSA signature(256B)
//  4. Server responds with two status frames (Addr=0x63):
//     a. Status 0x00 — input processed
//     b. Status 0x01 (authorized) or 0x06 (data field value error)
package cmd0x65

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

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
	// DEBUG ONLY — log incoming param request frame
	logDebug(ctx, "param request received: Addr=0x%02x Cmd=0x%02x DataLen=%d Data=%s",
		fr.Addr, fr.Cmd, len(fr.Data), hex.EncodeToString(fr.Data))

	// Gate 1: address check
	if fr.Addr != tcp.AddrParamRequest {
		// DEBUG ONLY
		logDebug(ctx, "param request: BAD ADDR — expected=0x%02x actual=0x%02x",
			tcp.AddrParamRequest, fr.Addr)
		h.sendStatus(conn, ctx, tcp.StatusSpecError)
		return nil, fmt.Errorf("expected Addr=0x%02x, got 0x%02x", tcp.AddrParamRequest, fr.Addr)
	}

	// Gate 2: data length check
	if len(fr.Data) < tcp.DeviceIDSize {
		// DEBUG ONLY
		logDebug(ctx, "param request: BAD DATA LEN — expected>=%d actual=%d raw=%s",
			tcp.DeviceIDSize, len(fr.Data), hex.EncodeToString(fr.Data))
		h.sendStatus(conn, ctx, tcp.StatusDataLenError)
		return nil, fmt.Errorf("data too short: %d", len(fr.Data))
	}

	// Gate 3: extract and trim DID
	h.deviceID = tcp.TrimDeviceID(fr.Data[:tcp.DeviceIDSize])
	// DEBUG ONLY
	logDebug(ctx, "param request: DID extracted — raw=%s trimmed=%q",
		hex.EncodeToString(fr.Data[:tcp.DeviceIDSize]), h.deviceID)
	ctx.DeviceID = h.deviceID
	logEvent(ctx, "auth", "← "+fmt.Sprintf("param request (Addr=0x%02x)", fr.Addr))
	log.Printf("cmd0x65: param request from %q", h.deviceID)

	// Gate 4: device exists in DB
	pubKeyPEM, err := ctx.Devices.GetPublicKey(context.Background(), h.deviceID)
	if err != nil {
		// DEBUG ONLY
		logDebug(ctx, "param request: DEVICE NOT FOUND — did=%q err=%v", h.deviceID, err)
		log.Printf("cmd0x65: device %q not found", h.deviceID)
		h.sendStatus(conn, ctx, tcp.StatusCmdExecError)
		logEvent(ctx, "auth", "denied: device not found")
		return nil, err
	}
	// DEBUG ONLY
	logDebug(ctx, "param request: device found — did=%q pubKeyLen=%d", h.deviceID, len(pubKeyPEM))

	// Gate 5: device in service
	inService, err := ctx.Devices.IsInService(context.Background(), h.deviceID)
	if err != nil || !inService {
		// DEBUG ONLY
		logDebug(ctx, "param request: NOT IN SERVICE — did=%q inService=%v err=%v", h.deviceID, inService, err)
		h.sendStatus(conn, ctx, tcp.StatusCmdExecError)
		logEvent(ctx, "auth", "denied: not in service")
		return nil, fmt.Errorf("device not in service")
	}

	h.pubKeyPEM = pubKeyPEM

	// Gate 6: generate challenge
	challenge, err := tcp.GenerateChallenge()
	if err != nil {
		// DEBUG ONLY
		logDebug(ctx, "param request: CHALLENGE GEN FAILED — err=%v", err)
		h.sendStatus(conn, ctx, tcp.StatusTimeoutError)
		return nil, err
	}
	h.challenge = challenge
	// DEBUG ONLY — challenge details
	nonce := challenge[:tcp.ChallengeSize]
	tsBytes := challenge[tcp.ChallengeSize:]
	ts, _ := tcp.ExtractTimestamp(challenge)
	logDebug(ctx, "param request: challenge generated — nonce=%s ts_raw=%s ts=%s challenge=%s",
		hex.EncodeToString(nonce), hex.EncodeToString(tsBytes), ts.UTC().Format(time.RFC3339Nano),
		hex.EncodeToString(challenge))

	// Build and send challenge response frame
	challengeData := make([]byte, 1+len(challenge))
	challengeData[0] = tcp.StatusOK
	copy(challengeData[1:], challenge)

	challengeFrame := tcp.Frame{
		Addr: tcp.AddrChallengeResponse,
		Cmd:  tcp.CmdAuth,
		Data: challengeData,
	}
	rawFrame := tcp.EncodeFrame(challengeFrame)
	// DEBUG ONLY
	logDebug(ctx, "param request: sending challenge frame — Addr=0x%02x Cmd=0x%02x DataLen=%d Status=0x%02x raw=%s",
		challengeFrame.Addr, challengeFrame.Cmd, len(challengeFrame.Data),
		challengeData[0], hex.EncodeToString(rawFrame))

	if _, err := conn.Write(rawFrame); err != nil {
		return nil, err
	}
	log.Printf("cmd0x65: sent challenge to %q", h.deviceID)
	logEvent(ctx, "message", "→ "+fmt.Sprintf("challenge sent (nonce=%x time=%x)",
		challenge[:tcp.ChallengeSize], challenge[tcp.ChallengeSize:]))

	h.step = stepWaitAuth
	return nil, nil
}

func (h *Handler) handleAuth(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) ([]byte, error) {
	// DEBUG ONLY — log incoming auth frame
	logDebug(ctx, "auth: frame received — Addr=0x%02x Cmd=0x%02x DataLen=%d Data=%s",
		fr.Addr, fr.Cmd, len(fr.Data), hex.EncodeToString(fr.Data))

	// Gate 1: address check
	if fr.Addr != tcp.AddrAuthCommand {
		// DEBUG ONLY
		logDebug(ctx, "auth: BAD ADDR — expected=0x%02x actual=0x%02x",
			tcp.AddrAuthCommand, fr.Addr)
		h.sendStatus(conn, ctx, tcp.StatusSpecError)
		return nil, fmt.Errorf("expected Addr=0x%02x, got 0x%02x", tcp.AddrAuthCommand, fr.Addr)
	}

	// Gate 2: data length check (14B DID + 1B version + 256B signature = 271)
	const expectedAuthLen = tcp.DeviceIDSize + 1 + 256 // 14+1+256 = 271
	if len(fr.Data) < expectedAuthLen {
		// DEBUG ONLY
		logDebug(ctx, "auth: BAD DATA LEN — expected>=%d actual=%d raw=%s",
			expectedAuthLen, len(fr.Data), hex.EncodeToString(fr.Data))
		h.sendStatus(conn, ctx, tcp.StatusDataLenError)
		return nil, fmt.Errorf("auth data too short: expected >=%d, got %d", expectedAuthLen, len(fr.Data))
	}

	// Gate 3: parse fields
	respDID := tcp.TrimDeviceID(fr.Data[:tcp.DeviceIDSize])
	version := fr.Data[tcp.DeviceIDSize]
	signature := fr.Data[tcp.DeviceIDSize+1 : tcp.DeviceIDSize+1+256]
	// DEBUG ONLY
	logDebug(ctx, "auth: parsed — did_raw=%s did=%q version=0x%02x sigLen=%d sig_head=%s sig_tail=%s",
		hex.EncodeToString(fr.Data[:tcp.DeviceIDSize]), respDID, version,
		len(signature),
		hex.EncodeToString(signature[:min(8, len(signature))]),
		hex.EncodeToString(signature[max(0, len(signature)-8):]))

	// Gate 4: protocol version check
	if version != tcp.AuthProtocolVersion {
		// DEBUG ONLY
		logDebug(ctx, "auth: BAD VERSION — expected=0x%02x actual=0x%02x did=%q",
			tcp.AuthProtocolVersion, version, respDID)
		log.Printf("cmd0x65: unsupported auth protocol version %d from %q", version, respDID)
		h.sendTwoStatuses(conn, ctx, tcp.StatusDataValueError)
		logEvent(ctx, "auth", "denied: unsupported protocol version")
		return nil, fmt.Errorf("unsupported auth protocol version %d", version)
	}

	// Gate 5: DID match
	if respDID != h.deviceID {
		// DEBUG ONLY
		logDebug(ctx, "auth: BAD DID MATCH — expected=%q actual=%q", h.deviceID, respDID)
		log.Printf("cmd0x65: DID mismatch: expected %q, got %q", h.deviceID, respDID)
		h.sendTwoStatuses(conn, ctx, tcp.StatusDataValueError)
		logEvent(ctx, "auth", "denied: DID mismatch")
		return nil, fmt.Errorf("DID mismatch: expected %q, got %q", h.deviceID, respDID)
	}

	// Gate 6: challenge TTL check
	challengeTs, tsErr := tcp.ExtractTimestamp(h.challenge)
	// DEBUG ONLY
	logDebug(ctx, "auth: TTL check — challenge_ts=%s now=%s ttl=%s",
		func() string {
			if tsErr != nil { return tsErr.Error() }
			return challengeTs.UTC().Format(time.RFC3339Nano)
		}(),
		time.Now().UTC().Format(time.RFC3339Nano),
		tcp.ChallengeTTL.String())

	expired, err := tcp.IsChallengeExpired(h.challenge)
	if err != nil {
		// DEBUG ONLY
		logDebug(ctx, "auth: TTL PARSE ERROR — err=%v challenge=%s", err, hex.EncodeToString(h.challenge))
		h.sendTwoStatuses(conn, ctx, tcp.StatusTimeoutError)
		return nil, err
	}
	if expired {
		// DEBUG ONLY
		logDebug(ctx, "auth: CHALLENGE EXPIRED — challenge_ts=%s ttl=%s",
			func() string {
				if tsErr != nil { return tsErr.Error() }
				return challengeTs.UTC().Format(time.RFC3339Nano)
			}(),
			tcp.ChallengeTTL.String())
		h.sendTwoStatuses(conn, ctx, tcp.StatusCmdExecError)
		logEvent(ctx, "auth", "denied: challenge expired")
		return nil, fmt.Errorf("challenge expired")
	}

	// Gate 7: signature verification
	pubKey, err := tcp.ParsePublicKey(h.pubKeyPEM)
	if err != nil {
		// DEBUG ONLY
		logDebug(ctx, "auth: PUBKEY PARSE ERROR — did=%q err=%v", h.deviceID, err)
		h.sendTwoStatuses(conn, ctx, tcp.StatusTimeoutError)
		return nil, err
	}
	// DEBUG ONLY
	logDebug(ctx, "auth: verifying signature — did=%q keySize=%d challengeLen=%d challenge=%s sigLen=%d",
		h.deviceID, pubKey.Size(), len(h.challenge),
		hex.EncodeToString(h.challenge), len(signature))

	if err := tcp.VerifyChallengeResponse(pubKey, h.challenge, signature); err != nil {
		// DEBUG ONLY
		logDebug(ctx, "auth: SIGNATURE VERIFY FAILED — did=%q challenge=%s sig=%s err=%v",
			h.deviceID,
			hex.EncodeToString(h.challenge),
			hex.EncodeToString(signature),
			err)
		log.Printf("cmd0x65: signature verification failed for %q", h.deviceID)
		h.sendTwoStatuses(conn, ctx, tcp.StatusDataValueError)
		logEvent(ctx, "auth", "denied: signature verification failed")
		return nil, err
	}

	// Authorization successful — send two responses
	h.sendTwoStatuses(conn, ctx, tcp.StatusAuthorized)

	// Mark as fully authenticated — hub subscription happens after this.
	ctx.Authenticated = true

	// DEBUG ONLY
	logDebug(ctx, "auth: AUTHORIZED — did=%q", h.deviceID)
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
	// DEBUG ONLY
	logDebug(ctx, "auth: sending two-status response — first=0x%02x (input processed) second=0x%02x (result) step=%d",
		tcp.StatusOK, resultCode, h.step)
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
	// DEBUG ONLY
	logDebug(ctx, "auth: sending status — Addr=0x%02x Cmd=0x%02x Status=0x%02x raw=%s",
		tcp.AddrServerStatus, tcp.CmdAuth, code, hex.EncodeToString(raw))
	log.Printf("cmd0x65: sending status 0x%02x to %q (%x)", code, h.deviceID, raw)
	logEvent(ctx, "message", "→ "+fmt.Sprintf("status 0x%02x → %x", code, raw))
	conn.Write(raw)
}

// logDebug logs a debug-only message prefixed with [DEBUG cmd0x65].
// These logs are for initial protocol debugging and should be removed or
// downgraded in production.
func logDebug(ctx *tcp.CmdContext, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[DEBUG cmd0x65] %s", msg)
	// DEBUG ONLY — also send to web UI log channel
	logEvent(ctx, "debug", msg)
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
