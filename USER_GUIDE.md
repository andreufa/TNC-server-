# TNC-server — User Guide

## Overview


New file structure

internal/tcp/
  frame.go          — frame encode/decode, constants for all addresses & status codes
  handler.go         — CmdHandler interface + CmdContext struct
  crypto_server.go   — CryptoServer: accept connections, dispatch frames by cmd to handlers
  crypto.go          — RSA crypto helpers (unchanged)

internal/cmd/
  doc.go             — package doc
  cmd0x65/
    handler.go       — AT Authorization state machine (command 0x65)
  cmd0x59/
    handler.go       — Regular data message broadcast (command 0x59)

Protocol changes

Command 0x65 (AT Authorization):
┌────────────────────────────┬────────────────────────────┬────────────────────────────┬────────────────────────────┐
Step                       │ Direction                  │ Addr                       │ Data                       │
├────────────────────────────┼────────────────────────────┼────────────────────────────┼────────────────────────────┤
1                          │ Device → Server            │ 0x61                       │ 10B DID                    │
├────────────────────────────┼────────────────────────────┼────────────────────────────┼────────────────────────────┤
2                          │ Server → Device            │ 0x64                       │ 8B timestamp + 8B nonce    │
├────────────────────────────┼────────────────────────────┼────────────────────────────┼────────────────────────────┤
3                          │ Device → Server            │ 0x60                       │ 10B DID + 256B RSA         │
                           │                            │                            │ signature                  │
├────────────────────────────┼────────────────────────────┼────────────────────────────┼────────────────────────────┤
4a                         │ Server → Device            │ 0x63                       │ 0x00 (processed)           │
├────────────────────────────┼────────────────────────────┼────────────────────────────┼────────────────────────────┤
4b                         │ Server → Device            │ 0x63                       │ 0x01 (authorized) or 0x06  │
                           │                            │                            │ (failed)                   │
└────────────────────────────┴────────────────────────────┴────────────────────────────┴────────────────────────────┘

Status codes:
0x00 OK · 0x01 Authorized · 0x02 Addr error · 0x03 Spec error · 0x05 Data len error · 0x06 Data value error · 0x08 Timeout · 0x0A Exec error

Dispatch model

crypto_server.go now runs a generic read loop per connection. Before auth, only Cmd=0x65 frames are accepted. After the cmd0x65.Handler sets ctx.DeviceID, all registered commands are dispatched via the handlers map. The server creates handlers once:

handlers := map[byte]tcp.CmdHandler{
    tcp.CmdAuth:    &cmd0x65.Handler{},  // per-connection state machine
    tcp.CmdRegular: &cmd0x59.Handler{},  // stateless broadcast
}

To add a new command handler, create a package under internal/cmd/cmd0xNN/, implement tcp.CmdHandler, and register it in main.go.

Explain to me which files and functions a command goes through after it arrives at the server and before it is        
processed.                                                                                                            

Here's the full chain, file by file and function by function:

────────────────────────────────────────────────────────────

1. `cmd/server/main.go` — Server startup (one-time)

`run()` creates the handler map and passes it to NewCryptoServer:
handlers := map[byte]tcp.CmdHandler{
    tcp.CmdAuth:    &cmd0x65.Handler{},
    tcp.CmdRegular: &cmd0x59.Handler{},
}
cryptoSrv := tcp.NewCryptoServer(addr, devices, h, logChan, handlers)
cryptoSrv.ListenAndServe()   // blocks, runs in a goroutine

────────────────────────────────────────────────────────────

2. `internal/tcp/crypto_server.go` — Connection acceptance

`ListenAndServe()` — accepts TCP connections in a loop:
net.Listen → ln.Accept() → go s.handleConnection(conn)

────────────────────────────────────────────────────────────

3. `internal/tcp/crypto_server.go` — Per-connection read loop

`handleConnection(conn)` creates a per-connection CmdContext and enters a read loop:

bufio.NewReader(conn)
NewFrameReader(reader)           → FrameReader wraps the buffered reader
CmdContext{Devices, Hub, LogChan} → shared context for all handlers on this conn

Then the main read loop (one iteration per incoming frame):

conn.SetReadDeadline(...)
frameReader.ReadFrame()          → raw bytes → Frame{Addr, Cmd, Data}

────────────────────────────────────────────────────────────

4. `internal/tcp/crypto_server.go` — `FrameReader.ReadFrame()`

Reads from the bufio.Reader byte by byte:

1. Scan for preamble — skip bytes until $ (0x24) found
2. Read header — 4 bytes: [Addr, Cmd, LenLo, LenHi]
3. Parse length — binary.LittleEndian.Uint16 → dataLen
4. Read data + CRC — dataLen bytes of payload + 1 byte CRC
5. Reconstruct full frame — rebuild the complete byte slice: [$, Addr, Cmd, Len, Data..., CRC]
6. Call `DecodeFrame(full)` — verifies CRC, returns Frame{Addr, Cmd, Data}

Returns: (Frame, rawBytes, error)

────────────────────────────────────────────────────────────

5. `internal/tcp/frame.go` — `DecodeFrame(raw)`

1. Validates minimum length (≥ 6)
2. Validates preamble byte is $
3. Parses dataLen via binary.LittleEndian.Uint16
4. Validates frame length matches 6 + dataLen
5. CRC check: crcCalc(raw[:len-1]) — XOR of preamble through last data byte — must match last byte

Returns: Frame{Addr, Cmd, Data} (Data is the payload without CRC)

────────────────────────────────────────────────────────────

6. Back in `handleConnection()` — Dispatch

After ReadFrame returns successfully:

// Before auth, only command 0x65 is allowed
if ctx.DeviceID == "" && fr.Cmd != CmdAuth { continue }

// Look up handler by command number
handler := s.handlers[fr.Cmd]    // map lookup: 0x65 → cmd0x65.Handler, 0x59 → cmd0x59.Handler

// Dispatch
broadcastData, err := handler.Handle(fr, conn, ctx)

────────────────────────────────────────────────────────────

### Generating keys for a device

```sh
# Generate private key
openssl genpkey -algorithm RSA -out device_private.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in device_private.pem -out device_public.pem
```

Paste the contents of `device_public.pem` into the web form.

### Logs
The `/logs` page shows real-time events via WebSocket:
- Device connections and disconnections
- Authentication attempts (success/failure)
- Messages received from devices

## Testing with the client

```sh
# Register device 37777 via web UI (paste public key)

# Run client with private key
go run ./cmd/challenge_client 37777 device_private.pem

# Or use built-in stub key (register _stub_public.pem first)
go run ./cmd/challenge_client 37777
```

The client performs the handshake, then waits for **Enter** to send test messages. Press **Ctrl+C** to exit.

## Protocol

Binary frame format for device↔server communication:

```
$ | Addr+Spec(1) | Cmd(1) | DataLen(2, BE) | Data(N) | CRC(1)
```

| Field      | Size   | Description                          |
|------------|--------|--------------------------------------|
| Preamble   | 1 byte | `$` (0x24)                           |
| Addr+Spec  | 1 byte | `0x60`=hello `0x61`=challenge `0x62`=auth `0x63`=result |
| Command    | 1 byte | Always `0x65` for handshake          |
| DataLen    | 2 bytes| Payload length, big-endian, max 1024 |
| Data       | N bytes| Payload                              |
| CRC        | 1 byte | XOR of bytes from Addr through Data  |

### Handshake flow

All messages use Cmd=0x65. Addr+Spec distinguishes message purpose.

```
Device                              Server
  │                                   │
  │── Hello ────────────────────────→│  Addr=0x60 Cmd=0x65
  │   [10 bytes: Device ID]          │  padded with 0x00
  │                                   │
  │←─ Challenge ─────────────────────│  Addr=0x61 Cmd=0x65
  │   [8B time + 8B random key]      │  16 bytes total
  │                                   │
  │── Auth Request ─────────────────→│  Addr=0x62 Cmd=0x65
  │   [10B ID + 256B RSA signature]  │  266 bytes total
  │                                   │
  │←─ Result ────────────────────────│  Addr=0x63 Cmd=0x65
  │   [10B ID + 1B result code]      │  11 bytes total
```

### Result codes

| Code   | Meaning                             |
|--------|-------------------------------------|
| `0x01` | Authorized                          |
| `0x02` | Error decoding data field           |
| `0x03` | Error combining specifier + number  |
| `0x07` | Integrity error (CRC)               |
| `0x0A` | Authorization error                 |

### Challenge

- 8-byte Unix timestamp (uint64, big-endian) + 8 random bytes = 16 bytes total
- Valid for 5 minutes (TTL checked via embedded timestamp)
- Signed with RSA-2048 PKCS#1 v1.5 + SHA-256

## Configuration

| Variable              | Default     | Description          |
|-----------------------|-------------|----------------------|
| `DB_HOST`             | `localhost` | Postgres host        |
| `DB_PORT`             | `5432`      | Postgres port        |
| `DB_USER`             | `tnc`       | Postgres user        |
| `DB_PASSWORD`         | `tnc`       | Postgres password    |
| `DB_NAME`             | `tnc`       | Database name        |
| `HTTP_ADDR`           | `:8080`     | Web UI listen addr   |
| `CRYPTO_TCP_ADDR`     | `:9001`     | Crypto TCP addr      |
| `SESSION_SECRET`      | *(required)*| Session encryption   |
| `BOOTSTRAP_ADMIN_USER`| `admin`     | Initial admin username|
| `BOOTSTRAP_ADMIN_PASSWORD` | `admin` | Initial admin password|

## Database schema

```sql
devices (id, public_key, password_hash, in_service, last_seen_at, ...)
users   (id, username, password_hash, role)
sessions(token, user_id, expires_at)
```

## Docker

```sh
docker compose up -d    # starts Postgres + server
docker compose down     # stops everything
```
