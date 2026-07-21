# TNC-server — User Guide

## Overview

TNC-server is a TCP server for device authentication via RSA challenge-response.
It also includes a web UI for managing devices and users, and a real-time log viewer.

## Quick start

```sh
# 1. Start Postgres
docker compose up -d

# 2. Start the server
go run ./cmd/server

# 3. Open web UI
# http://localhost:8080
# Default login: admin / admin
```

## Architecture

| Port  | Protocol  | Purpose                          |
|-------|-----------|----------------------------------|
| 8080  | HTTP      | Web UI + API                     |
| 9001  | TCP       | Binary RSA challenge-response    |

## Web UI

### Adding a device
1. Log in at `/login`
2. On the Devices page, enter:
   - **Device ID** — unique identifier (e.g. `37777`)
   - **Public Key (PEM)** — the device's RSA public key
   - Check **В эксплуатацию** to activate
3. Click **Добавить**

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
