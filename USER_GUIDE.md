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
