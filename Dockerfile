# --- Stage 1: Build ---
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Статический бинарник без cgo
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o tnc-server ./cmd/server

# --- Stage 2: Runtime ---
FROM alpine:3.22

RUN apk add --no-cache ca-certificates

WORKDIR /app

# Копируем бинарник
COPY --from=builder /build/tnc-server .

# ВАЖНО: копируем папку с миграциями
COPY --from=builder /build/migrations ./migrations

EXPOSE 8080
EXPOSE 9000

CMD ["./tnc-server"]
