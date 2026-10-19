package cmd0x65

// Обработка регулярного сообщения поддержания соединения и синхронизации
// часов (спецификаторы 0x66 → 0x67 команды 0x65, docs/protocol/cmd0x66.md).
//
// Устройство шлёт:  $ | 0x66 | 0x65 | 0x0008 | время устройства (8, uint64 LE, Unix-мс) | CRC
// Сервер отвечает:   $ | 0x67 | 0x65 | 0x0010 | время сервера (8) + время приёма (8) | CRC
//
// Оба времени ответа — в NTP-шкале (internal/ntp); при недоступном NTP —
// системное время. Момент приёма фиксируется в crypto_server сразу после
// чтения кадра (ctx.ReceivedAt) и поправляется тем же NTP-offset.
//
// Каждая пара записывается в ctx.TimeLogs для вкладки «Временная метка» (полные кадры
// в hex). Записи не блокируют TCP-цикл: при переполнении очереди — дроп.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"tnc-server/internal/models"
	"tnc-server/internal/tcp"
)

// handleHeartbeat обрабатывает кадр 0x66 после завершения авторизации.
func (h *Handler) handleHeartbeat(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) (*tcp.Message, error) {
	// Gate 1: спецификатор.
	if fr.Addr != tcp.AddrTimeRequest {
		log.Printf("cmd0x65: 0x66: bad addr 0x%02x from %q", fr.Addr, ctx.DeviceID)
		h.sendStatus(conn, ctx, tcp.StatusSpecError)
		return nil, fmt.Errorf("0x66: expected Addr=0x%02x, got 0x%02x", tcp.AddrTimeRequest, fr.Addr)
	}
	// Gate 2: длина данных.
	if len(fr.Data) != tcp.TimeDataLen {
		log.Printf("cmd0x65: 0x66: bad data len %d from %q", len(fr.Data), ctx.DeviceID)
		h.sendStatus(conn, ctx, tcp.StatusDataLenError)
		return nil, fmt.Errorf("0x66: expected data len %d, got %d", tcp.TimeDataLen, len(fr.Data))
	}

	// Времена ответа: NTP-шкала, системное время — если Clock == nil.
	receivedAt := ctx.ReceivedAt
	serverNow := time.Now()
	if ctx.Clock != nil {
		receivedAt = ctx.Clock.Correct(ctx.ReceivedAt)
		serverNow = ctx.Clock.Now()
	}

	deviceTimeMs := binary.LittleEndian.Uint64(fr.Data[:tcp.TimeDataLen])
	serverTimeMs := uint64(serverNow.UnixMilli())
	receivedAtMs := uint64(receivedAt.UnixMilli())

	resp := tcp.Frame{
		Addr: tcp.AddrTimeResponse,
		Cmd:  tcp.CmdAuth,
		Data: buildTimeResponse(serverTimeMs, receivedAtMs),
	}
	raw := tcp.EncodeFrame(resp)

	// Лог вкладки «Временная метка» — до записи, чтобы при ошибке отправки принятый
	// кадр всё равно попал в лог. Пишем полные кадры в hex.
	if ctx.TimeLogs != nil {
		atMs := time.Now().UnixMilli()
		rx := models.TimeLogEntry{
			DeviceID:     ctx.DeviceID,
			Dir:          "rx",
			At:           atMs,
			FrameHex:     hex.EncodeToString(ctx.LastRaw),
			DeviceTimeMs: int64(deviceTimeMs),
			ReceivedAtMs: receivedAt.UnixMilli(),
		}
		tx := models.TimeLogEntry{
			DeviceID:     ctx.DeviceID,
			Dir:          "tx",
			At:           atMs,
			FrameHex:     hex.EncodeToString(raw),
			ServerTimeMs: serverNow.UnixMilli(),
			ReceivedAtMs: receivedAt.UnixMilli(),
		}
		select {
		case ctx.TimeLogs <- rx:
		default:
		}
		select {
		case ctx.TimeLogs <- tx:
		default:
		}
	}

	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}

	log.Printf("cmd0x65: time sync from %q: device=%d ms, server=%d ms, received=%d ms",
		ctx.DeviceID, deviceTimeMs, serverTimeMs, receivedAtMs)
	return nil, nil
}

// buildTimeResponse формирует 16 байт данных ответа 0x67:
// время сервера + время получения сообщения (uint64 little-endian, Unix-мс).
func buildTimeResponse(serverTimeMs, receivedAtMs uint64) []byte {
	data := make([]byte, tcp.TimeResponseDataLen)
	binary.LittleEndian.PutUint64(data[0:8], serverTimeMs)
	binary.LittleEndian.PutUint64(data[8:16], receivedAtMs)
	return data
}
