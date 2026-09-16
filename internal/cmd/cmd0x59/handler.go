// Package cmd0x59 implements the regular data message command handler.
//
// Device sends:  $ | 0x76 | 0x59 | len(44 LE) | 44 bytes data | CRC
// Server broadcasts: $ | 0x70 | 0x59 | len(44 LE) | 44 bytes data | CRC
package cmd0x59

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
	"time"

	"tnc-server/internal/cmd"
	"tnc-server/internal/models"
	"tnc-server/internal/tcp"
)

// DataLen — фиксированная длина данных сообщения 0x59 в байтах
// (docs/auth/protocol/cmd0x59.md).
const DataLen = 44

// init auto-registers this command handler in the central registry.
// The blank import in cmd/server/main.go triggers this init().
func init() {
	cmd.Register(tcp.CmdRegular, func() tcp.CmdHandler { return &Handler{} })
}

// Handler implements tcp.CmdHandler for command 0x59 (regular data messages).
type Handler struct{}

// Msg — декодированное сообщение 0x59 (docs/auth/protocol/cmd0x59.md).
type Msg struct {
	Number   uint32  // номер сообщения
	UTC      uint64  // время сообщения, миллисекунды с эпохи Unix
	Off1     float64 // iekf_hw_offset_1, метры
	Off2     float64 // iekf_hw_offset_2, метры
	Off3     float64 // iekf_hw_offset_3, метры
	Static   uint32  // static_cnt — количество эпох в измерении
	Validity uint32  // битовая маска: бит 0 → off1, бит 1 → off2, бит 2 → off3
}

// Decode разбирает данные сообщения 0x59 (little-endian, 44 байта).
func Decode(data []byte) (Msg, error) {
	var m Msg
	if len(data) < DataLen {
		return m, fmt.Errorf("0x59: data length %d < %d", len(data), DataLen)
	}
	m.Number = binary.LittleEndian.Uint32(data[0:4])
	m.UTC = binary.LittleEndian.Uint64(data[4:12])
	m.Off1 = math.Float64frombits(binary.LittleEndian.Uint64(data[12:20]))
	m.Off2 = math.Float64frombits(binary.LittleEndian.Uint64(data[20:28]))
	m.Off3 = math.Float64frombits(binary.LittleEndian.Uint64(data[28:36]))
	m.Static = binary.LittleEndian.Uint32(data[36:40])
	m.Validity = binary.LittleEndian.Uint32(data[40:44])
	return m, nil
}

// FormatLog форматирует строку человекочитаемого лога (docs/logging.md §6).
// Имена полей — строго как в протоколе (docs/auth/protocol/cmd0x59.md):
//
//	2026-09-16 12:34:56.789  N-10  0x59  Номер_сообщения=12345  UTC=…  iekf_hw_offset_1=+12.345000 …
//
// t — момент приёма сообщения сервером; невалидные слоты (бит валидности
// сброшен) помечаются суффиксом (invalid).
func (m Msg) FormatLog(t time.Time, did string) string {
	utc := time.UnixMilli(int64(m.UTC)).UTC().Format("2006-01-02T15:04:05.000Z")
	off := func(v float64, bit uint32) string {
		s := fmt.Sprintf("%+.6f", v)
		if m.Validity&bit == 0 {
			s += "(invalid)"
		}
		return s
	}
	return fmt.Sprintf(
		"%s  %s  0x59  Номер_сообщения=%d  UTC=%s  iekf_hw_offset_1=%s  iekf_hw_offset_2=%s  iekf_hw_offset_3=%s  static_cnt=%d  validity=0b%08b",
		t.UTC().Format("2006-01-02 15:04:05.000"), did, m.Number, utc,
		off(m.Off1, 1<<0), off(m.Off2, 1<<1), off(m.Off3, 1<<2),
		m.Static, m.Validity&0xFF)
}

// Handle processes a regular data frame.
//
// Device → Server frame:  [Addr=0x76 | Cmd=0x59 | payload]
// Server → all others:    [Addr=0x70 | Cmd=0x59 | payload]
//
// Returns DeliverBroadcast — CryptoServer publishes the transformed
// message to the Hub, which fans it out to every other connected device.
// При включённых файловых логах пишет декодированную строку в <DID>.txt.
func (h *Handler) Handle(fr tcp.Frame, conn net.Conn, ctx *tcp.CmdContext) (*tcp.Message, error) {
	if fr.Addr != tcp.AddrDeviceRegular {
		return nil, nil // ignore unexpected addr
	}

	log.Printf("cmd0x59: message from %q: Addr=0x%02x data=%x",
		ctx.DeviceID, fr.Addr, fr.Data)

	// Декодируем 0x59: человекочитаемый файловый лог + измерение для графиков.
	m, err := Decode(fr.Data)
	if err != nil {
		log.Printf("cmd0x59: decode from %q: %v", ctx.DeviceID, err)
	} else {
		now := time.Now()
		if ctx.Logger != nil {
			ctx.Logger.LogTxt(ctx.DeviceID, m.FormatLog(now, ctx.DeviceID))
		}
		if ctx.Measurements != nil {
			ts := time.UnixMilli(int64(m.UTC))
			if m.UTC == 0 {
				ts = now // в кадре нет времени — используем момент приёма
			}
			ctx.Measurements.Enqueue(models.Measurement{
				DeviceID:   ctx.DeviceID,
				MsgNo:      m.Number,
				Ts:         ts,
				ReceivedAt: now,
				Off1:       m.Off1,
				Off2:       m.Off2,
				Off3:       m.Off3,
				StaticCnt:  m.Static,
				Validity:   m.Validity,
			})
		}
	}

	// Return a typed message — the server handles serialisation and routing.
	return &tcp.Message{
		Mode:    tcp.DeliverBroadcast,
		Addr:    tcp.AddrBroadcast, // 0x76 → 0x70
		Cmd:     fr.Cmd,
		Payload: fr.Data,
	}, nil
}
