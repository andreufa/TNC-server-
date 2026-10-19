package cmd0x65

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"tnc-server/internal/models"
	"tnc-server/internal/tcp"
)

func TestBuildTimeResponse(t *testing.T) {
	data := buildTimeResponse(0x0102030405060708, 0x1112131415161718)
	if len(data) != tcp.TimeResponseDataLen {
		t.Fatalf("len=%d, want %d", len(data), tcp.TimeResponseDataLen)
	}
	if got := binary.LittleEndian.Uint64(data[0:8]); got != 0x0102030405060708 {
		t.Fatalf("server time: got 0x%016x", got)
	}
	if got := binary.LittleEndian.Uint64(data[8:16]); got != 0x1112131415161718 {
		t.Fatalf("received at: got 0x%016x", got)
	}
}

// TestHandleHeartbeatRoundTrip прогоняет полный обмен 0x66 → 0x67 через
// net.Pipe и проверяет формат ответа и записи в TimeLogs.
func TestHandleHeartbeatRoundTrip(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	const deviceTimeMs = 1_700_000_000_000
	deviceData := make([]byte, tcp.TimeDataLen)
	binary.LittleEndian.PutUint64(deviceData, deviceTimeMs)
	rxFrame := tcp.EncodeFrame(tcp.Frame{Addr: tcp.AddrTimeRequest, Cmd: tcp.CmdAuth, Data: deviceData})

	receivedAt := time.UnixMilli(1_700_000_000_100)
	timeLogs := make(chan models.TimeLogEntry, 4)
	h := &Handler{step: stepDone}
	ctx := &tcp.CmdContext{
		DeviceID:   "N-10",
		ReceivedAt: receivedAt,
		LastRaw:    rxFrame,
		TimeLogs:   timeLogs,
		// Clock == nil → системное время; в тесте важны байты ответа.
	}

	go func() {
		msg, err := h.Handle(tcp.Frame{Addr: tcp.AddrTimeRequest, Cmd: tcp.CmdAuth, Data: deviceData}, server, ctx)
		if err != nil {
			t.Errorf("Handle: %v", err)
		}
		if msg != nil {
			t.Errorf("Handle: expected nil message, got %+v", msg)
		}
		server.Close()
	}()

	respFrame, respRaw, err := tcp.NewFrameReader(bufio.NewReader(client)).ReadFrame()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if respFrame.Addr != tcp.AddrTimeResponse || respFrame.Cmd != tcp.CmdAuth {
		t.Fatalf("resp addr/cmd: 0x%02x 0x%02x, want 0x%02x 0x%02x",
			respFrame.Addr, respFrame.Cmd, tcp.AddrTimeResponse, tcp.CmdAuth)
	}
	if len(respFrame.Data) != tcp.TimeResponseDataLen {
		t.Fatalf("resp data len: %d, want %d", len(respFrame.Data), tcp.TimeResponseDataLen)
	}
	serverTimeMs := binary.LittleEndian.Uint64(respFrame.Data[0:8])
	receivedMs := binary.LittleEndian.Uint64(respFrame.Data[8:16])
	if receivedMs != uint64(receivedAt.UnixMilli()) {
		t.Fatalf("received at: got %d, want %d", receivedMs, receivedAt.UnixMilli())
	}
	if serverTimeMs < receivedMs {
		t.Fatalf("server time %d earlier than received %d", serverTimeMs, receivedMs)
	}

	// Две записи в лог вкладки «Временная метка»: rx (полный принятый кадр) и tx (ответ).
	var entries []models.TimeLogEntry
	for i := 0; i < 2; i++ {
		select {
		case e := <-timeLogs:
			entries = append(entries, e)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for time log entry")
		}
	}
	if entries[0].Dir != "rx" || entries[1].Dir != "tx" {
		t.Fatalf("entry dirs: %q, %q; want rx, tx", entries[0].Dir, entries[1].Dir)
	}
	if entries[0].FrameHex != hex.EncodeToString(rxFrame) {
		t.Fatalf("rx hex mismatch:\n got %s\nwant %s", entries[0].FrameHex, hex.EncodeToString(rxFrame))
	}
	if entries[1].FrameHex != hex.EncodeToString(respRaw) {
		t.Fatalf("tx hex mismatch:\n got %s\nwant %s", entries[1].FrameHex, hex.EncodeToString(respRaw))
	}
	if entries[0].DeviceTimeMs != deviceTimeMs {
		t.Fatalf("device time ms: got %d, want %d", entries[0].DeviceTimeMs, deviceTimeMs)
	}
	if entries[0].ReceivedAtMs != receivedAt.UnixMilli() {
		t.Fatalf("rx received at: got %d, want %d", entries[0].ReceivedAtMs, receivedAt.UnixMilli())
	}
	if entries[1].ServerTimeMs == 0 || entries[1].ReceivedAtMs != receivedAt.UnixMilli() {
		t.Fatalf("tx entry: server=%d received=%d", entries[1].ServerTimeMs, entries[1].ReceivedAtMs)
	}
}

// readStatusFrame читает один кадр ответа через net.Pipe и возвращает его.
func readStatusFrame(t *testing.T, conn net.Conn) tcp.Frame {
	t.Helper()
	fr, _, err := tcp.NewFrameReader(bufio.NewReader(conn)).ReadFrame()
	if err != nil {
		t.Fatalf("read status frame: %v", err)
	}
	return fr
}

func TestHandleHeartbeatBadAddr(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	h := &Handler{step: stepDone}
	ctx := &tcp.CmdContext{DeviceID: "N-10", ReceivedAt: time.Now()}
	go func() {
		_, err := h.Handle(tcp.Frame{Addr: 0x60, Cmd: tcp.CmdAuth, Data: make([]byte, tcp.TimeDataLen)}, server, ctx)
		if err == nil {
			t.Error("expected error for bad addr")
		}
		server.Close()
	}()

	fr := readStatusFrame(t, client)
	if fr.Addr != tcp.AddrServerStatus || fr.Cmd != tcp.CmdAuth {
		t.Fatalf("status frame addr/cmd: 0x%02x 0x%02x", fr.Addr, fr.Cmd)
	}
	if len(fr.Data) != 1 || fr.Data[0] != tcp.StatusSpecError {
		t.Fatalf("status: %x, want 0x%02x", fr.Data, tcp.StatusSpecError)
	}
}

func TestHandleHeartbeatBadLen(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	h := &Handler{step: stepDone}
	ctx := &tcp.CmdContext{DeviceID: "N-10", ReceivedAt: time.Now()}
	go func() {
		_, err := h.Handle(tcp.Frame{Addr: tcp.AddrTimeRequest, Cmd: tcp.CmdAuth, Data: make([]byte, 4)}, server, ctx)
		if err == nil {
			t.Error("expected error for bad data len")
		}
		server.Close()
	}()

	fr := readStatusFrame(t, client)
	if fr.Addr != tcp.AddrServerStatus || fr.Cmd != tcp.CmdAuth {
		t.Fatalf("status frame addr/cmd: 0x%02x 0x%02x", fr.Addr, fr.Cmd)
	}
	if len(fr.Data) != 1 || fr.Data[0] != tcp.StatusDataLenError {
		t.Fatalf("status: %x, want 0x%02x", fr.Data, tcp.StatusDataLenError)
	}
}
