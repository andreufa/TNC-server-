package cmd0x59

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

func TestDecode(t *testing.T) {
	data := make([]byte, DataLen)
	binary.LittleEndian.PutUint32(data[0:4], 12345)
	utcMs := time.Date(2026, 9, 16, 12, 34, 56, 789e6, time.UTC).UnixMilli()
	binary.LittleEndian.PutUint64(data[4:12], uint64(utcMs))
	binary.LittleEndian.PutUint64(data[12:20], math.Float64bits(12.345))
	binary.LittleEndian.PutUint64(data[20:28], math.Float64bits(0.001))
	binary.LittleEndian.PutUint64(data[28:36], math.Float64bits(-7.89))
	binary.LittleEndian.PutUint32(data[36:40], 10)
	binary.LittleEndian.PutUint32(data[40:44], 0b00000111)

	m, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if m.Number != 12345 {
		t.Errorf("Number = %d, want 12345", m.Number)
	}
	if m.UTC != uint64(utcMs) {
		t.Errorf("UTC = %d, want %d", m.UTC, utcMs)
	}
	if m.Off1 != 12.345 {
		t.Errorf("Off1 = %v, want 12.345", m.Off1)
	}
	if m.Off2 != 0.001 {
		t.Errorf("Off2 = %v, want 0.001", m.Off2)
	}
	if m.Off3 != -7.89 {
		t.Errorf("Off3 = %v, want -7.89", m.Off3)
	}
	if m.Static != 10 {
		t.Errorf("Static = %d, want 10", m.Static)
	}
	if m.Validity != 0b00000111 {
		t.Errorf("Validity = %b, want 0b00000111", m.Validity)
	}
}

func TestDecodeShort(t *testing.T) {
	if _, err := Decode(make([]byte, DataLen-1)); err == nil {
		t.Fatal("expected error for data shorter than 44 bytes")
	}
}

func TestFormatLog(t *testing.T) {
	ts := time.Date(2026, 9, 16, 12, 34, 56, 789e6, time.UTC)
	m := Msg{
		Number:   12345,
		UTC:      uint64(ts.UnixMilli()),
		Off1:     12.345,
		Off2:     0.001,
		Off3:     -7.89,
		Static:   10,
		Validity: 0b00000101, // бит 1 сброшен → off2 невалиден
	}

	got := m.FormatLog(ts, "N-10")
	want := "2026-09-16 12:34:56.789  N-10  0x59  msg=12345  utc=2026-09-16T12:34:56.789Z  off1=+12.345000  off2=+0.001000(invalid)  off3=-7.890000  static=10  valid=0b00000101"
	if got != want {
		t.Errorf("FormatLog:\n got: %q\nwant: %q", got, want)
	}
}
