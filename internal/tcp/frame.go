package tcp

import (
	"encoding/binary"
	"fmt"
)

// Binary frame format for the crypto handshake protocol:
//
//	$ | Addr+Spec(1) | Cmd(1) | DataLen(2, big-endian) | Data(DataLen) | CRC(1)
//
// Minimum frame: 6 bytes ($ + addr + cmd + len[2] + 0 data + crc)
const (
	FramePreamble   = '$'
	FrameMinLen     = 6 // preamble(1) + addr(1) + cmd(1) + len(2) + crc(1)
	FrameMaxDataLen = 1024
	FrameMaxLen     = FrameMinLen + FrameMaxDataLen

	// Address byte: upper nibble = source, lower nibble = flags
	AddrServer = 0x10
	AddrDevice = 0x20
)

// Commands for the crypto handshake protocol.
const (
	CmdHello     byte = 0x01 // Device → Server: device ID (requests challenge)
	CmdChallenge byte = 0x02 // Server → Device: 8 random bytes + 8 byte timestamp
	CmdResponse  byte = 0x03 // Device → Server: device ID + RSA signature
	CmdSuccess   byte = 0x04 // Server → Device: authentication succeeded
	CmdDenied    byte = 0x05 // Server → Device: authentication denied
)

// Frame represents a parsed binary frame.
type Frame struct {
	Addr byte   // Address + Specifier
	Cmd  byte   // Command number
	Data []byte // Payload
}

// EncodeFrame serializes a Frame into the wire format and returns the bytes.
func EncodeFrame(f Frame) []byte {
	dataLen := len(f.Data)
	if dataLen > FrameMaxDataLen {
		panic(fmt.Sprintf("frame data too long: %d > %d", dataLen, FrameMaxDataLen))
	}
	total := FrameMinLen + dataLen
	buf := make([]byte, total)

	buf[0] = FramePreamble
	buf[1] = f.Addr
	buf[2] = f.Cmd
	binary.BigEndian.PutUint16(buf[3:5], uint16(dataLen))
	if dataLen > 0 {
		copy(buf[5:5+dataLen], f.Data)
	}
	// CRC over bytes 1..(total-2) (addr through end of data)
	crc := crcCalc(buf[1 : total-1])
	buf[total-1] = crc

	return buf
}

// DecodeFrame parses a binary frame from raw bytes. Returns an error if the
// frame is malformed, too short, has wrong preamble, or CRC mismatch.
func DecodeFrame(raw []byte) (Frame, error) {
	if len(raw) < FrameMinLen {
		return Frame{}, fmt.Errorf("frame too short: %d < %d", len(raw), FrameMinLen)
	}
	if raw[0] != FramePreamble {
		return Frame{}, fmt.Errorf("bad preamble: 0x%02x", raw[0])
	}
	dataLen := binary.BigEndian.Uint16(raw[3:5])
	if int(dataLen) > FrameMaxDataLen {
		return Frame{}, fmt.Errorf("data length too large: %d", dataLen)
	}
	expectedLen := FrameMinLen + int(dataLen)
	if len(raw) != expectedLen {
		return Frame{}, fmt.Errorf("frame length mismatch: got %d, expected %d", len(raw), expectedLen)
	}

	// Verify CRC: bytes 1..(expectedLen-2)
	expectedCRC := crcCalc(raw[1 : expectedLen-1])
	actualCRC := raw[expectedLen-1]
	if expectedCRC != actualCRC {
		return Frame{}, fmt.Errorf("CRC mismatch: calc 0x%02x, got 0x%02x", expectedCRC, actualCRC)
	}

	f := Frame{
		Addr: raw[1],
		Cmd:  raw[2],
	}
	if dataLen > 0 {
		f.Data = make([]byte, dataLen)
		copy(f.Data, raw[5:5+dataLen])
	}
	return f, nil
}

// crcCalc computes XOR of all bytes in buf. Returns 0 for empty input.
func crcCalc(buf []byte) byte {
	if len(buf) == 0 {
		return 0
	}
	crc := buf[0]
	for i := 1; i < len(buf); i++ {
		crc ^= buf[i]
	}
	return crc
}
