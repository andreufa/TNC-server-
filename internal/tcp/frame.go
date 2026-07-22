package tcp

import (
	"encoding/binary"
	"fmt"
)

// Binary frame format for the crypto handshake protocol:
//
//	$ | Addr+Spec(1) | Cmd(1) | DataLen(2, little-endian) | Data(DataLen) | CRC(1)
//
// Addr+Spec distinguishes the message direction and purpose.
// Command number is always 0x65 for the handshake protocol.
//
// Minimum frame: 6 bytes ($ + addr + cmd + len[2] + 0 data + crc)
const (
	FramePreamble   = '$'
	FrameMinLen     = 6 // preamble(1) + addr(1) + cmd(1) + len(2) + crc(1)
	FrameMaxDataLen = 1024
	FrameMaxLen     = FrameMinLen + FrameMaxDataLen

	// Address + Specifier constants for command 0x65 (AT Authorization).
	AddrAuthCommand       = 0x60 // Device → Server: authorization (DID + signature)
	AddrParamRequest      = 0x61 // Device → Server: parameter request (DID)
	AddrServerStatus      = 0x63 // Server → Device: status response
	AddrChallengeResponse = 0x64 // Server → Device: challenge (timestamp + nonce)

	// Address + Specifier constants for command 0x59 (regular messages).
	AddrDeviceRegular  = 0x76 // Device → Server: regular data message
	AddrBroadcast      = 0x70 // Server → Device: broadcast (modified addr)

	// Command numbers.
	CmdAuth    byte = 0x65
	CmdRegular byte = 0x59 // Regular data message command number

	// Status codes from the status table (server → device).
	StatusOK             byte = 0x00 // Input message processed successfully
	StatusAuthorized     byte = 0x01 // Input message instruction executed (auth OK)
	StatusAddrError      byte = 0x02 // Address error
	StatusSpecError      byte = 0x03 // Specifier error
	StatusNumberError    byte = 0x04 // Number error
	StatusDataLenError   byte = 0x05 // Data field length error
	StatusDataValueError byte = 0x06 // Data field value error
	StatusIntegrityError byte = 0x07 // Integrity error (CRC field)
	StatusTimeoutError   byte = 0x08 // Processing timeout error
	StatusSeqError       byte = 0x09 // Command sequence error
	StatusCmdExecError   byte = 0x0A // Command execution error

	// Fixed field sizes.
	DeviceIDSize = 10 // Device ID is exactly 10 bytes
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
	binary.LittleEndian.PutUint16(buf[3:5], uint16(dataLen))
	if dataLen > 0 {
		copy(buf[5:5+dataLen], f.Data)
	}
	// CRC over bytes 0..(total-2) (preamble through end of data)
	crc := crcCalc(buf[:total-1])
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
	dataLen := binary.LittleEndian.Uint16(raw[3:5])
	if int(dataLen) > FrameMaxDataLen {
		return Frame{}, fmt.Errorf("data length too large: %d", dataLen)
	}
	expectedLen := FrameMinLen + int(dataLen)
	if len(raw) != expectedLen {
		return Frame{}, fmt.Errorf("frame length mismatch: got %d, expected %d", len(raw), expectedLen)
	}

	// Verify CRC: bytes 0..(expectedLen-2) (preamble through end of data)
	expectedCRC := crcCalc(raw[:expectedLen-1])
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
