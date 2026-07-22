// challenge_client is a test client for the crypto handshake TCP server.
//
// Protocol: ROS MP ↔ APCS Communication Module
//
// Usage:
//
//	go run ./cmd/challenge_client <device_id> [private_key.pem]
//
// If no private key file is provided, the built-in stub key is used (matching
// public key must be registered on the server for this device).
//
// The client:
//  1. Connects to the crypto TCP server (default :9001)
//  2. Sends Hello (Addr=0x60, Cmd=0x65, 10-byte device ID)
//  3. Receives Challenge (Addr=0x61, Cmd=0x65, 8B time + 8B key)
//  4. Signs the challenge (RSA PKCS#1 v1.5 SHA-256)
//  5. Sends Auth request (Addr=0x62, Cmd=0x65, 10B ID + 256B signature)
//  6. Receives Result (Addr=0x63, Cmd=0x65, 10B ID + 1B code)
package main

import (
	"bufio"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const (
	framePreamble   = '$'
	frameMinLen     = 6
	frameMaxDataLen = 1024

	addrDeviceHello  = 0x60
	addrServerChal   = 0x61
	addrDeviceAuth   = 0x62
	addrServerResult = 0x63
	addrRegular      = 0x76

	cmdAuth     byte = 0x65
	cmdRegular  byte = 0x59
	deviceIDLen      = 10

	resultAuthorized byte = 0x01
)

// stubPrivateKey is a pre-generated RSA 2048-bit key used when no key file is
// provided.  The matching public key is in _stub_public.pem.
const stubPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+8u4ZzpfSfqlf
pLRxc52iWlFVIsDAZ2q9WSeipu4ib+jS3qWB/GX+FnKu6WuY11SdAYPcToCTwVON
hAEAeJqsEsgakx4gM1kHLTeEATaP4CHDFfZ4vRxMv32G0KnMTEngwxA6sMoYgvD8
b/n9RiGOm8IUiiiAd1bkOWZJjcR5WQPd4kfOkuGLbu1oiB7OnUJ67RTCaKYo3eM2
vduY9inE56hg1iPgrxRYLhANBimgxEmvgolK/T0IilgsFJu0YBxYC/VM7xweJzIn
le7fdiJuR61Qaqqn+FITg5QCdAKCjVPIW/Qcb/ZfC0ikguvJU3MwbOW3V+UchyVF
0rqabkxRAgMBAAECggEAAOgQFY8HpTwM84tpgGLhQBKv8Wimc9th1DeKwsDKX186
4ppkPIFdXhcO8RHiXQHDsPGfhcGZJmpr6j9yzkTkThYSPV8OrO41eV1fdrjXQJha
rK2LY6AZNOuRTd0qezHvBVpDttWdRf/EI1yoOgm10dKfOZ/8yHxYjSGRIN8DjGRr
0O4CNgeeviFn5LsMpE6GejwxE54XUOjL6sP5JleEOrSN98OYeGEd4+4LcCeanyxc
fi9Q0ofuYGV3EDnz35cECYvNFLWXWDAb1xwDle/IvNyFak+kvYmjCNzLurrx+ZxR
J7bzFgGg5Yyl4ljy9bOUgnjFbyBOnw7e1++uRidUgQKBgQDgl6fQ04VbVTNe9OJu
LGrKtlS94W0JeFMneiOpHXVK4JuMvQZyaWbjEmioMFD5BNgP6PU1EYPfuthvTruD
P8tQOEYo3bEDZHMkoywPRcVrYBxQKrrnGzey9v0zuyDXkHz9alr2dQA3C5ZrpOjL
NMNhJPY3l83T0zZ4vSVmn2ssQQKBgQDZptknPQR0avoFCAHzZoIMLPQ9HfB0rfsW
m3iiVRr88qs0/O6qLxxcbqgzjUVeDCYZB9CxBVMt7XPR37NRZpTl/fbbi5dUDCBv
qi1w+Lr1rPdmv2cbi56Ek3WJFvF+nyFLiqiZTmU7u+r+HudSi69ETAeS86DnH/mj
if6C6ilcEQKBgBwVequXN47DKahPEN1b+oKcqB4SSTMs86D1Ge50u40AZxMDNAIs
gewVCjc1y3pIC8h5hef757SbRaMtgi8YVBEU6FkF17On5OoI6WKDg/s4SnIP1c0+
Twm27tSAKswpyidaHEPDP6KidU3CkkWOtHu6RnuPJPK+74nLhRi/CITBAoGAcTKy
vBKjD31X3WgFw7arqnNy75pzpeuarG5dtmf26lm3q45k/oQUBwrSVkWCL2C4K8qB
wp+XXEqkMyJaW9qzVE7apeKa6O6JrCnhCmGCsyWrYnfnw07BOgiLV6pkHUvcADL0
bw9z3TZmCJbADpFxrV6xjb9CDxL1PhYWFbZ9nlECgYEAweHmk6mrxI4wMj6fiN6l
SWCdq4cWoTw12EH5MIc2GVPhDWvvqfnt4wUs9LTr91Xi6OwEGt28eaesiaLaC64d
YalUJkc+1QAORbKbQZZS11ugHwSsjzP5N99luvfjvpQxuclGCgGcV8TP0EFwjlPI
jN7eTnLCMpz0Zhx7gqOq8HA=
-----END PRIVATE KEY-----`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: go run ./cmd/challenge_client <device_id> [private_key.pem]\n")
		os.Exit(1)
	}
	deviceID := os.Args[1]

	addr := os.Getenv("CRYPTO_TCP_ADDR")
	if addr == "" {
		addr = "localhost:9001"
	}

	// --- Load private key ---
	var privKey *rsa.PrivateKey
	if len(os.Args) >= 3 {
		pemData, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "read key file %q: %v\n", os.Args[2], err)
			os.Exit(1)
		}
		privKey, err = parsePrivateKey(string(pemData))
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[client] loaded private key from %s\n", os.Args[2])
	} else {
		var err error
		privKey, err = parsePrivateKey(stubPrivateKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse stub key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[client] using built-in stub private key")
	}

	// --- Connect ---
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("[client] connected to %s\n", addr)

	reader := bufio.NewReader(conn)

	// === Step 1: Send Hello (Addr=0x60, Cmd=0x65, 10B ID) ===
	idPadded := padID(deviceID)
	fmt.Printf("[client] sending hello: Addr=0x60 Cmd=0x65 ID=%q (padded=%d bytes)\n", deviceID, len(idPadded))
	helloFrame := encodeFrame(addrDeviceHello, cmdAuth, idPadded)
	if _, err := conn.Write(helloFrame); err != nil {
		fmt.Fprintf(os.Stderr, "send hello: %v\n", err)
		os.Exit(1)
	}

	// === Step 2: Receive Challenge (Addr=0x61, Cmd=0x65) ===
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	challengeFrame, err := readFrame(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read challenge: %v\n", err)
		os.Exit(1)
	}
	if challengeFrame.addr != addrServerChal || challengeFrame.cmd != cmdAuth {
		fmt.Fprintf(os.Stderr, "expected Addr=0x61 Cmd=0x65, got Addr=0x%02x Cmd=0x%02x\n",
			challengeFrame.addr, challengeFrame.cmd)
		os.Exit(1)
	}

	challenge := challengeFrame.data
	fmt.Printf("[client] received challenge: %d bytes (time=%x key=%x)\n",
		len(challenge), challenge[:8], challenge[8:])

	// === Step 3: Sign challenge ===
	signature, err := signChallenge(privKey, challenge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[client] signed challenge: signature=%d bytes\n", len(signature))

	// === Step 4: Send Auth request (Addr=0x62, Cmd=0x65, 10B ID + 256B sig) ===
	authData := make([]byte, deviceIDLen+len(signature))
	copy(authData[:deviceIDLen], idPadded)
	copy(authData[deviceIDLen:], signature)

	fmt.Printf("[client] sending auth request (data=%d bytes)\n", len(authData))
	authFrame := encodeFrame(addrDeviceAuth, cmdAuth, authData)
	if _, err := conn.Write(authFrame); err != nil {
		fmt.Fprintf(os.Stderr, "send auth: %v\n", err)
		os.Exit(1)
	}

	// === Step 5: Receive Result (Addr=0x63, Cmd=0x65, 10B ID + 1B code) ===
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	resultFrame, err := readFrame(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read result: %v\n", err)
		os.Exit(1)
	}
	if resultFrame.addr != addrServerResult || resultFrame.cmd != cmdAuth {
		fmt.Fprintf(os.Stderr, "expected Addr=0x63 Cmd=0x65, got Addr=0x%02x Cmd=0x%02x\n",
			resultFrame.addr, resultFrame.cmd)
		os.Exit(1)
	}

	if len(resultFrame.data) < 1 {
		fmt.Fprintf(os.Stderr, "result too short\n")
		os.Exit(1)
	}
	resultCode := resultFrame.data[len(resultFrame.data)-1]
	resultID := string(resultFrame.data[:len(resultFrame.data)-1])

	switch resultCode {
	case resultAuthorized:
		fmt.Printf("[client] AUTHORIZED (code=0x%02x) device=%q\n", resultCode, resultID)
	default:
		fmt.Printf("[client] DENIED (code=0x%02x) device=%q data=%x\n", resultCode, resultID, resultFrame.data)
		os.Exit(1)
	}

	// === Step 6: Background reader — print everything from server ===
	stopReader := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopReader:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			fr, err := readFrame(reader)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				return
			}
			fmt.Printf("\r[client] <- RECV: Addr=0x%02x Cmd=0x%02x data=%x\n", fr.addr, fr.cmd, fr.data)
		}
	}()

	// === Step 7: Send regular message every second ===
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Build frame: preamble + addr + cmd + len(LE) + data; CRC computed below.
	frameWithoutCRC := []byte{
		0x24, 0x76, 0x59, 0x2C, 0x00, // $ | addr=0x76 | cmd=0x59 | len=44 (LE)
		0x46, 0x23, 0x00, 0x00, 0xF0, 0xAA, 0x4A, 0x60, // data[0..7]
		0x9F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // data[8..15]
		0x00, 0x00, 0x00, 0x00, 0x73, 0x6F, 0x63, 0x9A, // data[16..23]
		0x19, 0xE8, 0xA1, 0x40, 0x0A, 0xDD, 0x6E, 0x28, // data[24..31]
		0x5D, 0xBA, 0xA5, 0xC0, 0xB9, 0x00, 0x00, 0x00, // data[32..39]
		0x07, 0x00, 0x00, 0x00, // data[40..43]
	}
	// CRC = XOR of entire frame (preamble through end of data)
	regularMsg := append(frameWithoutCRC, crcCalc(frameWithoutCRC))

	var counter byte
	for range ticker.C {
		counter++
		fmt.Printf("[client] sending regular msg #%d (%d bytes)\n", counter, len(regularMsg))
		if _, err := conn.Write(regularMsg); err != nil {
			fmt.Fprintf(os.Stderr, "send message: %v\n", err)
			break
		}
	}
	close(stopReader)
	fmt.Println("[client] done, closing connection")
}

func padID(id string) []byte {
	buf := make([]byte, deviceIDLen)
	copy(buf, id)
	return buf
}

// ---- frame helpers ----

type rawFrame struct {
	addr byte
	cmd  byte
	data []byte
}

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

func encodeFrame(addr, cmd byte, data []byte) []byte {
	dataLen := len(data)
	total := frameMinLen + dataLen
	buf := make([]byte, total)

	buf[0] = framePreamble
	buf[1] = addr
	buf[2] = cmd
	binary.LittleEndian.PutUint16(buf[3:5], uint16(dataLen))
	if dataLen > 0 {
		copy(buf[5:5+dataLen], data)
	}
	crc := crcCalc(buf[:total-1])
	buf[total-1] = crc
	return buf
}

func readFrame(rd *bufio.Reader) (rawFrame, error) {
	for {
		b, err := rd.ReadByte()
		if err != nil {
			return rawFrame{}, fmt.Errorf("read preamble: %w", err)
		}
		if b == framePreamble {
			break
		}
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(rd, header); err != nil {
		return rawFrame{}, fmt.Errorf("read header: %w", err)
	}

	addr := header[0]
	cmd := header[1]
	dataLen := binary.LittleEndian.Uint16(header[2:4])

	if dataLen > frameMaxDataLen {
		return rawFrame{}, fmt.Errorf("data length too large: %d", dataLen)
	}

	rest := make([]byte, int(dataLen)+1)
	if _, err := io.ReadFull(rd, rest); err != nil {
		return rawFrame{}, fmt.Errorf("read data+crc: %w", err)
	}

	total := frameMinLen + int(dataLen)
	full := make([]byte, total)
	full[0] = framePreamble
	full[1] = addr
	full[2] = cmd
	binary.LittleEndian.PutUint16(full[3:5], dataLen)
	copy(full[5:5+dataLen], rest[:dataLen])
	full[total-1] = rest[dataLen]

	expectedCRC := crcCalc(full[:total-1])
	actualCRC := full[total-1]
	if expectedCRC != actualCRC {
		return rawFrame{}, fmt.Errorf("CRC mismatch: calc 0x%02x, got 0x%02x", expectedCRC, actualCRC)
	}

	return rawFrame{addr: addr, cmd: cmd, data: rest[:dataLen]}, nil
}

func signChallenge(priv *rsa.PrivateKey, challenge []byte) ([]byte, error) {
	hashed := sha256.Sum256(challenge)
	return rsa.SignPKCS1v15(cryptorand.Reader, priv, crypto.SHA256, hashed[:])
}

func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}
	return rsaKey, nil
}
