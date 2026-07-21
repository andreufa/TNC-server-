// challenge_client is a test client for the crypto handshake TCP server.
//
// Usage:
//
//	go run ./cmd/challenge_client <device_id> [private_key.pem]
//
// If no private key file is provided, the built-in stub key is used (matching
// public key must be registered on the server for this device).
//
// Generate your own key pair with OpenSSL:
//
//	openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
//	openssl rsa -pubout -in private_key.pem -out public_key.pem
//
// Register the public key (see cmd/keygen), then connect:
//
//	go run ./cmd/challenge_client 37777 private_key.pem
//
// The client:
//  1. Connects to the crypto TCP server (default :9001)
//  2. Sends a Hello frame with the device ID
//  3. Receives a Challenge frame (8 random + 8 timestamp bytes)
//  4. Signs the challenge with the private key (RSA PKCS#1 v1.5 SHA-256)
//  5. Sends a Response frame with the device ID + signature
//  6. Receives Success or Denied
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

	addrDevice = 0x20

	cmdHello     byte = 0x01
	cmdChallenge byte = 0x02
	cmdResponse  byte = 0x03
	cmdSuccess   byte = 0x04
	cmdDenied    byte = 0x05
	cmdMessage   byte = 0x06
)

// stubPrivateKey is a pre-generated RSA 2048-bit key used when no key file is
// provided.  The matching public key is in _stub_public.pem.  Generate your
// own key pair with OpenSSL for production use.
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

	// --- Load private key (file or built-in stub) ---
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

	// === Step 1: Send Hello ===
	fmt.Printf("[client] sending hello for device %q\n", deviceID)
	helloFrame := encodeFrame(addrDevice, cmdHello, []byte(deviceID))
	if _, err := conn.Write(helloFrame); err != nil {
		fmt.Fprintf(os.Stderr, "send hello: %v\n", err)
		os.Exit(1)
	}

	// === Step 2: Receive Challenge ===
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	challengeFrame, err := readFrame(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read challenge: %v\n", err)
		os.Exit(1)
	}
	if challengeFrame.cmd == cmdDenied {
		fmt.Printf("[client] DENIED: %s\n", string(challengeFrame.data))
		os.Exit(1)
	}
	if challengeFrame.cmd != cmdChallenge {
		fmt.Fprintf(os.Stderr, "expected challenge (0x%02x), got 0x%02x\n", cmdChallenge, challengeFrame.cmd)
		os.Exit(1)
	}

	challenge := challengeFrame.data
	fmt.Printf("[client] received challenge: %d bytes (nonce=%x ts=%d)\n",
		len(challenge), challenge[:8], binary.BigEndian.Uint64(challenge[8:]))

	// === Step 3: Sign challenge ===
	signature, err := signChallenge(privKey, challenge)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[client] signed challenge: signature=%d bytes\n", len(signature))

	// === Step 4: Send Response ===
	// Format: [2 bytes ID length] [deviceID] [signature]
	idBytes := []byte(deviceID)
	respData := make([]byte, 2+len(idBytes)+len(signature))
	binary.BigEndian.PutUint16(respData[:2], uint16(len(idBytes)))
	copy(respData[2:2+len(idBytes)], idBytes)
	copy(respData[2+len(idBytes):], signature)

	fmt.Printf("[client] sending response (data=%d bytes)\n", len(respData))
	respFrame := encodeFrame(addrDevice, cmdResponse, respData)
	if _, err := conn.Write(respFrame); err != nil {
		fmt.Fprintf(os.Stderr, "send response: %v\n", err)
		os.Exit(1)
	}

	// === Step 5: Receive result ===
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	resultFrame, err := readFrame(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read result: %v\n", err)
		os.Exit(1)
	}

	switch resultFrame.cmd {
	case cmdSuccess:
		fmt.Printf("[client] SUCCESS: %s\n", string(resultFrame.data))
	case cmdDenied:
		fmt.Printf("[client] DENIED: %s\n", string(resultFrame.data))
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unexpected response: cmd=0x%02x data=%s\n", resultFrame.cmd, string(resultFrame.data))
		os.Exit(1)
	}

	// === Step 6: Loop — wait for Enter, send message ===
	stdin := bufio.NewReader(os.Stdin)
	msgData := []byte("$7052000000000000000001111")
	for {
		fmt.Print("[client] Press Enter to send (Ctrl+C to exit)...")
		_, err := stdin.ReadString('\n')
		if err != nil {
			fmt.Printf("\n[client] input closed (%v), exiting loop\n", err)
			break
		}

		msgFrame := encodeFrame(addrDevice, cmdMessage, msgData)
		fmt.Printf("[client] sending message frame: %q (frame=%d bytes)\n", string(msgData), len(msgFrame))
		if _, err := conn.Write(msgFrame); err != nil {
			fmt.Fprintf(os.Stderr, "send message: %v\n", err)
			break
		}
	}
	fmt.Println("[client] done, closing connection")
}

// ---- frame helpers (duplicated for standalone client) ----

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
	binary.BigEndian.PutUint16(buf[3:5], uint16(dataLen))
	if dataLen > 0 {
		copy(buf[5:5+dataLen], data)
	}
	crc := crcCalc(buf[1 : total-1])
	buf[total-1] = crc
	return buf
}

func readFrame(rd *bufio.Reader) (rawFrame, error) {
	// Scan for preamble
	for {
		b, err := rd.ReadByte()
		if err != nil {
			return rawFrame{}, fmt.Errorf("read preamble: %w", err)
		}
		if b == framePreamble {
			break
		}
	}

	// Read header: addr + cmd + len(2)
	header := make([]byte, 4)
	if _, err := io.ReadFull(rd, header); err != nil {
		return rawFrame{}, fmt.Errorf("read header: %w", err)
	}

	addr := header[0]
	cmd := header[1]
	dataLen := binary.BigEndian.Uint16(header[2:4])

	if dataLen > frameMaxDataLen {
		return rawFrame{}, fmt.Errorf("data length too large: %d", dataLen)
	}

	// Read data + CRC
	rest := make([]byte, int(dataLen)+1)
	if _, err := io.ReadFull(rd, rest); err != nil {
		return rawFrame{}, fmt.Errorf("read data+crc: %w", err)
	}

	// Reconstruct for CRC check
	total := frameMinLen + int(dataLen)
	full := make([]byte, total)
	full[0] = framePreamble
	full[1] = addr
	full[2] = cmd
	binary.BigEndian.PutUint16(full[3:5], dataLen)
	copy(full[5:5+dataLen], rest[:dataLen])
	full[total-1] = rest[dataLen]

	expectedCRC := crcCalc(full[1 : total-1])
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
