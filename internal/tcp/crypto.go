package tcp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

const (
	// ChallengeSize is the number of random bytes in the challenge.
	ChallengeSize = 8

	// TimestampSize is the number of bytes used for the Unix timestamp.
	TimestampSize = 8

	// ChallengeTTL is how long a challenge remains valid.
	ChallengeTTL = 5 * time.Minute
)

// GenerateChallenge creates a random 8-byte nonce + current Unix timestamp (8 bytes, big-endian).
// Returns a 16-byte challenge.
func GenerateChallenge() ([]byte, error) {
	nonce := make([]byte, ChallengeSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ts := make([]byte, TimestampSize)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	challenge := make([]byte, ChallengeSize+TimestampSize)
	copy(challenge[:ChallengeSize], nonce)
	copy(challenge[ChallengeSize:], ts)
	return challenge, nil
}

// ExtractTimestamp parses the timestamp from a challenge (last 8 bytes, big-endian).
func ExtractTimestamp(challenge []byte) (time.Time, error) {
	if len(challenge) < ChallengeSize+TimestampSize {
		return time.Time{}, errors.New("challenge too short")
	}
	raw := binary.BigEndian.Uint64(challenge[ChallengeSize:])
	return time.Unix(int64(raw), 0), nil
}

// IsChallengeExpired returns true if the challenge timestamp is older than ChallengeTTL.
func IsChallengeExpired(challenge []byte) (bool, error) {
	ts, err := ExtractTimestamp(challenge)
	if err != nil {
		return true, err
	}
	return time.Since(ts) > ChallengeTTL, nil
}

// ParsePublicKey decodes a PEM-encoded RSA public key.
func ParsePublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	// Try PKIX format first (SubjectPublicKeyInfo)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not an RSA public key")
	}
	return rsaPub, nil
}

// ParsePrivateKey decodes a PEM-encoded RSA private key (PKCS1 or PKCS8).
func ParsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	// Try PKCS8
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not an RSA private key")
	}
	return rsaKey, nil
}

// SignChallenge signs a challenge using the device's RSA private key.
// Uses RSASSA-PKCS1-V1_5 with SHA-256.
func SignChallenge(priv *rsa.PrivateKey, challenge []byte) ([]byte, error) {
	hashed := sha256.Sum256(challenge)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("sign challenge: %w", err)
	}
	return sig, nil
}

// VerifyChallengeResponse verifies an RSA signature over the challenge using
// the device's public key. Returns nil on success.
func VerifyChallengeResponse(pub *rsa.PublicKey, challenge, signature []byte) error {
	hashed := sha256.Sum256(challenge)
	err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	return nil
}
