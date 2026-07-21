// keygen registers an OpenSSL-generated RSA public key for device 37777.
//
// Usage:
//
//	go run ./cmd/keygen <public_key.pem>
//
// Generate the key pair with OpenSSL:
//
//	openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
//	openssl rsa -pubout -in private_key.pem -out public_key.pem
//
// Then register:
//
//	go run ./cmd/keygen public_key.pem
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: go run ./cmd/keygen <public_key.pem>\n")
		os.Exit(1)
	}

	pubPath := os.Args[1]
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read public key file: %v\n", err)
		os.Exit(1)
	}

	pubPEMStr := strings.TrimSpace(string(pubPEM))

	fmt.Println("-- SQL to register device 37777 with the public key:")
	fmt.Println()
	fmt.Printf(`INSERT INTO devices (id, public_key, in_service)
VALUES (
    '37777',
    '%s',
    true
)
ON CONFLICT (id) DO UPDATE SET
    public_key  = EXCLUDED.public_key,
    in_service  = EXCLUDED.in_service,
    deleted_at  = NULL;
`, escapeSQL(pubPEMStr))

	fmt.Println()
	fmt.Println("Apply the SQL above to your database, or use the equivalent")
	fmt.Println("psql command:")
	fmt.Printf("  psql $DATABASE_URL -c \"UPDATE devices SET public_key = '%s', in_service = true WHERE id = '37777';\"\n", escapeSQL(pubPEMStr))
	fmt.Println()
	fmt.Printf("Registered at: %s\n", time.Now().Format("2006-01-02 15:04:05"))
}

func escapeSQL(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c == '\'' {
			b.WriteString("''")
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}
