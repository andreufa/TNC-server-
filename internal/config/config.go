package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Config holds all runtime configuration for the server.
type Config struct {
	DatabaseURL        string
	HTTPAddr           string
	TCPAddr            string
	SessionSecret      string
	BootstrapAdminUser string
	BootstrapAdminPass string
}

// Load reads configuration from environment variables, falling back to a .env
// file in the current directory (if present) and then to sane defaults.
func Load() (*Config, error) {
	loadDotEnv(".env")

	cfg := &Config{
		DatabaseURL:        getenv("DATABASE_URL", "postgres://tnc:tnc@localhost:5432/tnc?sslmode=disable"),
		HTTPAddr:           getenv("HTTP_ADDR", ":8080"),
		TCPAddr:            getenv("TCP_ADDR", ":9000"),
		SessionSecret:      getenv("SESSION_SECRET", ""),
		BootstrapAdminUser: getenv("BOOTSTRAP_ADMIN_USER", "admin"),
		BootstrapAdminPass: getenv("BOOTSTRAP_ADMIN_PASSWORD", "admin"),
	}

	if cfg.SessionSecret == "" {
		return nil, fmt.Errorf("SESSION_SECRET must be set")
	}
	return cfg, nil
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// loadDotEnv loads KEY=VALUE lines from the given file into the process
// environment, without overriding variables that are already set. Missing file
// is not an error.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
		}
	}
}
