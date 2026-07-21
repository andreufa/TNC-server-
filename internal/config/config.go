package config

import (
	"fmt"
	"net/url"
	"os"
)

// Config holds all runtime configuration for the server.
type Config struct {
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	HTTPAddr           string
	TCPAddr            string
	CryptoTCPAddr      string
	SessionSecret      string
	BootstrapAdminUser string
	BootstrapAdminPass string
}

func Load() (*Config, error) {
	cfg := &Config{
		DBHost:             getenv("DB_HOST", "localhost"),
		DBPort:             getenv("DB_PORT", "5432"),
		DBUser:             getenv("DB_USER", "tnc"),
		DBPassword:         getenv("DB_PASSWORD", "tnc"),
		DBName:             getenv("DB_NAME", "tnc"),
		DBSSLMode:          getenv("DB_SSL_MODE", "disable"),
		HTTPAddr:           getenv("HTTP_ADDR", ":8080"),
		TCPAddr:            getenv("TCP_ADDR", ":9000"),
		CryptoTCPAddr:      getenv("CRYPTO_TCP_ADDR", ":9001"),
		SessionSecret:      getenv("SESSION_SECRET", "dev-secret-change-in-production"),
		BootstrapAdminUser: getenv("BOOTSTRAP_ADMIN_USER", "admin"),
		BootstrapAdminPass: getenv("BOOTSTRAP_ADMIN_PASSWORD", "admin"),
	}

	return cfg, nil
}

// DatabaseURL returns a valid Postgres connection string.
func (c *Config) DatabaseURL() string {
	u := url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%s", c.DBHost, c.DBPort),
		Path:   "/" + c.DBName,
	}
	u.User = url.UserPassword(c.DBUser, c.DBPassword)
	q := u.Query()
	q.Set("sslmode", c.DBSSLMode)
	u.RawQuery = q.Encode()
	return u.String()
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
