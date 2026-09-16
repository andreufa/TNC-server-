package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
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

	LogDir           string
	LogRetentionDays int
	LogMaxFileMB     int64

	MeasurementRetentionDays int
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

		LogDir:           getenv("LOG_DIR", "logs"),
		LogRetentionDays: getenvInt("LOG_RETENTION_DAYS", 7),
		LogMaxFileMB:     getenvInt64("LOG_MAX_FILE_MB", 100),

		MeasurementRetentionDays: getenvInt("MEASUREMENT_RETENTION_DAYS", 7),
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

func getenvInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getenvInt64(key string, def int64) int64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
