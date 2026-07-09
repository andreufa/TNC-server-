package config

import (
	"bufio"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
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
	SessionSecret      string
	BootstrapAdminUser string
	BootstrapAdminPass string
}

func Load() (*Config, error) {
	// 1. Пытаемся загрузить .env, только если он реально есть
	if _, err := os.Stat(".env"); err == nil {
		log.Println("[DEBUG] .env found -> loading from file")
		loadDotEnv(".env") // ✅ просто вызываем, ничего не присваиваем
	} else {
		// Это нормально для Docker: файла нет, полагаемся на переменные окружения
		log.Println("[INFO] .env not found -> relying on OS environment variables (Docker mode)")
	}

	// 2. То же самое для .env.local (только локальная разработка)
	if _, err := os.Stat(".env.local"); err == nil {
		log.Println("[DEBUG] .env.local found -> applying local overrides")
		loadDotEnv(".env.local") // ✅ просто вызываем
	} else {
		log.Println("[INFO] .env.local not found -> no local overrides (Docker mode)")
	}

	cfg := &Config{
		DBHost:             getenv("DB_HOST", "localhost"),
		DBPort:             getenv("DB_PORT", "5432"),
		DBUser:             getenv("DB_USER", "tnc"),
		DBPassword:         getenv("DB_PASSWORD", "tnc"),
		DBName:             getenv("DB_NAME", "tnc"),
		DBSSLMode:          getenv("DB_SSL_MODE", "disable"),
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

// DatabaseURL возвращает валидную строку подключения, где ? и экранирование делает url.URL
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

func loadDotEnv(path string) {
	// ПРАВИЛЬНО: получаем оба значения
	dir, err := os.Getwd()
	if err != nil {
		log.Printf("DEBUG: loadDotEnv: failed to get working directory: %v", err)
		return
	}
	log.Printf("DEBUG: loadDotEnv trying to open: %s (working dir: %s)", path, dir)

	f, err := os.Open(path)
	if err != nil {
		log.Printf("DEBUG: loadDotEnv: file not found or error: %v", err)
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	count := 0
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

		os.Setenv(key, val)
		count++
	}
}
