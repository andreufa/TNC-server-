package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type handshake struct {
	Protocol string `json:"protocol"`
	LsnCmd   string `json:"lsncmd"`
	DeviceID string `json:"deviceId"`
	Password string `json:"password"`
}

type commandMsg struct {
	Protocol string `json:"protocol"`
	LsnCmd   string `json:"lsncmd"`
	DeviceID string `json:"deviceId"`
	Payload  string `json:"payload"`
}

// --- НАСТРОЙКИ: МЕНЯЙ ЗДЕСЬ ---
const (
	// defaultServerAddr = "localhost:9000"
	defaultServerAddr = "194.58.79.41:6407"
	testDeviceID      = "N-11"
	testPayloadHex    = "24 76 59 2C 00 46 23 00 00 F0 AA 4A 60 9F 01 00 00 00 00 00 00 00 00 00 00 73 6F 63 9A 19 E8 A1 40 0A DD 6E 28 5D BA A5 C0 B9 00 00 00 07 00 00 00 F4"
)

var (
	running bool
	mu      sync.Mutex
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	running = true

	// Настраиваем обработку сигналов
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		mu.Lock()
		running = false
		mu.Unlock()
		fmt.Println("\n\n👋 Shutting down gracefully...")
		os.Exit(0)
	}()

	for running {
		fmt.Println("\n=== TCP Client ===")
		fmt.Print("Enter server address (default: " + defaultServerAddr + "): ")
		addrInput, _ := reader.ReadString('\n')
		addrInput = strings.TrimSpace(addrInput)
		if addrInput == "" {
			addrInput = defaultServerAddr
		}

		// Пытаемся установить TCP соединение
		fmt.Printf("🔌 Connecting to %s...\n", addrInput)
		conn, err := net.Dial("tcp", addrInput)
		if err != nil {
			log.Printf("❌ TCP connection failed: %v", err)
			fmt.Println("Failed to connect. Try again? (y/n)")
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				fmt.Println("Goodbye!")
				return
			}
			continue
		}
		fmt.Println("✅ TCP connection established successfully!")

		// Теперь запрашиваем Device ID и пароль
		fmt.Print("Enter device ID: ")
		deviceID, _ := reader.ReadString('\n')
		deviceID = strings.TrimSpace(deviceID)
		if deviceID == "" {
			fmt.Println("❌ Device ID cannot be empty")
			conn.Close()
			continue
		}

		fmt.Print("Enter password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)
		if password == "" {
			fmt.Println("❌ Password cannot be empty")
			conn.Close()
			continue
		}

		// Пытаемся авторизоваться
		if tryAuth(conn, deviceID, password, reader) {
			fmt.Println("✅ Connection successful!")
			fmt.Println("Press Enter to send test command (or Ctrl+C to exit)")
			break
		} else {
			fmt.Println("❌ Authorization failed. Try again? (y/n)")
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				fmt.Println("Goodbye!")
				conn.Close()
				return
			}
			// Закрываем соединение перед повторной попыткой
			conn.Close()
		}
	}
}

// formatPayload форматирует payload: верхний регистр и пробелы между байтами
func formatPayload(payload string) string {
	// Убираем все пробелы
	clean := strings.ReplaceAll(payload, " ", "")
	// Приводим к верхнему регистру
	clean = strings.ToUpper(clean)

	// Разбиваем по 2 символа и вставляем пробелы
	var result strings.Builder
	for i := 0; i < len(clean); i += 2 {
		if i > 0 {
			result.WriteString(" ")
		}
		if i+2 <= len(clean) {
			result.WriteString(clean[i : i+2])
		}
	}
	return result.String()
}

const msgDelimiter byte = 0x00

func tryAuth(conn net.Conn, deviceID, password string, reader *bufio.Reader) bool {
	// Создаём reader для корректного чтения до разделителя
	r := bufio.NewReader(conn)

	// Отправляем handshake
	hs := handshake{
		Protocol: "progress_konsul_bin",
		LsnCmd:   "104",
		DeviceID: deviceID,
		Password: password,
	}

	data, err := json.Marshal(hs)
	if err != nil {
		log.Printf("Failed to marshal: %v", err)
		return false
	}

	fmt.Printf("\n📤 Sending handshake: %s\n", string(data))
	// ОТПРАВКА: используем константу msgDelimiter
	_, err = conn.Write(append(data, msgDelimiter))
	if err != nil {
		log.Printf("Failed to send: %v", err)
		return false
	}

	// Читаем ответ строго до разделителя
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := r.ReadBytes(msgDelimiter)
	if err != nil {
		log.Printf("Failed to read auth response: %v", err)
		return false
	}
	// Убираем разделитель и возможный \r
	rawData := bytes.TrimRight(line, string(msgDelimiter)+"\r")

	if len(rawData) == 0 {
		log.Println("Empty response from server")
		return false
	}

	fmt.Printf("📥 Received: %s\n", string(rawData))

	// Парсим JSON ответ
	var authResp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rawData, &authResp); err != nil {
		log.Printf("Failed to parse auth response: %v, raw=%x", err, rawData)
		return false
	}

	// Проверяем, что статус заканчивается на "Ok"
	if !strings.HasSuffix(authResp.Status, "Ok") {
		log.Printf("Auth status is not OK: %s", authResp.Status)
		return false
	}

	// Авторизация успешна — держим соединение открытым
	// Фоновый читатель: выводит всё, что приходит от сервера
	go func() {
		for {
			// Проверяем флаг running перед чтением
			mu.Lock()
			if !running {
				mu.Unlock()
				return
			}
			mu.Unlock()

			conn.SetReadDeadline(time.Now().Add(30 * time.Second))

			// ЧИТАЕМ ДО РАЗДЕЛИТЕЛЯ (используем константу)
			line, err := r.ReadBytes(msgDelimiter)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("Disconnected: %v", err)
				mu.Lock()
				running = false
				mu.Unlock()
				os.Exit(0)
			}

			// Убираем разделитель и \r
			rawData := bytes.TrimRight(line, string(msgDelimiter)+"\r")
			if len(rawData) == 0 {
				continue
			}

			var jsonMsg map[string]interface{}
			if err := json.Unmarshal(rawData, &jsonMsg); err == nil {
				if payload, ok := jsonMsg["payload"].(string); ok {
					jsonMsg["payload"] = formatPayload(payload)
				}

				compactJSON, _ := json.Marshal(jsonMsg)
				fmt.Printf("\n📨 Server message: %s\n> ", string(compactJSON))
			} else {
				// Если не JSON — выводим HEX, чтобы видеть, что реально пришло
				fmt.Printf("\n📨 Server message (raw bytes, hex): %x\n> ", rawData)
			}
		}
	}()

	fmt.Println("\n📝 Connected. Press Enter to send test command.")
	for {
		// Проверяем флаг running перед чтением ввода
		mu.Lock()
		if !running {
			mu.Unlock()
			return false
		}
		mu.Unlock()

		fmt.Print("> ")
		msg, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Input error: %v", err)
			return false
		}
		msg = strings.TrimSpace(msg)

		// Проверяем флаг running после чтения
		mu.Lock()
		if !running {
			mu.Unlock()
			return false
		}
		mu.Unlock()

		if msg == "" {
			cmd := commandMsg{
				Protocol: "progress_konsul_bin",
				LsnCmd:   "109",
				DeviceID: deviceID,
				Payload:  testPayloadHex,
			}

			data, err := json.Marshal(cmd)
			if err != nil {
				log.Printf("Failed to marshal test command: %v", err)
				continue
			}

			// ОТПРАВКА ТЕСТОВОЙ КОМАНДЫ: используем константу msgDelimiter
			_, err = conn.Write(append(data, msgDelimiter))
			if err != nil {
				log.Printf("Failed to send test command: %v", err)
				return false
			}

			fmt.Printf("✅ Sent test command:\n%s\n\n", string(data))
			continue
		}

		if strings.HasPrefix(msg, "{") {
			// ОТПРАВКА КАСТОМНОГО JSON: используем константу msgDelimiter
			_, err = conn.Write(append([]byte(msg), msgDelimiter))
			if err != nil {
				log.Printf("Failed to send custom message: %v", err)
				return false
			}
			fmt.Printf("✅ Sent custom JSON:\n%s\n", msg)
		} else {
			fmt.Println("⚠️ Enter empty line to send test command, or valid JSON to send custom message")
		}
	}
}
