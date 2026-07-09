package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type handshake struct {
	Protocol string `json:"protocol"`
	LsnCmd   string `json:"lsncmd"`
	DeviceID string `json:"deviceId"`
	Password string `json:"password"`
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n=== TCP Client ===")
		fmt.Print("Enter server address (default: localhost:9000): ")
		addrInput, _ := reader.ReadString('\n')
		addrInput = strings.TrimSpace(addrInput)
		if addrInput == "" {
			addrInput = "localhost:9000"
		}

		fmt.Print("Enter device ID: ")
		deviceID, _ := reader.ReadString('\n')
		deviceID = strings.TrimSpace(deviceID)
		if deviceID == "" {
			fmt.Println("❌ Device ID cannot be empty")
			continue
		}

		fmt.Print("Enter password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)
		if password == "" {
			fmt.Println("❌ Password cannot be empty")
			continue
		}

		// Пытаемся авторизоваться
		if tryAuth(addrInput, deviceID, password) {
			fmt.Println("✅ Connection successful!")
			fmt.Println("Press Ctrl+C to exit")
			break
		} else {
			fmt.Println("❌ Authorization failed. Try again? (y/n)")
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer != "y" && answer != "yes" {
				fmt.Println("Goodbye!")
				break
			}
		}
	}
}

func tryAuth(addr, deviceID, password string) bool {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return false
	}
	defer conn.Close()

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

	fmt.Printf("\n📤 Sending: %s\n", string(data))
	_, err = conn.Write(append(data, '\n'))
	if err != nil {
		log.Printf("Failed to send: %v", err)
		return false
	}

	// Читаем ответ
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
		return false
	}

	response := string(buf[:n])
	fmt.Printf("📥 Received: %q\n", response)

	if response == "Msg100Ok\n" {
		// Авторизация успешна, держим соединение открытым
		go func() {
			// Читаем сообщения от сервера
			for {
				conn.SetReadDeadline(time.Now().Add(30 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					log.Printf("Disconnected: %v", err)
					os.Exit(0)
				}
				fmt.Printf("\n📨 Server message: %s", string(buf[:n]))
				fmt.Print("\n> ")
			}
		}()

		// Интерактивная отправка сообщений
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("\n📝 Connected! Enter messages to send to server (or 'quit' to exit):")
		for {
			fmt.Print("> ")
			msg, _ := reader.ReadString('\n')
			msg = strings.TrimSpace(msg)

			if msg == "quit" || msg == "exit" {
				fmt.Println("Goodbye!")
				return true
			}

			if msg == "" {
				continue
			}

			// // Проверяем что это валидный JSON
			// if !json.Valid([]byte(msg)) {
			// 	fmt.Println("⚠️  Message must be valid JSON")
			// 	continue
			// }

			_, err := conn.Write(append([]byte(msg), '\n'))
			if err != nil {
				log.Printf("Failed to send: %v", err)
				return true
			}
			fmt.Printf("✅ Sent: %s\n", msg)
		}
	}

	return false
}
