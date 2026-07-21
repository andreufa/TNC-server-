package tcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// Константа для разделителя сообщений в TCP протоколе
// Используется только для общения с клиентом (прием и отправка)
const MessageDelimiter = '\x00' // 0x00 (NUL)

type commandMsg struct {
	Protocol string `json:"protocol"`
	LsnCmd   string `json:"lsncmd"`
	DeviceID string `json:"deviceId"`
	Payload  string `json:"payload"`
}

// handleConnection обрабатывает одно TCP-соединение
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	// Лог подключения (IP известен, DeviceID ещё нет)
	log.Printf("tcp: [%s] new connection accepted", remote)
	s.logChan <- formatLog(
		"connect",
		"", // DeviceID пока неизвестен
		fmt.Sprintf("new connection from %s", remote),
	)
	reader := bufio.NewReader(conn)

	// --- handshake ---
	if idleTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
	}

	// Читаем handshake (клиент отправляет с 0x00)
	line, err := reader.ReadBytes(MessageDelimiter)
	if err != nil {
		log.Printf("tcp: %s handshake read error: %v", remote, err)
		return
	}

	// Убираем разделитель
	line = bytes.TrimRight(line, string(MessageDelimiter)+"\r")

	var hs handshake
	if err := json.Unmarshal(line, &hs); err != nil {
		s.sendResponse(conn, "Denied", "bad handshake json: "+err.Error())
		msg := formatLog("auth", remote, "bad handshake json: "+err.Error())
		s.logChan <- msg
		log.Printf("tcp: %s bad handshake json: %v", remote, err)
		return
	}

	if hs.Protocol != expectedProtocol || hs.LsnCmd != expectedLsnCmd {
		s.sendResponse(conn, "Denied", "invalid protocol/lsncmd")
		reason := fmt.Sprintf("invalid protocol/lsncmd: %s/%s", hs.Protocol, hs.LsnCmd)
		msg := formatLog("auth", remote, reason)
		s.logChan <- msg
		log.Printf("tcp: %s auth failed: %s", remote, reason)
		return
	}

	ok, err := s.devices.VerifyDevice(context.Background(), hs.DeviceID, hs.Password)
	if err != nil || !ok {
		s.sendResponse(conn, "Denied", "authentication failed")
		reason := "verify error: " + err.Error()
		if !ok {
			reason = "denied (device " + hs.DeviceID + ")"
		}
		msg := formatLog("auth", remote, reason)
		s.logChan <- msg
		log.Printf("tcp: %s auth failed: %s", remote, reason)
		return
	}
	if updateErr := s.devices.UpdateLastSeen(context.Background(), hs.DeviceID); updateErr != nil {
		// Важно: не прерываем соединение из-за ошибки БД,
		// просто логируем. Устройство всё равно подключено.
		log.Printf("tcp: [%s] failed to update last_seen_at in DB: %v", hs.DeviceID, updateErr)
	}

	// === ПОДТВЕРЖДЕНИЕ РЕГИСТРАЦИИ ===
	cleanHandshakeCmd := strings.TrimSpace(hs.LsnCmd)
	handshakeStatus := "Msg" + cleanHandshakeCmd + "Ok"
	s.sendResponse(conn, handshakeStatus, "")

	log.Printf("tcp: [%s] sent handshake confirmation: %s", hs.DeviceID, handshakeStatus)

	s.logChan <- formatLog(
		"auth",
		hs.DeviceID,
		fmt.Sprintf("handshake confirmed: %s", handshakeStatus),
	)
	// ========================================================

	// --- subscribe & pump ---
	sub := s.hub.Subscribe()

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for msg := range sub.C {
			// Отправляем с разделителем для клиента
			if _, wErr := conn.Write(append(msg, MessageDelimiter)); wErr != nil {
				return
			}
		}
	}()

	// --- reader loop ---
	for {
		if idleTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(idleTimeout))
		}

		// 1. Читаем до разделителя (константа MessageDelimiter)
		line, err := reader.ReadBytes(MessageDelimiter)
		if err != nil {
			// Сюда попадут: таймаут (если стоит deadline), EOF, разрыв соединения и т.д.
			if !errors.Is(err, io.EOF) {
				log.Printf("tcp: [%s] read error in loop: %v", hs.DeviceID, err)
			}
			break
		}

		// 2. Для отладки: смотрим, что реально пришло (в HEX)
		log.Printf("tcp: [%s] raw message received (hex): %x, len=%d", hs.DeviceID, line, len(line))

		// 3. Убираем разделитель и возможный \r
		trimmed := bytes.TrimRight(line, string(MessageDelimiter)+"\r")

		// 4. Защита от слишком длинных сообщений (DoS-защита)
		const maxMsgLen = 4096
		if len(trimmed) > maxMsgLen {
			log.Printf("tcp: [%s] message too long (%d bytes), dropping", hs.DeviceID, len(trimmed))
			continue
		}

		if len(trimmed) == 0 {
			continue // Пропускаем пустые пакеты
		}

		msgLog := formatLog("message", hs.DeviceID, string(trimmed))
		s.logChan <- msgLog
		log.Printf("tcp: from [%s] received message: %s", hs.DeviceID, string(trimmed))

		if updateErr := s.devices.UpdateLastSeen(context.Background(), hs.DeviceID); updateErr != nil {
			log.Printf("tcp: [%s] failed to update last_seen_at in DB: %v", hs.DeviceID, updateErr)
		}

		var incoming commandMsg
		if err := json.Unmarshal(trimmed, &incoming); err != nil {
			log.Printf("tcp: [%s] invalid JSON: %v, raw data: %x", hs.DeviceID, err, trimmed)
			continue
		}

		cleanLsnCmd := strings.TrimSpace(incoming.LsnCmd)

		// === ПРОВЕРКА КОМАНДЫ ===
		if !IsValidCommand(cleanLsnCmd) {
			msg := fmt.Sprintf("ignored unsupported lsncmd=%q", cleanLsnCmd)
			log.Printf("tcp: [%s] %s", hs.DeviceID, msg)
			s.logChan <- formatLog("message", hs.DeviceID, msg)

			s.sendResponse(conn, "", "Unsupported command: "+cleanLsnCmd)
			continue
		}
		// =========================

		// === ПОДТВЕРЖДЕНИЕ ПРИЁМА ===
		confirmStatus := "Msg" + cleanLsnCmd + "Ok"
		s.sendResponse(conn, confirmStatus, "")

		log.Printf("tcp: [%s] sent confirmation status: %s", hs.DeviceID, confirmStatus)
		// ========================================================

		// === ОСНОВНАЯ ЛОГИКА ОБРАБОТКИ ===
		payloadHex := strings.ReplaceAll(incoming.Payload, " ", "")

		bin, err := hex.DecodeString(payloadHex)
		if err != nil {
			log.Printf("tcp: [%s] invalid hex payload: %v", hs.DeviceID, err)
			continue
		}

		const minLen = 5
		if len(bin) < minLen {
			log.Printf("tcp: [%s] payload too short: %d bytes", hs.DeviceID, len(bin))
			continue
		}

		// Протокол: меняем байт адреса и пересчитываем CRC
		bin[1] = 0x70
		crc := crcCalc(bin[:len(bin)-1])
		bin[len(bin)-1] = crc

		finalHex := hex.EncodeToString(bin)

		outgoingMsg := commandMsg{
			Protocol: expectedProtocol,
			LsnCmd:   "110",
			DeviceID: hs.DeviceID,
			Payload:  finalHex,
		}

		jsonData, marshalErr := json.Marshal(outgoingMsg)
		if marshalErr != nil {
			log.Printf("tcp: failed to marshal outgoing JSON: %v", marshalErr)
			continue
		}

		s.hub.Broadcast(jsonData, sub.ID())
		msgLogHub := formatLog("broadcast", hs.DeviceID, string(jsonData))
		s.logChan <- msgLogHub
	}

	disconnectMsg := formatLog("disconnect", hs.DeviceID, "disconnected")
	s.logChan <- disconnectMsg
	log.Printf("tcp: %s (device %q) disconnected", remote, hs.DeviceID)

	s.hub.Unsubscribe(sub)
	conn.Close()
	<-writerDone
}

// sendResponse отправляет ответ клиенту с разделителем MessageDelimiter
func (s *Server) sendResponse(conn net.Conn, status string, errorMsg string) {
	var resp interface{}
	if status != "" {
		resp = struct {
			Status string `json:"status"`
		}{
			Status: status,
		}
	} else {
		resp = struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}{
			Success: false,
			Error:   errorMsg,
		}
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return
	}

	// Отправляем с разделителем
	if _, writeErr := conn.Write(append(jsonData, MessageDelimiter)); writeErr != nil {
		log.Printf("Write error sending response: %v", writeErr)
	}
}

func trimLine(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func formatLog(eventType, deviceID, message string) string {
	logEntry := struct {
		Timestamp string `json:"timestamp"`
		Type      string `json:"type"`
		DeviceID  string `json:"deviceId"`
		Message   string `json:"message"`
	}{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		Type:      eventType,
		DeviceID:  deviceID,
		Message:   message,
	}

	data, _ := json.Marshal(logEntry)
	return string(data)
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

var allowedCommands = map[string]struct{}{
	"109": {},
	"110": {},
}

func IsValidCommand(cmd string) bool {
	cleanCmd := strings.TrimSpace(cmd)
	_, ok := allowedCommands[cleanCmd]
	return ok
}
