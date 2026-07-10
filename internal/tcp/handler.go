package tcp

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"net"
	"time"
)

// handleConnection обрабатывает одно TCP-соединение
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	reader := bufio.NewReader(conn)

	// --- handshake ---
	if idleTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))
	}

	line, err := reader.ReadBytes('\n')
	if err != nil {
		msg := formatLog("handshake", remote, "read error: "+err.Error())
		s.logChan <- msg
		log.Printf("tcp: %s handshake read error: %v", remote, err)
		return
	}

	var hs handshake
	if err := json.Unmarshal(line, &hs); err != nil {
		conn.Write([]byte(msgDenied))
		msg := formatLog("auth", remote, "bad handshake json: "+err.Error())
		s.logChan <- msg
		log.Printf("tcp: %s bad handshake json: %v", remote, err)
		return
	}

	// Проверяем protocol и lsncmd
	if hs.Protocol != expectedProtocol || hs.LsnCmd != expectedLsnCmd {
		conn.Write([]byte(msgDenied))
		msg := formatLog("auth", remote, "invalid protocol/lsncmd: "+hs.Protocol+"/"+hs.LsnCmd)
		s.logChan <- msg
		log.Printf("tcp: %s invalid protocol/lsncmd: %s/%s", remote, hs.Protocol, hs.LsnCmd)
		return
	}

	// Проверяем устройство
	ok, err := s.devices.VerifyDevice(context.Background(), hs.DeviceID, hs.Password)
	if err != nil {
		conn.Write([]byte(msgDenied))
		msg := formatLog("auth", remote, "verify error: "+err.Error())
		s.logChan <- msg
		log.Printf("tcp: %s verify error: %v", remote, err)
		return
	}

	if !ok {
		conn.Write([]byte(msgDenied))
		msg := formatLog("auth", remote, "denied (device "+hs.DeviceID+")")
		s.logChan <- msg
		log.Printf("tcp: %s denied (device %q)", remote, hs.DeviceID)
		return
	}

	if _, err := conn.Write([]byte(msgOk)); err != nil {
		return
	}
	connMsg := formatLog("connect", hs.DeviceID, "connected from "+remote)
	s.logChan <- connMsg
	log.Printf("tcp: %s verified as device %q", remote, hs.DeviceID)

	// --- subscribe & pump ---
	sub := s.hub.Subscribe()

	// writer goroutine: forward broadcast messages to this client.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for msg := range sub.C {
			if _, err := conn.Write(append(msg, '\n')); err != nil {
				return
			}
		}
	}()

	// reader loop: read \n-delimited JSON lines and broadcast them.
	for {
		if idleTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}
		trimmed := trimLine(line)
		if len(trimmed) == 0 {
			continue
		}
		// Отправляем сообщение в лог
		msg := formatLog("message", hs.DeviceID, string(trimmed))
		s.logChan <- msg
		// if !json.Valid(trimmed) {
		// 	log.Printf("tcp: from [%s] ignoring non-json message: %s", hs.DeviceID, string(trimmed))
		// 	continue
		// }
		log.Printf("tcp: from [%s] received message: %s", hs.DeviceID, string(trimmed))
		payload := make([]byte, len(trimmed))
		copy(payload, trimmed)
		s.hub.Broadcast(payload, sub.ID())
	}
	disconnectMsg := formatLog("disconnect", hs.DeviceID, "disconnected")
	s.logChan <- disconnectMsg

	log.Printf("tcp: %s (device %q) disconnected", remote, hs.DeviceID)
	s.hub.Unsubscribe(sub)
	conn.Close()
	<-writerDone
}

// trimLine удаляет \n и \r в конце
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
		DeviceID  string `json:"device_id"`
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
