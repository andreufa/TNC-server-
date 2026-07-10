package web

import (
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// LogServer управляет WebSocket соединениями для логов
type LogServer struct {
	clients   map[*websocket.Conn]bool
	clientsMu sync.RWMutex
	logChan   <-chan string
	done      chan struct{}
}

// NewLogServer создает новый сервер логов
func NewLogServer(logChan <-chan string) *LogServer {
	ls := &LogServer{
		clients: make(map[*websocket.Conn]bool),
		logChan: logChan,
		done:    make(chan struct{}),
	}
	go ls.broadcastLoop()
	return ls
}

// broadcastLoop рассылает логи всем подключенным клиентам
func (ls *LogServer) broadcastLoop() {
	for {
		select {
		case msg := <-ls.logChan:
			ls.clientsMu.RLock()
			for client := range ls.clients {
				err := client.WriteMessage(websocket.TextMessage, []byte(msg))
				if err != nil {
					client.Close()
					ls.clientsMu.RUnlock()
					ls.clientsMu.Lock()
					delete(ls.clients, client)
					ls.clientsMu.Unlock()
					ls.clientsMu.RLock()
				}
			}
			ls.clientsMu.RUnlock()
		case <-ls.done:
			return
		}
	}
}

// ServeWS обрабатывает WebSocket подключения для логов
func (ls *LogServer) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("log ws upgrade error: %v", err)
		return
	}
	defer conn.Close()

	ls.clientsMu.Lock()
	ls.clients[conn] = true
	ls.clientsMu.Unlock()

	log.Printf("log client connected: %s", conn.RemoteAddr())

	// Отправляем историю последних 100 логов
	// Это можно реализовать если сохранять логи в буфер

	// Ждем пока клиент не отключится
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}

	ls.clientsMu.Lock()
	delete(ls.clients, conn)
	ls.clientsMu.Unlock()
	log.Printf("log client disconnected: %s", conn.RemoteAddr())
}

// Close закрывает сервер логов
func (ls *LogServer) Close() {
	close(ls.done)
	ls.clientsMu.Lock()
	for client := range ls.clients {
		client.Close()
	}
	ls.clientsMu.Unlock()
}
