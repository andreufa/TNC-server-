package web

import (
	"container/ring"
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

	logChan <-chan string
	done    chan struct{}

	// Буфер истории логов (кольцевой список)
	history *ring.Ring
	histMu  sync.Mutex
	maxLogs int
}

const defaultMaxLogs = 100

// NewLogServer создает новый сервер логов
func NewLogServer(logChan <-chan string) *LogServer {
	ls := &LogServer{
		clients: make(map[*websocket.Conn]bool),
		logChan: logChan,
		done:    make(chan struct{}),
		history: ring.New(defaultMaxLogs), // создаём кольцо на 100 элементов
		maxLogs: defaultMaxLogs,
	}

	// Инициализируем кольцо пустыми значениями
	for i := 0; i < defaultMaxLogs; i++ {
		ls.history.Value = ""
		ls.history = ls.history.Next()
	}

	go ls.broadcastLoop()
	return ls
}

// addToHistory добавляет сообщение в кольцевой буфер
func (ls *LogServer) addToHistory(msg string) {
	ls.histMu.Lock()
	defer ls.histMu.Unlock()

	ls.history.Value = msg
	ls.history = ls.history.Next() // сдвигаем указатель вперёд
}

// getHistory возвращает срез последних логов (в правильном порядке)
func (ls *LogServer) getHistory() []string {
	ls.histMu.Lock()
	defer ls.histMu.Unlock()

	result := make([]string, 0, ls.maxLogs)
	r := ls.history
	// Находим первый непустой элемент (если буфер ещё не заполнен)
	// Простой способ: собираем всё, потом убираем пустые строки с начала
	for i := 0; i < ls.maxLogs; i++ {
		v := r.Value.(string)
		if v != "" {
			result = append(result, v)
		}
		r = r.Next()
	}
	return result
}

// broadcastLoop рассылает логи всем подключенным клиентам
func (ls *LogServer) broadcastLoop() {
	for {
		select {
		case msg := <-ls.logChan:
			// Сначала сохраняем в историю
			ls.addToHistory(msg)

			// Потом рассылаем всем подключённым
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

	// Отправляем историю последних логов новому клиенту
	history := ls.getHistory()
	for _, msg := range history {
		err := conn.WriteMessage(websocket.TextMessage, []byte(msg))
		if err != nil {
			log.Printf("log ws history send error: %v", err)
			conn.Close()
			return
		}
	}

	// Ждём, пока клиент не отключится (пинг/понг можно добавить позже)
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
