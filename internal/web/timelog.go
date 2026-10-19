package web

// TimeLogServer — раздача логов вкладки «Временная метка» по WebSocket.
//
// В отличие от LogServer (один общий кольцевой буфер на все события), хранит
// отдельные кольцевые буферы на каждое устройство: вкладка показывает логи
// только выбранного устройства, а heartbeat (0x66/0x67) может идти часто.
// Клиент подключается с ?device=<id>, получает историю этого устройства и
// затем — только его новые записи. Смена устройства в интерфейсе — это
// переподключение WebSocket.

import (
	"container/ring"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"

	"tnc-server/internal/models"
)

// maxTimeLogsPerDevice — глубина истории на устройство (только память).
const maxTimeLogsPerDevice = 500

// TimeLogServer обслуживает WebSocket-клиентов вкладки «Временная метка».
type TimeLogServer struct {
	in <-chan models.TimeLogEntry

	mu      sync.RWMutex // защищает clients и rings
	clients map[*websocket.Conn]string
	rings   map[string]*ring.Ring
}

// NewTimeLogServer создаёт сервер; in — канал записей от TCP-обработчика.
func NewTimeLogServer(in <-chan models.TimeLogEntry) *TimeLogServer {
	s := &TimeLogServer{
		in:      in,
		clients: make(map[*websocket.Conn]string),
		rings:   make(map[string]*ring.Ring),
	}
	go s.broadcastLoop()
	return s
}

// broadcastLoop разбирает записи по устройствам и рассылает подписчикам.
// Выходит по закрытию входного канала (при остановке сервера).
func (s *TimeLogServer) broadcastLoop() {
	for e := range s.in {
		s.mu.Lock()
		r := s.rings[e.DeviceID]
		if r == nil {
			r = ring.New(maxTimeLogsPerDevice)
			s.rings[e.DeviceID] = r
		}
		r.Value = e
		s.rings[e.DeviceID] = r.Next()

		conns := make([]*websocket.Conn, 0, 4)
		for conn, device := range s.clients {
			if device == e.DeviceID {
				conns = append(conns, conn)
			}
		}
		s.mu.Unlock()

		for _, conn := range conns {
			if err := conn.WriteJSON(e); err != nil {
				conn.Close()
				s.mu.Lock()
				delete(s.clients, conn)
				s.mu.Unlock()
			}
		}
	}
}

// history возвращает историю устройства от старых записей к новым.
func (s *TimeLogServer) history(deviceID string) []models.TimeLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.rings[deviceID]
	if r == nil {
		return nil
	}
	out := make([]models.TimeLogEntry, 0, maxTimeLogsPerDevice)
	r.Do(func(v any) {
		if v != nil {
			out = append(out, v.(models.TimeLogEntry))
		}
	})
	return out
}

// ServeWS обслуживает WebSocket-соединение вкладки «Временная метка» для одного
// устройства: сначала история, затем поток новых записей.
func (s *TimeLogServer) ServeWS(w http.ResponseWriter, r *http.Request, deviceID string) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("time ws: upgrade error: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("time ws: client connected: %s (device=%q)", conn.RemoteAddr(), deviceID)

	// Сначала история, затем регистрация в clients — иначе broadcastLoop
	// может писать в соединение одновременно с этим циклом (gorilla/websocket
	// допускает только одного писателя).
	for _, e := range s.history(deviceID) {
		if err := conn.WriteJSON(e); err != nil {
			log.Printf("time ws: history send error: %v", err)
			return
		}
	}

	s.mu.Lock()
	s.clients[conn] = deviceID
	s.mu.Unlock()

	// Держим соединение, пока клиент не отключится.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}

	s.mu.Lock()
	delete(s.clients, conn)
	s.mu.Unlock()
	log.Printf("time ws: client disconnected: %s", conn.RemoteAddr())
}
