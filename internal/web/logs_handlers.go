package web

import (
	"net/http"
)

// handleLogsPage отображает страницу с логами
func (s *Server) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "logs.html", nil)
}

// handleLogsWS обрабатывает WebSocket подключение для логов
func (s *Server) handleLogsWS(w http.ResponseWriter, r *http.Request) {
	s.logServer.ServeWS(w, r)
}
