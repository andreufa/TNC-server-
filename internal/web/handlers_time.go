package web

import (
	"log"
	"net/http"
)

// handleTimePage отображает вкладку «Временная метка» (логи синхронизации 0x66/0x67).
func (s *Server) handleTimePage(w http.ResponseWriter, r *http.Request) {
	devices, err := s.devices.List(r.Context(), false)
	if err != nil {
		log.Printf("time: list devices: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "time.html", map[string]any{
		"Devices":  devices,
		"Selected": r.URL.Query().Get("device"),
	})
}

// handleTimeWS — WebSocket логов «Время» для выбранного устройства.
func (s *Server) handleTimeWS(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device")
	if deviceID == "" {
		http.Error(w, "device is required", http.StatusBadRequest)
		return
	}
	s.timeLogServer.ServeWS(w, r, deviceID)
}
