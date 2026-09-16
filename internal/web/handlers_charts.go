package web

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"
)

const (
	chartsMaxPoints    = 1000 // максимум точек на ответ (прореживание на сервере)
	chartsMaxHours     = 7 * 24
	chartsDefaultHours = 6
)

// handleChartsPage отображает страницу графиков измерений 0x59.
func (s *Server) handleChartsPage(w http.ResponseWriter, r *http.Request) {
	devices, err := s.devices.List(r.Context(), false)
	if err != nil {
		log.Printf("charts: list devices: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "charts.html", map[string]any{
		"Devices":  devices,
		"Selected": r.URL.Query().Get("device"),
	})
}

// handleMeasurementsAPI отдаёт точки измерений устройства за последние N часов.
// GET /api/measurements?device=<id>&hours=<n>
func (s *Server) handleMeasurementsAPI(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("device")
	if deviceID == "" {
		http.Error(w, "device is required", http.StatusBadRequest)
		return
	}
	hours := float64(chartsDefaultHours)
	if v := r.URL.Query().Get("hours"); v != "" {
		h, err := strconv.ParseFloat(v, 64)
		if err != nil || h <= 0 || h > chartsMaxHours {
			http.Error(w, "invalid hours", http.StatusBadRequest)
			return
		}
		hours = h
	}

	to := time.Now().Add(time.Minute) // запас на буфер асинхронной вставки
	from := to.Add(-time.Duration(hours * float64(time.Hour)))

	points, err := s.measurements.QueryRange(r.Context(), deviceID, from, to, chartsMaxPoints)
	if err != nil {
		log.Printf("charts: query %q: %v", deviceID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(map[string]any{
		"device": deviceID,
		"hours":  hours,
		"points": points,
	})
}
