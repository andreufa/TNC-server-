package web

import (
	"errors"
	"net/http"

	"tnc-server/internal/store"
)

func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	devices, err := s.devices.List(r.Context(), false)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "devices.html", map[string]any{
		"Devices": devices,
		"Flash":   r.URL.Query().Get("flash"),
	})
}

func (s *Server) handleDeviceAdd(w http.ResponseWriter, r *http.Request) {
	id := r.FormValue("id")
	password := r.FormValue("password")
	inService := r.FormValue("in_service") == "on"

	if id == "" || password == "" {
		http.Redirect(w, r, "/?flash=ID+и+пароль+обязательны", http.StatusSeeOther)
		return
	}
	if err := s.devices.Add(r.Context(), id, password, inService); err != nil {
		http.Redirect(w, r, "/?flash=Не+удалось+добавить+(возможно+ID+занят)", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?flash=Устройство+добавлено", http.StatusSeeOther)
}

func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.devices.SoftDelete(r.Context(), id); err != nil {
		s.deviceActionResult(w, r, err)
		return
	}
	http.Redirect(w, r, "/?flash=Устройство+удалено", http.StatusSeeOther)
}

func (s *Server) handleDeviceService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inService := r.FormValue("in_service") == "true"
	if err := s.devices.SetInService(r.Context(), id, inService); err != nil {
		s.deviceActionResult(w, r, err)
		return
	}
	http.Redirect(w, r, "/?flash=Статус+обновлён", http.StatusSeeOther)
}

func (s *Server) handleDevicePassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	newPass := r.FormValue("password")
	if newPass == "" {
		http.Redirect(w, r, "/?flash=Пароль+не+может+быть+пустым", http.StatusSeeOther)
		return
	}
	if err := s.devices.SetPassword(r.Context(), id, newPass); err != nil {
		s.deviceActionResult(w, r, err)
		return
	}
	http.Redirect(w, r, "/?flash=Пароль+изменён", http.StatusSeeOther)
}

func (s *Server) handleDeviceRename(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	newID := r.FormValue("new_id")
	if newID == "" {
		http.Redirect(w, r, "/?flash=Новый+ID+обязателен", http.StatusSeeOther)
		return
	}
	if err := s.devices.Rename(r.Context(), id, newID); err != nil {
		s.deviceActionResult(w, r, err)
		return
	}
	http.Redirect(w, r, "/?flash=ID+изменён", http.StatusSeeOther)
}

// deviceActionResult maps store errors to a redirect with a flash message.
func (s *Server) deviceActionResult(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/?flash=Устройство+не+найдено", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?flash=Ошибка+операции", http.StatusSeeOther)
}
