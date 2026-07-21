package web

import (
	"errors"
	"log"
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
	publicKey := r.FormValue("public_key")
	inService := r.FormValue("in_service") == "on"

	if id == "" || publicKey == "" {
		http.Redirect(w, r, "/?flash=ID+и+публичный+ключ+обязательны", http.StatusSeeOther)
		return
	}

	// Получаем текущего пользователя из контекста
	user := userFrom(r.Context())
	// Логгируем проблемы с админом
	if user == nil {
		log.Println("⚠️ handleDeviceAdd: no user in context")
	} else {
		log.Printf("✅ handleDeviceAdd: user=%s, role=%s, IsAdmin=%v", user.Username, user.Role, user.Role.IsAdmin())
	}
	//
	if user == nil {
		http.Redirect(w, r, "/?flash=Не+авторизован", http.StatusSeeOther)
		return
	}

	if err := s.devices.Add(r.Context(), id, publicKey, inService, user.ID); err != nil {
		http.Redirect(w, r, "/?flash=Не+удалось+добавить+(возможно+ID+занят)", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?flash=Устройство+добавлено", http.StatusSeeOther)
}

func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	user := userFrom(r.Context())
	if user == nil {
		http.Redirect(w, r, "/?flash=Не+авторизован", http.StatusSeeOther)
		return
	}

	if err := s.devices.SoftDelete(r.Context(), id, user.ID); err != nil {
		s.deviceActionResult(w, r, err)
		return
	}
	http.Redirect(w, r, "/?flash=Устройство+удалено", http.StatusSeeOther)
}

func (s *Server) handleDeviceService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	inService := r.FormValue("in_service") == "true"

	user := userFrom(r.Context())
	if user == nil {
		http.Redirect(w, r, "/?flash=Не+авторизован", http.StatusSeeOther)
		return
	}

	if err := s.devices.SetInService(r.Context(), id, inService, user.ID); err != nil {
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

	user := userFrom(r.Context())
	// Логгируем проблемы с админом
	if user == nil {
		log.Println("⚠️ handleDeviceAdd: no user in context")
	} else {
		log.Printf("✅ handleDeviceAdd: user=%s, role=%s, IsAdmin=%v", user.Username, user.Role, user.Role.IsAdmin())
	}
	//
	if user == nil {
		http.Redirect(w, r, "/?flash=Не+авторизован", http.StatusSeeOther)
		return
	}

	if err := s.devices.SetPassword(r.Context(), id, newPass, user.ID); err != nil {
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

	user := userFrom(r.Context())
	if user == nil {
		http.Redirect(w, r, "/?flash=Не+авторизован", http.StatusSeeOther)
		return
	}

	if err := s.devices.Rename(r.Context(), id, newID, user.ID); err != nil {
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
