package web

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"tnc-server/internal/models"
	"tnc-server/internal/store"
)

func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	users, err := s.users.List(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "users.html", map[string]any{
		"Users": users,
		"Flash": r.URL.Query().Get("flash"),
	})
}

func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	role := models.Role(r.FormValue("role"))

	if username == "" || password == "" {
		http.Redirect(w, r, "/users?flash=Имя+и+пароль+обязательны", http.StatusSeeOther)
		return
	}
	if !role.Valid() {
		http.Redirect(w, r, "/users?flash=Некорректная+роль", http.StatusSeeOther)
		return
	}
	if err := s.users.Create(r.Context(), username, password, role); err != nil {
		http.Redirect(w, r, "/users?flash=Не+удалось+создать+(возможно+имя+занято)", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/users?flash=Пользователь+создан", http.StatusSeeOther)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Redirect(w, r, "/users?flash=Некорректный+ID", http.StatusSeeOther)
		return
	}

	// Prevent an admin from deleting their own account (would lock them out).
	if u := userFrom(r.Context()); u != nil && u.ID == id {
		http.Redirect(w, r, "/users?flash=Нельзя+удалить+себя", http.StatusSeeOther)
		return
	}

	if err := s.users.Delete(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Redirect(w, r, "/users?flash=Пользователь+не+найден", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/users?flash=Ошибка+удаления", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/users?flash=Пользователь+удалён", http.StatusSeeOther)
}
