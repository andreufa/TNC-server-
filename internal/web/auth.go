package web

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"tnc-server/internal/models"
	"tnc-server/internal/store"
)

const sessionCookie = "tnc_session"

type ctxKey int

const userCtxKey ctxKey = 0

// userFrom returns the authenticated user from the request context, if any.
func userFrom(ctx context.Context) *models.User {
	u, _ := ctx.Value(userCtxKey).(*models.User)
	return u
}

// withUser resolves the session cookie and stores the user in the context.
// It never rejects the request; authorization is enforced by requireAuth /
// requireRole wrappers.
func (s *Server) withUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err == nil {
			if u, err := s.sessions.Get(r.Context(), c.Value); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), userCtxKey, u))
			}
		}
		next.ServeHTTP(w, r)
	})
}
func requireRoleOrAdmin(allowedRole models.Role, next http.HandlerFunc) http.HandlerFunc {
	return requireAuth(func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r.Context())
		if u == nil {
			// Если не залогинен — на логин
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// ГЛАВНОЕ ПРАВИЛО: доступ есть, если роль совпадает ИЛИ если это админ
		isAllowed := u.Role == allowedRole || u.Role.IsAdmin()

		log.Printf("🔐 requireRoleOrAdmin: user=%s, role=%s, isAdmin=%v, allowed=%v",
			u.Username, u.Role, u.Role.IsAdmin(), isAllowed)

		if !isAllowed {
			log.Printf("❌ requireRoleOrAdmin: access denied for user '%s'", u.Username)
			http.Redirect(w, r, "/?flash=Недостаточно+прав", http.StatusSeeOther)
			return
		}

		next(w, r)
	})
}

// requireAuth redirects to /login if there is no authenticated user.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r.Context()) == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requireAdmin проверяет, что пользователь авторизован и имеет роль admin
func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return requireAuth(func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r.Context())
		if u == nil {
			log.Println("❌ requireAdmin: user is nil")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// ОТЛАДКА: выводим информацию о пользователе
		log.Printf("🔍 requireAdmin: user=%s, role='%s', isAdmin=%v",
			u.Username, u.Role, u.Role.IsAdmin())

		if !u.Role.IsAdmin() {
			log.Printf("❌ requireAdmin: access denied for user '%s' with role '%s'", u.Username, u.Role)
			http.Redirect(w, r, "/?flash=Доступ+запрещён", http.StatusSeeOther)
			return
		}

		log.Printf("✅ requireAdmin: access granted for user '%s'", u.Username)
		next(w, r)
	})
}

// --- login / logout handlers ---

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if userFrom(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login.html", map[string]any{"Error": ""})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	u, err := s.users.VerifyUser(r.Context(), username, password)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusUnauthorized)
			s.render(w, r, "login.html", map[string]any{"Error": "Неверные учётные данные"})
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	token, err := s.sessions.Create(r.Context(), u.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(store.SessionTTL),
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
