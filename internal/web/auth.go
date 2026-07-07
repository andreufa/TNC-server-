package web

import (
	"context"
	"errors"
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

// requireRole enforces that the authenticated user has the given role.
func requireRole(role models.Role, next http.HandlerFunc) http.HandlerFunc {
	return requireAuth(func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r.Context())
		if u.Role != role {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
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
