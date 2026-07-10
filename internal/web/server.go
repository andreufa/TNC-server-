package web

import (
	"embed"
	"html/template"
	"log"
	"net/http"

	"tnc-server/internal/models"
	"tnc-server/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Server is the HTTP frontend (web form).
type Server struct {
	devices   *store.DeviceStore
	users     *store.UserStore
	sessions  *store.SessionStore
	tmpl      *template.Template
	logServer *LogServer // добавляем
}

// NewServer builds the web server and parses templates.
func NewServer(devices *store.DeviceStore, users *store.UserStore, sessions *store.SessionStore, logChan <-chan string) (*Server, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	logServer := NewLogServer(logChan)

	return &Server{
		devices:   devices,
		users:     users,
		sessions:  sessions,
		tmpl:      tmpl,
		logServer: logServer,
	}, nil
}

// Handler returns the root http.Handler with all routes wired up.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Auth
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// Devices — viewing is allowed for any authenticated user.
	mux.HandleFunc("GET /", requireAuth(s.handleDeviceList))

	// Devices — mutations require the privileged role.
	mux.HandleFunc("POST /devices/add", requireRole(models.RolePrivileged, s.handleDeviceAdd))
	mux.HandleFunc("POST /devices/{id}/delete", requireRole(models.RolePrivileged, s.handleDeviceDelete))
	mux.HandleFunc("POST /devices/{id}/service", requireRole(models.RolePrivileged, s.handleDeviceService))
	mux.HandleFunc("POST /devices/{id}/password", requireRole(models.RolePrivileged, s.handleDevicePassword))
	mux.HandleFunc("POST /devices/{id}/rename", requireRole(models.RolePrivileged, s.handleDeviceRename))

	// Users — privileged only.
	mux.HandleFunc("GET /users", requireRole(models.RolePrivileged, s.handleUserList))
	mux.HandleFunc("POST /users/add", requireRole(models.RolePrivileged, s.handleUserAdd))
	mux.HandleFunc("POST /users/{id}/delete", requireRole(models.RolePrivileged, s.handleUserDelete))

	// Logs — viewing is allowed for any authenticated user.
	mux.HandleFunc("GET /logs", requireAuth(s.handleLogsPage))
	mux.HandleFunc("GET /logs/ws", requireAuth(s.handleLogsWS))

	return s.withUser(mux)
}

// render executes a named template, injecting the current user.
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["User"] = userFrom(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("web: template %s error: %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
