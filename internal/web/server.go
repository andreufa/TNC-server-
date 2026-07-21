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

	// --- Auth routes (доступны всем, без дополнительных проверок) ---
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// --- Обычные пользователи (просмотр) ---
	// Доступ есть у любого авторизованного пользователя
	mux.HandleFunc("GET /", requireAuth(s.handleDeviceList))    // список устройств
	mux.HandleFunc("GET /logs", requireAuth(s.handleLogsPage))  // список логов
	mux.HandleFunc("GET /logs/ws", requireAuth(s.handleLogsWS)) // WebSocket логов

	// --- Привилегированные (и админ тоже) ---
	// Используем requireRoleOrAdmin: доступ, если role == privileged ИЛИ IsAdmin() == true
	mux.HandleFunc("POST /devices/add", requireRoleOrAdmin(models.RolePrivileged, s.handleDeviceAdd))
	mux.HandleFunc("POST /devices/{id}/delete", requireRoleOrAdmin(models.RolePrivileged, s.handleDeviceDelete))
	mux.HandleFunc("POST /devices/{id}/service", requireRoleOrAdmin(models.RolePrivileged, s.handleDeviceService))
	mux.HandleFunc("POST /devices/{id}/password", requireRoleOrAdmin(models.RolePrivileged, s.handleDevicePassword))
	mux.HandleFunc("POST /devices/{id}/rename", requireRoleOrAdmin(models.RolePrivileged, s.handleDeviceRename))

	// --- Только Админ (всё, что выше + управление пользователями) ---
	// Строгая проверка: только IsAdmin() == true
	mux.HandleFunc("GET /users", requireAdmin(s.handleUserList))
	mux.HandleFunc("POST /users/add", requireAdmin(s.handleUserAdd))
	mux.HandleFunc("POST /users/{id}/delete", requireAdmin(s.handleUserDelete))

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
