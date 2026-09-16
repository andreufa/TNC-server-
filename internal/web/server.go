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

//go:embed static/*
var staticFS embed.FS

// Server is the HTTP frontend (web form).
type Server struct {
	devices      *store.DeviceStore
	users        *store.UserStore
	sessions     *store.SessionStore
	measurements *store.MeasurementStore
	tmpl         *template.Template
	logServer    *LogServer // добавляем
}

// NewServer builds the web server and parses templates.
func NewServer(devices *store.DeviceStore, users *store.UserStore, sessions *store.SessionStore, logChan <-chan string, measurements *store.MeasurementStore) (*Server, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	logServer := NewLogServer(logChan)

	return &Server{
		devices:      devices,
		users:        users,
		sessions:     sessions,
		measurements: measurements,
		tmpl:         tmpl,
		logServer:    logServer,
	}, nil
}

// Handler returns the root http.Handler with all routes wired up.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// --- Auth routes (доступны всем, без дополнительных проверок) ---
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// --- Статические ресурсы (логотип / favicon) ---
	mux.Handle("GET /static/", cacheStatic(http.FileServer(http.FS(staticFS))))

	// --- Обычные пользователи (просмотр) ---
	// Доступ есть у любого авторизованного пользователя
	mux.HandleFunc("GET /", requireAuth(s.handleDeviceList))    // список устройств
	mux.HandleFunc("GET /logs", requireAuth(s.handleLogsPage))  // список логов
	mux.HandleFunc("GET /logs/ws", requireAuth(s.handleLogsWS)) // WebSocket логов

	// Графики измерений 0x59 (доступны всем авторизованным)
	mux.HandleFunc("GET /charts", requireAuth(s.handleChartsPage))                // страница графиков
	mux.HandleFunc("GET /api/measurements", requireAuth(s.handleMeasurementsAPI)) // данные для графиков

	// --- Привилегированные (и админ тоже) ---
	// Используем requireRoleOrAdmin: доступ, если role == privileged ИЛИ IsAdmin() == true
	mux.HandleFunc("POST /devices/add", requireRoleOrAdmin(models.RolePrivileged, s.handleDeviceAdd))
	mux.HandleFunc("POST /devices/{id}/delete", requireRoleOrAdmin(models.RolePrivileged, s.handleDeviceDelete))
	mux.HandleFunc("POST /devices/{id}/service", requireRoleOrAdmin(models.RolePrivileged, s.handleDeviceService))
	mux.HandleFunc("POST /devices/{id}/publickey", requireRoleOrAdmin(models.RolePrivileged, s.handleDevicePublicKey))
	mux.HandleFunc("POST /devices/{id}/rename", requireRoleOrAdmin(models.RolePrivileged, s.handleDeviceRename))

	// --- Удалённые устройства: восстановление / окончательное удаление ---
	mux.HandleFunc("GET /devices/deleted", requireRoleOrAdmin(models.RolePrivileged, s.handleDeletedList))
	mux.HandleFunc("POST /devices/{id}/restore", requireRoleOrAdmin(models.RolePrivileged, s.handleDeviceRestore))
	mux.HandleFunc("POST /devices/{id}/purge", requireRoleOrAdmin(models.RolePrivileged, s.handleDevicePurge))

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

// cacheStatic adds a long browser-cache header for embedded static assets.
// embed.FS carries no modification times, so http.FileServer emits no
// Last-Modified/ETag; without this header browsers would re-download the
// asset on every page load.
func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		next.ServeHTTP(w, r)
	})
}
