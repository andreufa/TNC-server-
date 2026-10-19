package web

import (
	"bytes"
	"html/template"
	"testing"
	"time"

	"github.com/google/uuid"

	"tnc-server/internal/models"
)

// TestTemplatesParseAndRender проверяет, что все шаблоны парсятся без ошибок
// и страница графиков рендерится как со списком устройств, так и без него.
// Шаблоны парсятся только при старте сервера (ParseFS), поэтому синтаксические
// ошибки не ловятся компилятором — этот тест их отлавливает.
func TestTemplatesParseAndRender(t *testing.T) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	user := &models.User{ID: uuid.New(), Username: "admin", Role: models.RoleAdmin}
	devices := []models.Device{{ID: "N-10", RegisteredAt: time.Now(), InService: true}}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "charts.html", map[string]any{
		"User":     user,
		"Devices":  devices,
		"Selected": "N-10",
	}); err != nil {
		t.Fatalf("execute charts.html: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("uplot.iife.min.js")) {
		t.Error("charts.html не подключает uPlot")
	}
	if !bytes.Contains(buf.Bytes(), []byte("N-10")) {
		t.Error("charts.html не выводит список устройств")
	}

	// Без устройств страница тоже должна рендериться.
	buf.Reset()
	if err := tmpl.ExecuteTemplate(&buf, "charts.html", map[string]any{
		"User":     user,
		"Devices":  []models.Device{},
		"Selected": "",
	}); err != nil {
		t.Fatalf("execute charts.html (no devices): %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Нет зарегистрированных устройств")) {
		t.Error("charts.html без устройств должен показывать сообщение")
	}

	// Вкладка «Временная метка» рендерится со списком устройств.
	buf.Reset()
	if err := tmpl.ExecuteTemplate(&buf, "time.html", map[string]any{
		"User":     user,
		"Devices":  devices,
		"Selected": "N-10",
	}); err != nil {
		t.Fatalf("execute time.html: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("/time/ws")) {
		t.Error("time.html не подключает WebSocket вкладки «Временная метка»")
	}
}
