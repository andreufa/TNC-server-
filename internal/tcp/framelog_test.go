package tcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSanitizeDID(t *testing.T) {
	cases := map[string]string{
		"N-10":   "N-10",
		"../etc": ".._etc",
		"..":     "unknown",
		".":      "unknown",
		"":       "unknown",
		"a/b\\c": "a_b_c",
		"устр_1": "_____1",
	}
	for in, want := range cases {
		if got := SanitizeDID(in); got != want {
			t.Errorf("SanitizeDID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFrameLoggerWrites(t *testing.T) {
	dir := t.TempDir()
	l := NewFrameLogger(dir, 0)
	if err := l.Open("N-10"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	l.LogHex("N-10", []byte{0x24, 0x76, 0x59, 0x2C, 0x00})
	l.LogTxt("N-10", "line one")
	l.Close("N-10")

	day := time.Now().UTC().Format(dayDirLayout)
	hexData, err := os.ReadFile(filepath.Join(dir, day, "N-10.hex"))
	if err != nil {
		t.Fatalf("read hex: %v", err)
	}
	if !strings.Contains(string(hexData), "IN 24 76 59 2C 00") {
		t.Errorf("hex line = %q, want to contain %q", string(hexData), "IN 24 76 59 2C 00")
	}
	txtData, err := os.ReadFile(filepath.Join(dir, day, "N-10.txt"))
	if err != nil {
		t.Fatalf("read txt: %v", err)
	}
	if string(txtData) != "line one\n" {
		t.Errorf("txt = %q, want %q", string(txtData), "line one\n")
	}
}

func TestFrameLoggerDayRollover(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	l := NewFrameLogger(dir, 0)
	l.now = func() time.Time { return now }

	if err := l.Open("N-10"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	l.LogHex("N-10", []byte{0x24})
	now = now.Add(24 * time.Hour) // полночь прошла
	l.LogHex("N-10", []byte{0x25})
	l.Close("N-10")

	if _, err := os.Stat(filepath.Join(dir, "2026-09-16", "N-10.hex")); err != nil {
		t.Errorf("day 2026-09-16 missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-09-17", "N-10.hex")); err != nil {
		t.Errorf("day 2026-09-17 missing: %v", err)
	}
}

func TestFrameLoggerRotation(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	l := NewFrameLogger(dir, 100) // лимит 100 байт
	l.now = func() time.Time { return now }

	if err := l.Open("N-10"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Строка hex-лога ~36 байт: 2 строки (72) + 3-я (108 > 100) → новая часть.
	for i := 0; i < 5; i++ {
		l.LogHex("N-10", []byte{0x24, 0x76, 0x59})
	}
	l.Close("N-10")

	dayDir := filepath.Join(dir, "2026-09-16")
	for _, name := range []string{"N-10.hex", "N-10.2.hex", "N-10.3.hex"} {
		if _, err := os.Stat(filepath.Join(dayDir, name)); err != nil {
			t.Errorf("expected part %s: %v", name, err)
		}
	}
	for name, wantLines := range map[string]int{"N-10.hex": 2, "N-10.2.hex": 2, "N-10.3.hex": 1} {
		data, err := os.ReadFile(filepath.Join(dayDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		got := strings.Count(string(data), "\n")
		if got != wantLines {
			t.Errorf("%s lines = %d, want %d", name, got, wantLines)
		}
	}
}

func TestCleanupOldLogs(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"2026-09-01", "2026-09-10", "2026-09-15", "notes"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
	// Файл с «датой» в имени трогать нельзя.
	if err := os.WriteFile(filepath.Join(root, "2026-09-02.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	n, err := cleanupOldLogsAt(root, 7, now)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n != 1 {
		t.Errorf("removed = %d, want 1", n)
	}
	// Граница: сегодня (16-е) − 6 = 10-е. 10-е хранится, 1-е удалено.
	for _, name := range []string{"2026-09-10", "2026-09-15", "notes"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Errorf("%s должен остаться: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "2026-09-01")); !os.IsNotExist(err) {
		t.Error("2026-09-01 должен быть удалён")
	}
	if _, err := os.Stat(filepath.Join(root, "2026-09-02.txt")); err != nil {
		t.Errorf("файл не должен быть удалён: %v", err)
	}
}
