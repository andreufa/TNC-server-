// Файловые логи устройств. Правила — docs/logging.md.
//
// Раскладка: <LOG_DIR>/YYYY-MM-DD/<DID>.txt (декодированные 0x59)
// и <LOG_DIR>/YYYY-MM-DD/<DID>.hex (сырые входящие фреймы).
package tcp

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// dayDirLayout — имя папки дня (UTC), строго YYYY-MM-DD.
const dayDirLayout = "2006-01-02"

// DefaultLogFileMaxBytes — дефолтный лимит размера одного файла: 100 МБ
// (docs/logging.md §4).
const DefaultLogFileMaxBytes = 100 << 20

// FrameLogger — общий логгер файловых логов всех устройств. Один экземпляр
// на сервер. Сессия устройства открывается Open() при авторизации и
// закрывается Close() при разрыве соединения; параллельные соединения одного
// устройства делят файлы (ref-счётчик). Вся запись сериализуется одним
// мьютексом — строки разных соединений не перемешиваются.
type FrameLogger struct {
	dir      string
	maxBytes int64
	now      func() time.Time // источник времени (заменяется в тестах)

	mu       sync.Mutex
	sessions map[string]*logSession // ключ: санитизированный DID
}

// logSession — файлы одного устройства в текущем дне.
type logSession struct {
	refs int
	did  string // санитизированный DID
	day  string // YYYY-MM-DD открытой папки
	hex  *logFile
	txt  *logFile
}

// logFile — один открытый файл лога.
type logFile struct {
	did  string
	ext  string
	f    *os.File
	w    *bufio.Writer
	size int64 // байт, записанных в текущий файл (включая существовавший размер)
	path string // полный путь текущего файла
	seq  int    // номер части в текущем дне (1 — базовое имя <DID><ext>)
}

// NewFrameLogger создаёт логгер файловых логов. maxBytes — лимит одного файла
// в байтах (<=0 → DefaultLogFileMaxBytes).
func NewFrameLogger(dir string, maxBytes int64) *FrameLogger {
	if maxBytes <= 0 {
		maxBytes = DefaultLogFileMaxBytes
	}
	return &FrameLogger{
		dir:      dir,
		maxBytes: maxBytes,
		now:      time.Now,
		sessions: make(map[string]*logSession),
	}
}

// SanitizeDID очищает Device ID для использования в имени файла
// (docs/logging.md §2): допустимы A–Z a–z 0–9 . _ -; прочие символы
// заменяются на "_"; пустая строка, "." и ".." → "unknown".
func SanitizeDID(did string) string {
	var b strings.Builder
	b.Grow(len(did))
	for _, r := range did {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" || s == "." || s == ".." {
		return "unknown"
	}
	return s
}

// Open активирует сессию устройства: открывает (создаёт при необходимости)
// файлы текущего дня в режиме дозаписи. Повторный Open того же DID до
// Close не закрывает файлы.
func (l *FrameLogger) Open(did string) error {
	key := SanitizeDID(did)
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.sessions[key]; ok {
		s.refs++
		return nil
	}
	s := &logSession{refs: 1, did: key}
	if err := s.open(l.dir, l.now().UTC(), l.maxBytes); err != nil {
		return err
	}
	l.sessions[key] = s
	return nil
}

// Close завершает сессию устройства; файлы закрываются, когда закрыты все
// параллельные соединения этого устройства.
func (l *FrameLogger) Close(did string) {
	key := SanitizeDID(did)
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sessions[key]
	if !ok {
		return
	}
	s.refs--
	if s.refs > 0 {
		return
	}
	s.close()
	delete(l.sessions, key)
}

// CloseAll закрывает файлы всех активных сессий (остановка сервера).
func (l *FrameLogger) CloseAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, s := range l.sessions {
		s.close()
		delete(l.sessions, k)
	}
}

// LogHex пишет одну строку в <DID>.hex: время приёма (UTC) + " IN " + байты
// фрейма в hex (верхний регистр) через пробел. Сессия не открыта — no-op.
func (l *FrameLogger) LogHex(did string, raw []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sessions[SanitizeDID(did)]
	if !ok {
		return
	}
	l.rolloverDay(s)
	var b strings.Builder
	b.Grow(24 + len(raw)*3)
	b.WriteString(l.now().UTC().Format("2006-01-02 15:04:05.000"))
	b.WriteString(" IN ")
	const hexDigits = "0123456789ABCDEF"
	for _, c := range raw {
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0F])
		b.WriteByte(' ')
	}
	b.WriteByte('\n')
	l.writeLine(s.hex, b.String())
}

// LogTxt дописывает готовую строку в <DID>.txt (перевод строки добавляется).
// Форматирует строку вызывающий (декодер 0x59). Сессия не открыта — no-op.
func (l *FrameLogger) LogTxt(did, line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sessions[SanitizeDID(did)]
	if !ok {
		return
	}
	l.rolloverDay(s)
	l.writeLine(s.txt, line+"\n")
}

// rolloverDay переключает сессию на папку нового дня при смене суток (UTC).
func (l *FrameLogger) rolloverDay(s *logSession) {
	if s.day == l.now().UTC().Format(dayDirLayout) {
		return
	}
	s.close()
	if err := s.open(l.dir, l.now().UTC(), l.maxBytes); err != nil {
		log.Printf("frame log: open day: %v", err)
	}
}

// writeLine пишет строку в файл; при превышении лимита сначала открывает
// следующую часть (граница строки — фрейм не разрывается).
func (l *FrameLogger) writeLine(f *logFile, line string) {
	if f == nil || f.w == nil {
		return
	}
	if l.maxBytes > 0 && f.size+int64(len(line)) > l.maxBytes {
		if err := l.rotate(f); err != nil {
			log.Printf("frame log: rotate %s: %v", f.path, err)
		}
	}
	if f.w == nil {
		return
	}
	if _, err := f.w.WriteString(line); err == nil {
		f.size += int64(len(line))
		f.w.Flush()
	}
}

// rotate закрывает текущий файл и открывает следующую часть в той же папке
// дня: <DID><ext> → <DID>.2<ext> → … Текущий файл не переименовывается
// (docs/logging.md §4). При неудаче возвращает файл в рабочее состояние.
func (l *FrameLogger) rotate(f *logFile) error {
	dir := filepath.Dir(f.path)
	did, ext, seq := f.did, f.ext, f.seq
	f.close()
	nf, err := openLogPart(dir, did, ext, seq+1, l.maxBytes)
	if err != nil {
		if rf, rerr := openLogPart(dir, did, ext, seq, l.maxBytes); rerr == nil {
			*f = *rf
		}
		return fmt.Errorf("open next part: %w", err)
	}
	*f = *nf
	return nil
}

// open открывает файлы .hex и .txt папки дня now в режиме дозаписи.
func (s *logSession) open(root string, now time.Time, maxBytes int64) error {
	day := now.Format(dayDirLayout)
	dir := filepath.Join(root, day)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("frame log: mkdir %s: %w", dir, err)
	}
	hex, err := openLogPart(dir, s.did, ".hex", 1, maxBytes)
	if err != nil {
		return err
	}
	txt, err := openLogPart(dir, s.did, ".txt", 1, maxBytes)
	if err != nil {
		hex.close()
		return err
	}
	s.day = day
	s.hex = hex
	s.txt = txt
	return nil
}

// openLogPart открывает часть seq (1 → <DID><ext>); если кандидат существует
// и уже полон (>= maxBytes), перебирает следующие номера.
func openLogPart(dir, did, ext string, seq int, maxBytes int64) (*logFile, error) {
	for {
		name := did + ext
		if seq > 1 {
			name = fmt.Sprintf("%s.%d%s", did, seq, ext)
		}
		path := filepath.Join(dir, name)
		st, err := os.Stat(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("frame log: stat %s: %w", path, err)
		}
		if st != nil && st.Size() >= maxBytes {
			seq++
			continue
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("frame log: open %s: %w", path, err)
		}
		size := int64(0)
		if st != nil {
			size = st.Size()
		}
		return &logFile{
			did: did, ext: ext,
			f: f, w: bufio.NewWriterSize(f, 64*1024),
			size: size, path: path, seq: seq,
		}, nil
	}
}

// close сбрасывает буфер и закрывает файл.
func (f *logFile) close() {
	if f.w != nil {
		f.w.Flush()
	}
	if f.f != nil {
		f.f.Close()
	}
	f.f, f.w = nil, nil
}

// close закрывает оба файла сессии.
func (s *logSession) close() {
	if s.hex != nil {
		s.hex.close()
	}
	if s.txt != nil {
		s.txt.close()
	}
	s.hex, s.txt = nil, nil
	s.day = ""
}
