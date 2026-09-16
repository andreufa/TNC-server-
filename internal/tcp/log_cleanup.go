// Очистка устаревших файловых логов устройств (docs/logging.md §4).
package tcp

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// CleanupOldLogs удаляет папки дней старше срока хранения из корня файловых
// логов. Хранятся сегодня + (retentionDays−1) прошлых дней (UTC); всё, что
// старше, удаляется целиком (RemoveAll).
//
// Трогаются ТОЛЬКО подпапки с именем, парсящимся строго как YYYY-MM-DD;
// файлы и папки с другими именами игнорируются. Возвращает количество
// удалённых папок.
func CleanupOldLogs(root string, retentionDays int) (int, error) {
	return cleanupOldLogsAt(root, retentionDays, time.Now())
}

func cleanupOldLogsAt(root string, retentionDays int, now time.Time) (int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil // каталога логов ещё нет — нечего чистить
		}
		return 0, fmt.Errorf("read %s: %w", root, err)
	}
	if retentionDays < 1 {
		retentionDays = 1
	}

	// Граница хранения: полночь сегодняшнего дня (UTC) минус N−1 дней.
	cutoff := now.UTC().Truncate(24 * time.Hour).AddDate(0, 0, -(retentionDays - 1))

	removed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		d, err := time.Parse(dayDirLayout, e.Name())
		if err != nil {
			continue // не папка дня — не трогаем
		}
		if !d.Before(cutoff) {
			continue
		}
		p := filepath.Join(root, e.Name())
		if err := os.RemoveAll(p); err != nil {
			log.Printf("log cleanup: remove %s: %v", p, err)
			continue
		}
		removed++
	}
	return removed, nil
}
