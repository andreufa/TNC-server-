package store

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"tnc-server/internal/models"
)

// Константа для определения времени офлайн
const OfflineThreshold = 30 * time.Second

// ErrAuthFailed — единая ошибка для всех случаев неудачной верификации.
// Клиент не должен знать, что именно пошло не так (нет устройства, не в сервисе, неверный пароль).
var ErrAuthFailed = errors.New("authentication failed")

var ErrNotFound = errors.New("not found")

type DeviceStore struct {
	pool *pgxpool.Pool
}

func NewDeviceStore(pool *pgxpool.Pool) *DeviceStore {
	return &DeviceStore{pool: pool}
}

// List returns devices. When includeDeleted is false, soft-deleted devices are
// omitted. Ordered by id.
func (s *DeviceStore) List(ctx context.Context, includeDeleted bool) ([]models.Device, error) {
	q := `
		SELECT
			id,
			registered_at,
			deleted_at,
			in_service,
			updated_by,
			updated_at,
			last_seen_at,
			(last_seen_at IS NOT NULL AND last_seen_at > NOW() - INTERVAL '` + OfflineThreshold.String() + `') AS is_online
		FROM devices
	`
	if !includeDeleted {
		q += ` WHERE deleted_at IS NULL`
	}
	q += ` ORDER BY id`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Device
	for rows.Next() {
		var d models.Device
		// Важно: порядок полей должен точно совпадать с SELECT
		if err := rows.Scan(
			&d.ID,
			&d.RegisteredAt,
			&d.DeletedAt,
			&d.InService,
			&d.UpdatedBy,
			&d.UpdatedAt,
			&d.LastSeenAt,
			&d.IsOnline, // <-- читаем вычисленное поле
		); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Add inserts a new device with a bcrypt-hashed password.
func (s *DeviceStore) Add(ctx context.Context, id, plainPassword string, inService bool, userID uuid.UUID) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO devices (id, password_hash, in_service, updated_by, updated_at) 
		 VALUES ($1, $2, $3, $4, $5)`,
		id, string(hash), inService, userID, time.Now())
	return err
}

// SoftDelete marks a device as deleted (sets deleted_at) without removing the row.
func (s *DeviceStore) SoftDelete(ctx context.Context, id string, userID uuid.UUID) error {
	return s.execAffecting(ctx,
		`UPDATE devices SET deleted_at = now(), updated_by = $2, updated_at = now() 
		 WHERE id = $1 AND deleted_at IS NULL`,
		id, userID)
}

// SetInService toggles whether the device is currently in service.
func (s *DeviceStore) SetInService(ctx context.Context, id string, inService bool, userID uuid.UUID) error {
	return s.execAffecting(ctx,
		`UPDATE devices SET in_service = $2, updated_by = $3, updated_at = now() 
		 WHERE id = $1 AND deleted_at IS NULL`,
		id, inService, userID)
}

// SetPassword resets a device's password.
func (s *DeviceStore) SetPassword(ctx context.Context, id, newPlain string, userID uuid.UUID) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPlain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.execAffecting(ctx,
		`UPDATE devices SET password_hash = $2, updated_by = $3, updated_at = now() 
		 WHERE id = $1 AND deleted_at IS NULL`,
		id, string(hash), userID)
}

// Rename changes a device's id.
func (s *DeviceStore) Rename(ctx context.Context, oldID, newID string, userID uuid.UUID) error {
	return s.execAffecting(ctx,
		`UPDATE devices SET id = $2, updated_by = $3, updated_at = now() 
		 WHERE id = $1 AND deleted_at IS NULL`,
		oldID, newID, userID)
}

func (s *DeviceStore) VerifyDevice(ctx context.Context, id, plainPassword string) (bool, error) {
	var hash string
	var inService bool

	err := s.pool.QueryRow(ctx,
		`SELECT password_hash, in_service FROM devices WHERE id = $1 AND deleted_at IS NULL`,
		id,
	).Scan(&hash, &inService)

	// Случай 1: устройства нет или оно удалено
	if errors.Is(err, pgx.ErrNoRows) {
		log.Printf("[DEBUG] VerifyDevice: device not found or deleted: id=%q", id)
		return false, ErrAuthFailed
	}

	// Случай 2: реальная ошибка БД
	if err != nil {
		log.Printf("[ERROR] VerifyDevice: database error: id=%q, err=%v", id, err)
		return false, err
	}

	// Случай 3: устройство есть, но не в сервисе
	if !inService {
		log.Printf("[DEBUG] VerifyDevice: device found but not in service: id=%q", id)
		return false, ErrAuthFailed
	}

	// Случай 4: проверка пароля
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPassword)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Printf("[DEBUG] VerifyDevice: invalid password: id=%q", id)
			return false, ErrAuthFailed
		}
		// Любая другая ошибка bcrypt — это уже не «неверный пароль», а проблема с данными/алгоритмом
		log.Printf("[ERROR] VerifyDevice: password comparison error: id=%q, err=%v", id, err)
		return false, err
	}

	log.Printf("[INFO] VerifyDevice: successful authentication: id=%q", id)
	return true, nil
}

func (s *DeviceStore) execAffecting(ctx context.Context, sql string, args ...any) error {
	tag, err := s.pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("device: %w", ErrNotFound)
	}
	return nil
}

func (s *DeviceStore) UpdateLastSeen(ctx context.Context, deviceID string) error {
	tag, err := s.pool.Exec(ctx, `
        UPDATE devices
        SET last_seen_at = NOW()
        WHERE id = $1 AND deleted_at IS NULL
    `, deviceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		log.Printf("[WARN] UpdateLastSeen: device not found or deleted: %s", deviceID)
		return ErrNotFound
	}
	return nil
}

// Дополнительный метод для получения обновленного статуса
func (s *DeviceStore) GetDeviceStatus(ctx context.Context, deviceID string) (bool, error) {
	var isOnline bool
	var lastSeenAt *time.Time

	err := s.pool.QueryRow(ctx, `
        SELECT 
            last_seen_at,
            (last_seen_at IS NOT NULL AND last_seen_at > NOW() - INTERVAL '`+OfflineThreshold.String()+`') AS is_online
        FROM devices
        WHERE id = $1 AND deleted_at IS NULL
    `, deviceID).Scan(&lastSeenAt, &isOnline)

	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}

	return isOnline, nil
}
