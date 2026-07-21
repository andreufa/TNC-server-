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

const OfflineThreshold = 30 * time.Second

var (
	ErrAuthFailed = errors.New("authentication failed")
	ErrNotFound   = errors.New("not found")
)

type DeviceStore struct {
	pool *pgxpool.Pool
}

func NewDeviceStore(pool *pgxpool.Pool) *DeviceStore {
	return &DeviceStore{pool: pool}
}

// ---- Web UI methods ----

func (s *DeviceStore) List(ctx context.Context, includeDeleted bool) ([]models.Device, error) {
	q := `
		SELECT id, public_key, registered_at, deleted_at, in_service,
		       updated_by, updated_at, last_seen_at,
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
		if err := rows.Scan(&d.ID, &d.PublicKey, &d.RegisteredAt, &d.DeletedAt,
			&d.InService, &d.UpdatedBy, &d.UpdatedAt, &d.LastSeenAt, &d.IsOnline); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *DeviceStore) Add(ctx context.Context, id, publicKeyPEM string, inService bool, userID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO devices (id, public_key, in_service, updated_by, updated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, publicKeyPEM, inService, userID, time.Now())
	return err
}

func (s *DeviceStore) SoftDelete(ctx context.Context, id string, userID uuid.UUID) error {
	return s.execAffecting(ctx,
		`UPDATE devices SET deleted_at = now(), updated_by = $2, updated_at = now()
		 WHERE id = $1 AND deleted_at IS NULL`,
		id, userID)
}

func (s *DeviceStore) SetInService(ctx context.Context, id string, inService bool, userID uuid.UUID) error {
	return s.execAffecting(ctx,
		`UPDATE devices SET in_service = $2, updated_by = $3, updated_at = now()
		 WHERE id = $1 AND deleted_at IS NULL`,
		id, inService, userID)
}

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

	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrAuthFailed
	}
	if err != nil {
		return false, err
	}
	if !inService {
		return false, ErrAuthFailed
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPassword)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, ErrAuthFailed
		}
		return false, err
	}
	return true, nil
}

func (s *DeviceStore) GetDeviceStatus(ctx context.Context, deviceID string) (bool, error) {
	var isOnline bool
	var lastSeenAt *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT last_seen_at,
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

func (s *DeviceStore) UpdateLastSeen(ctx context.Context, deviceID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE devices SET last_seen_at = NOW()
		 WHERE id = $1 AND deleted_at IS NULL`,
		deviceID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		log.Printf("[WARN] UpdateLastSeen: device not found or deleted: %s", deviceID)
		return ErrNotFound
	}
	return nil
}

// ---- Crypto handshake methods ----

func (s *DeviceStore) GetPublicKey(ctx context.Context, deviceID string) (string, error) {
	var pk string
	err := s.pool.QueryRow(ctx,
		`SELECT public_key FROM devices
		 WHERE id = $1 AND deleted_at IS NULL AND public_key IS NOT NULL`,
		deviceID,
	).Scan(&pk)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrAuthFailed
	}
	if err != nil {
		return "", err
	}
	return pk, nil
}

func (s *DeviceStore) IsInService(ctx context.Context, deviceID string) (bool, error) {
	var inService bool
	err := s.pool.QueryRow(ctx,
		`SELECT in_service FROM devices
		 WHERE id = $1 AND deleted_at IS NULL`,
		deviceID,
	).Scan(&inService)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrAuthFailed
	}
	if err != nil {
		return false, err
	}
	return inService, nil
}

func (s *DeviceStore) UpsertDevice(ctx context.Context, id, publicKeyPEM string, inService bool) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO devices (id, public_key, in_service)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (id) DO UPDATE SET
		     public_key = EXCLUDED.public_key,
		     in_service = EXCLUDED.in_service,
		     deleted_at = NULL`,
		id, publicKeyPEM, inService,
	)
	return err
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
