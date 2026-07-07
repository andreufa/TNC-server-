package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"tnc-server/internal/models"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// DeviceStore manages device rows in Postgres.
type DeviceStore struct {
	pool *pgxpool.Pool
}

func NewDeviceStore(pool *pgxpool.Pool) *DeviceStore {
	return &DeviceStore{pool: pool}
}

// List returns devices. When includeDeleted is false, soft-deleted devices are
// omitted. Ordered by id.
func (s *DeviceStore) List(ctx context.Context, includeDeleted bool) ([]models.Device, error) {
	q := `SELECT id, registered_at, deleted_at, in_service FROM devices`
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
		if err := rows.Scan(&d.ID, &d.RegisteredAt, &d.DeletedAt, &d.InService); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Add inserts a new device with a bcrypt-hashed password.
func (s *DeviceStore) Add(ctx context.Context, id, plainPassword string, inService bool) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO devices (id, password_hash, in_service) VALUES ($1, $2, $3)`,
		id, string(hash), inService)
	return err
}

// SoftDelete marks a device as deleted (sets deleted_at) without removing the row.
func (s *DeviceStore) SoftDelete(ctx context.Context, id string) error {
	return s.execAffecting(ctx,
		`UPDATE devices SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
}

// SetInService toggles whether the device is currently in service.
func (s *DeviceStore) SetInService(ctx context.Context, id string, inService bool) error {
	return s.execAffecting(ctx,
		`UPDATE devices SET in_service = $2 WHERE id = $1 AND deleted_at IS NULL`, id, inService)
}

// SetPassword resets a device's password.
func (s *DeviceStore) SetPassword(ctx context.Context, id, newPlain string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPlain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.execAffecting(ctx,
		`UPDATE devices SET password_hash = $2 WHERE id = $1 AND deleted_at IS NULL`, id, string(hash))
}

// Rename changes a device's id.
func (s *DeviceStore) Rename(ctx context.Context, oldID, newID string) error {
	return s.execAffecting(ctx,
		`UPDATE devices SET id = $2 WHERE id = $1 AND deleted_at IS NULL`, oldID, newID)
}

// VerifyDevice reports whether id+plainPassword is valid AND the device is
// active (not deleted) and in service. Used by the TCP handshake.
func (s *DeviceStore) VerifyDevice(ctx context.Context, id, plainPassword string) (bool, error) {
	var hash string
	var inService bool
	err := s.pool.QueryRow(ctx,
		`SELECT password_hash, in_service FROM devices WHERE id = $1 AND deleted_at IS NULL`, id).
		Scan(&hash, &inService)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !inService {
		return false, nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPassword)); err != nil {
		return false, nil
	}
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
