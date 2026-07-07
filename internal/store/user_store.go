package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"tnc-server/internal/models"
)

// UserStore manages web-user rows in Postgres.
type UserStore struct {
	pool *pgxpool.Pool
}

func NewUserStore(pool *pgxpool.Pool) *UserStore {
	return &UserStore{pool: pool}
}

// List returns all users ordered by username.
func (s *UserStore) List(ctx context.Context) ([]models.User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Create inserts a new user with a bcrypt-hashed password.
func (s *UserStore) Create(ctx context.Context, username, plainPassword string, role models.Role) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)`,
		uuid.New(), username, string(hash), string(role))
	return err
}

// Delete removes a user by id. Cascades to their sessions (ON DELETE CASCADE).
// Returns ErrNotFound if no such user exists.
func (s *UserStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user: %w", ErrNotFound)
	}
	return nil
}

// EnsureBootstrap creates a privileged user if it does not already exist. Used
// once at startup so there is always an account to log in with.
func (s *UserStore) EnsureBootstrap(ctx context.Context, username, plainPassword string) error {
	var exists bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)`, username).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.Create(ctx, username, plainPassword, models.RolePrivileged)
}

// VerifyUser checks username+password and returns the user on success.
// Returns ErrNotFound when credentials are invalid.
func (s *UserStore) VerifyUser(ctx context.Context, username, plainPassword string) (*models.User, error) {
	var (
		u    models.User
		hash string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role, created_at FROM users WHERE username = $1`, username).
		Scan(&u.ID, &u.Username, &hash, &u.Role, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainPassword)); err != nil {
		return nil, ErrNotFound
	}
	return &u, nil
}
