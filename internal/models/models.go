package models

import (
	"time"

	"github.com/google/uuid"
)

// Role identifies the permission level of a web user.
type Role string

const (
	RoleUser       Role = "user"       // read-only: view devices and their status
	RolePrivileged Role = "privileged" // full device management + user creation
	RoleAdmin      Role = "admin"      // full access + user management
)

func (r Role) Valid() bool {
	switch r {
	case RoleUser, RolePrivileged, RoleAdmin:
		return true
	default:
		return false
	}
}

// IsPrivileged checks if the user has privileged access
func (r Role) IsPrivileged() bool {
	return r == RolePrivileged || r == RoleAdmin
}

// IsAdmin checks if the user is an administrator
func (r Role) IsAdmin() bool {
	return r == RoleAdmin
}

// Device is a managed device that can connect over TCP.
type Device struct {
	ID           string
	RegisteredAt time.Time
	DeletedAt    *time.Time
	InService    bool
	UpdatedBy    *uuid.UUID
	UpdatedAt    time.Time
}

// User is a web-form account.
type User struct {
	ID        uuid.UUID
	Username  string
	Role      Role
	CreatedAt time.Time
}
