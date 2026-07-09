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
)

func (r Role) Valid() bool {
	return r == RoleUser || r == RolePrivileged
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
