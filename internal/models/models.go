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

func (r Role) IsPrivileged() bool { return r == RolePrivileged || r == RoleAdmin }
func (r Role) IsAdmin() bool      { return r == RoleAdmin }

// Device is a managed device that can connect over TCP.
type Device struct {
	ID           string
	PublicKey    string // RSA public key (PEM) for crypto handshake
	RegisteredAt time.Time
	DeletedAt    *time.Time
	InService    bool
	UpdatedBy    *uuid.UUID
	UpdatedAt    time.Time
	LastSeenAt   *time.Time
	IsOnline     bool // computed: online/offline
}

// Measurement — одно измерение команды 0x59 (для графиков).
type Measurement struct {
	DeviceID   string
	MsgNo      uint32
	Ts         time.Time // время сообщения (UTC из кадра)
	ReceivedAt time.Time // момент приёма сервером
	Off1       float64   // iekf_hw_offset_1, метры
	Off2       float64   // iekf_hw_offset_2, метры
	Off3       float64   // iekf_hw_offset_3, метры
	StaticCnt  uint32    // static_cnt
	Validity   uint32    // битовая маска: бит 0 → off1, бит 1 → off2, бит 2 → off3
}

// User is a web-form account.
type User struct {
	ID        uuid.UUID
	Username  string
	Role      Role
	CreatedAt time.Time
}
