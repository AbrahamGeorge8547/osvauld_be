// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.24.0

package db

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type AccessList struct {
	ID           uuid.UUID     `json:"id"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	CredentialID uuid.UUID     `json:"credential_id"`
	UserID       uuid.UUID     `json:"user_id"`
	AccessType   string        `json:"access_type"`
	GroupID      uuid.NullUUID `json:"group_id"`
}

type Credential struct {
	ID          uuid.UUID      `json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Name        string         `json:"name"`
	Description sql.NullString `json:"description"`
	FolderID    uuid.UUID      `json:"folder_id"`
	CreatedBy   uuid.UUID      `json:"created_by"`
}

type EncryptedDatum struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	FieldName    string    `json:"field_name"`
	CredentialID uuid.UUID `json:"credential_id"`
	FieldValue   string    `json:"field_value"`
	UserID       uuid.UUID `json:"user_id"`
}

type Folder struct {
	ID          uuid.UUID      `json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Name        string         `json:"name"`
	Description sql.NullString `json:"description"`
	CreatedBy   uuid.UUID      `json:"created_by"`
}

type FolderAccess struct {
	ID         uuid.UUID `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	FolderID   uuid.UUID `json:"folder_id"`
	UserID     uuid.UUID `json:"user_id"`
	AccessType string    `json:"access_type"`
}

type GroupList struct {
	ID         uuid.UUID `json:"id"`
	GroupingID uuid.UUID `json:"grouping_id"`
	UserID     uuid.UUID `json:"user_id"`
	AccessType string    `json:"access_type"`
	CreatedAt  time.Time `json:"created_at"`
}

type Grouping struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Name      string    `json:"name"`
	CreatedBy uuid.UUID `json:"created_by"`
}

type SessionTable struct {
	ID        uuid.UUID      `json:"id"`
	UserID    uuid.UUID      `json:"user_id"`
	PublicKey string         `json:"public_key"`
	Challenge string         `json:"challenge"`
	DeviceID  sql.NullString `json:"device_id"`
	SessionID sql.NullString `json:"session_id"`
	CreatedAt sql.NullTime   `json:"created_at"`
	UpdatedAt sql.NullTime   `json:"updated_at"`
}

type UnencryptedDatum struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	FieldName    string    `json:"field_name"`
	CredentialID uuid.UUID `json:"credential_id"`
	FieldValue   string    `json:"field_value"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Username  string    `json:"username"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	EccPubKey string    `json:"ecc_pub_key"`
}
