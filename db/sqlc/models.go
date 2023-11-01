// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.23.0

package db

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type AccessType string

const (
	AccessTypeOwner  AccessType = "owner"
	AccessTypeRead   AccessType = "read"
	AccessTypeManage AccessType = "manage"
)

func (e *AccessType) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = AccessType(s)
	case string:
		*e = AccessType(s)
	default:
		return fmt.Errorf("unsupported scan type for AccessType: %T", src)
	}
	return nil
}

type NullAccessType struct {
	AccessType AccessType `json:"access_type"`
	Valid      bool       `json:"valid"` // Valid is true if AccessType is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullAccessType) Scan(value interface{}) error {
	if value == nil {
		ns.AccessType, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.AccessType.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullAccessType) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.AccessType), nil
}

type AccessList struct {
	ID           uuid.UUID     `json:"id"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	CredentialID uuid.NullUUID `json:"credential_id"`
	UserID       uuid.NullUUID `json:"user_id"`
	AccessType   AccessType    `json:"access_type"`
}

type Credential struct {
	ID          uuid.UUID      `json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Name        string         `json:"name"`
	Description sql.NullString `json:"description"`
	FolderID    uuid.NullUUID  `json:"folder_id"`
	CreatedBy   uuid.NullUUID  `json:"created_by"`
}

type EncryptedDatum struct {
	ID           uuid.UUID     `json:"id"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	FieldName    string        `json:"field_name"`
	CredentialID uuid.NullUUID `json:"credential_id"`
	FieldValue   string        `json:"field_value"`
	UserID       uuid.NullUUID `json:"user_id"`
}

type Folder struct {
	ID          uuid.UUID      `json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Name        string         `json:"name"`
	Description sql.NullString `json:"description"`
	CreatedBy   uuid.NullUUID  `json:"created_by"`
}

type Group struct {
	ID        uuid.UUID     `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Name      string        `json:"name"`
	Members   []uuid.UUID   `json:"members"`
	CreatedBy uuid.NullUUID `json:"created_by"`
}

type UnencryptedDatum struct {
	ID           uuid.UUID     `json:"id"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	FieldName    string        `json:"field_name"`
	CredentialID uuid.NullUUID `json:"credential_id"`
	FieldValue   string        `json:"field_value"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Username  string    `json:"username"`
}
