// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.24.0
// source: environment.sql

package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const addEnvironment = `-- name: AddEnvironment :one
INSERT INTO environments (
    cli_user, 
    name, 
    created_by
) VALUES (
    $1, 
    $2, 
    $3
)
RETURNING id
`

type AddEnvironmentParams struct {
	CliUser   uuid.UUID `json:"cliUser"`
	Name      string    `json:"name"`
	CreatedBy uuid.UUID `json:"createdBy"`
}

func (q *Queries) AddEnvironment(ctx context.Context, arg AddEnvironmentParams) (uuid.UUID, error) {
	row := q.db.QueryRowContext(ctx, addEnvironment, arg.CliUser, arg.Name, arg.CreatedBy)
	var id uuid.UUID
	err := row.Scan(&id)
	return id, err
}

const checkCredentialExistsForEnv = `-- name: CheckCredentialExistsForEnv :one
SELECT EXISTS (
    SELECT 1 
    FROM environment_fields 
    WHERE credential_id = $1 AND env_id = $2
)
`

type CheckCredentialExistsForEnvParams struct {
	CredentialID uuid.UUID `json:"credentialId"`
	EnvID        uuid.UUID `json:"envId"`
}

func (q *Queries) CheckCredentialExistsForEnv(ctx context.Context, arg CheckCredentialExistsForEnvParams) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkCredentialExistsForEnv, arg.CredentialID, arg.EnvID)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const createEnvFields = `-- name: CreateEnvFields :one
INSERT INTO environment_fields (
    credential_id, 
    field_value, 
    field_name, 
    parent_field_value_id,
    env_id
) VALUES (
    $1, 
    $2, 
    $3, 
    $4, 
    $5 
)
RETURNING id
`

type CreateEnvFieldsParams struct {
	CredentialID       uuid.UUID `json:"credentialId"`
	FieldValue         string    `json:"fieldValue"`
	FieldName          string    `json:"fieldName"`
	ParentFieldValueID uuid.UUID `json:"parentFieldValueId"`
	EnvID              uuid.UUID `json:"envId"`
}

func (q *Queries) CreateEnvFields(ctx context.Context, arg CreateEnvFieldsParams) (uuid.UUID, error) {
	row := q.db.QueryRowContext(ctx, createEnvFields,
		arg.CredentialID,
		arg.FieldValue,
		arg.FieldName,
		arg.ParentFieldValueID,
		arg.EnvID,
	)
	var id uuid.UUID
	err := row.Scan(&id)
	return id, err
}

const editEnvFieldValue = `-- name: EditEnvFieldValue :exec
UPDATE environment_fields
SET field_value = $1, updated_at = NOW()
WHERE id = $2
`

type EditEnvFieldValueParams struct {
	FieldValue string    `json:"fieldValue"`
	ID         uuid.UUID `json:"id"`
}

func (q *Queries) EditEnvFieldValue(ctx context.Context, arg EditEnvFieldValueParams) error {
	_, err := q.db.ExecContext(ctx, editEnvFieldValue, arg.FieldValue, arg.ID)
	return err
}

const editEnvironmentFieldNameByID = `-- name: EditEnvironmentFieldNameByID :one
UPDATE environment_fields
SET field_name = $1, updated_at = NOW()
WHERE id = $2 and env_id = $3
RETURNING field_name
`

type EditEnvironmentFieldNameByIDParams struct {
	FieldName string    `json:"fieldName"`
	ID        uuid.UUID `json:"id"`
	EnvID     uuid.UUID `json:"envId"`
}

func (q *Queries) EditEnvironmentFieldNameByID(ctx context.Context, arg EditEnvironmentFieldNameByIDParams) (string, error) {
	row := q.db.QueryRowContext(ctx, editEnvironmentFieldNameByID, arg.FieldName, arg.ID, arg.EnvID)
	var field_name string
	err := row.Scan(&field_name)
	return field_name, err
}

const getEnvFields = `-- name: GetEnvFields :many
SELECT 
    fv.field_value, 
    ef.field_name, 
    ef.id,
    ef.credential_id, 
    c.name as "credentialName"
FROM environment_fields ef
JOIN field_values fv ON ef.parent_field_value_id = fv.id
JOIN credentials c ON ef.credential_id = c.id
WHERE ef.env_id = $1
`

type GetEnvFieldsRow struct {
	FieldValue     string    `json:"fieldValue"`
	FieldName      string    `json:"fieldName"`
	ID             uuid.UUID `json:"id"`
	CredentialID   uuid.UUID `json:"credentialId"`
	CredentialName string    `json:"credentialName"`
}

func (q *Queries) GetEnvFields(ctx context.Context, envID uuid.UUID) ([]GetEnvFieldsRow, error) {
	rows, err := q.db.QueryContext(ctx, getEnvFields, envID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetEnvFieldsRow{}
	for rows.Next() {
		var i GetEnvFieldsRow
		if err := rows.Scan(
			&i.FieldValue,
			&i.FieldName,
			&i.ID,
			&i.CredentialID,
			&i.CredentialName,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEnvFieldsForCredential = `-- name: GetEnvFieldsForCredential :many
SELECT ef.id as envFieldID, ef.env_id, fd.id as fieldID, u.id as userID, u.encryption_key as "publicKey"
FROM environment_fields as ef
    JOIN environments e ON ef.env_id = e.id
    JOIN field_values fv ON ef.parent_field_value_id = fv.id
    JOIN field_data fd ON fv.field_id = fd.id
    JOIN users u ON e.cli_user = u.id
WHERE ef.credential_id = $1
`

type GetEnvFieldsForCredentialRow struct {
	Envfieldid uuid.UUID      `json:"envfieldid"`
	EnvID      uuid.UUID      `json:"envId"`
	Fieldid    uuid.UUID      `json:"fieldid"`
	Userid     uuid.UUID      `json:"userid"`
	PublicKey  sql.NullString `json:"publicKey"`
}

func (q *Queries) GetEnvFieldsForCredential(ctx context.Context, credentialID uuid.UUID) ([]GetEnvFieldsForCredentialRow, error) {
	rows, err := q.db.QueryContext(ctx, getEnvFieldsForCredential, credentialID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetEnvFieldsForCredentialRow{}
	for rows.Next() {
		var i GetEnvFieldsForCredentialRow
		if err := rows.Scan(
			&i.Envfieldid,
			&i.EnvID,
			&i.Fieldid,
			&i.Userid,
			&i.PublicKey,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEnvForCredential = `-- name: GetEnvForCredential :many
SELECT 
    e.id as "envId", 
    COALESCE(u.encryption_key, '') as "cliUserPublicKey", 
    e.cli_user as "cliUserId",
    u.created_by as "cliUserCreatedBy"
FROM environments e
JOIN environment_fields ef ON e.id = ef.env_id
JOIN users u ON e.cli_user = u.id
WHERE ef.credential_id = $1
GROUP BY e.id, u.encryption_key, e.cli_user, u.created_by
`

type GetEnvForCredentialRow struct {
	EnvId            uuid.UUID     `json:"envId"`
	CliUserPublicKey string        `json:"cliUserPublicKey"`
	CliUserId        uuid.UUID     `json:"cliUserId"`
	CliUserCreatedBy uuid.NullUUID `json:"cliUserCreatedBy"`
}

func (q *Queries) GetEnvForCredential(ctx context.Context, credentialID uuid.UUID) ([]GetEnvForCredentialRow, error) {
	rows, err := q.db.QueryContext(ctx, getEnvForCredential, credentialID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetEnvForCredentialRow{}
	for rows.Next() {
		var i GetEnvForCredentialRow
		if err := rows.Scan(
			&i.EnvId,
			&i.CliUserPublicKey,
			&i.CliUserId,
			&i.CliUserCreatedBy,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEnvironmentByID = `-- name: GetEnvironmentByID :one
SELECT id, cli_user, name, createdat, updatedat, created_by from environments WHERE id = $1 and created_by = $2
`

type GetEnvironmentByIDParams struct {
	ID        uuid.UUID `json:"id"`
	CreatedBy uuid.UUID `json:"createdBy"`
}

func (q *Queries) GetEnvironmentByID(ctx context.Context, arg GetEnvironmentByIDParams) (Environment, error) {
	row := q.db.QueryRowContext(ctx, getEnvironmentByID, arg.ID, arg.CreatedBy)
	var i Environment
	err := row.Scan(
		&i.ID,
		&i.CliUser,
		&i.Name,
		&i.Createdat,
		&i.Updatedat,
		&i.CreatedBy,
	)
	return i, err
}

const getEnvironmentFieldsByName = `-- name: GetEnvironmentFieldsByName :many
SELECT ef.id, ef.field_name, ef.field_value, ef.credential_id
FROM environment_fields ef
JOIN environments e ON ef.env_id = e.Id
WHERE e.name = $1
`

type GetEnvironmentFieldsByNameRow struct {
	ID           uuid.UUID `json:"id"`
	FieldName    string    `json:"fieldName"`
	FieldValue   string    `json:"fieldValue"`
	CredentialID uuid.UUID `json:"credentialId"`
}

func (q *Queries) GetEnvironmentFieldsByName(ctx context.Context, name string) ([]GetEnvironmentFieldsByNameRow, error) {
	rows, err := q.db.QueryContext(ctx, getEnvironmentFieldsByName, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetEnvironmentFieldsByNameRow{}
	for rows.Next() {
		var i GetEnvironmentFieldsByNameRow
		if err := rows.Scan(
			&i.ID,
			&i.FieldName,
			&i.FieldValue,
			&i.CredentialID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getEnvironmentsForUser = `-- name: GetEnvironmentsForUser :many
SELECT e.id, e.cli_user, e.name, e.createdat, e.updatedat, e.created_by,   COALESCE( u.encryption_key, '') as "publicKey", u.username as "cliUsername"
FROM environments e
JOIN users u ON e.cli_user = u.id
WHERE e.cli_user IN (
    SELECT id
    FROM users 
    WHERE u.created_by = $1 AND type = 'cli'
)
`

type GetEnvironmentsForUserRow struct {
	ID          uuid.UUID `json:"id"`
	CliUser     uuid.UUID `json:"cliUser"`
	Name        string    `json:"name"`
	Createdat   time.Time `json:"createdat"`
	Updatedat   time.Time `json:"updatedat"`
	CreatedBy   uuid.UUID `json:"createdBy"`
	PublicKey   string    `json:"publicKey"`
	CliUsername string    `json:"cliUsername"`
}

func (q *Queries) GetEnvironmentsForUser(ctx context.Context, createdBy uuid.NullUUID) ([]GetEnvironmentsForUserRow, error) {
	rows, err := q.db.QueryContext(ctx, getEnvironmentsForUser, createdBy)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetEnvironmentsForUserRow{}
	for rows.Next() {
		var i GetEnvironmentsForUserRow
		if err := rows.Scan(
			&i.ID,
			&i.CliUser,
			&i.Name,
			&i.Createdat,
			&i.Updatedat,
			&i.CreatedBy,
			&i.PublicKey,
			&i.CliUsername,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getUserEnvsForCredential = `-- name: GetUserEnvsForCredential :many
SELECT e.id
FROM environments e
JOIN environment_fields ef ON e.id = ef.env_id
WHERE ef.credential_id = $1 AND cli_user = $2
`

type GetUserEnvsForCredentialParams struct {
	CredentialID uuid.UUID `json:"credentialId"`
	CliUser      uuid.UUID `json:"cliUser"`
}

func (q *Queries) GetUserEnvsForCredential(ctx context.Context, arg GetUserEnvsForCredentialParams) ([]uuid.UUID, error) {
	rows, err := q.db.QueryContext(ctx, getUserEnvsForCredential, arg.CredentialID, arg.CliUser)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		items = append(items, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const isEnvironmentOwner = `-- name: IsEnvironmentOwner :one
SELECT EXISTS (
    SELECT 1 
    FROM environments 
    WHERE id = $1 AND created_by = $2
)
`

type IsEnvironmentOwnerParams struct {
	ID        uuid.UUID `json:"id"`
	CreatedBy uuid.UUID `json:"createdBy"`
}

func (q *Queries) IsEnvironmentOwner(ctx context.Context, arg IsEnvironmentOwnerParams) (bool, error) {
	row := q.db.QueryRowContext(ctx, isEnvironmentOwner, arg.ID, arg.CreatedBy)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}
