// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.24.0
// source: environment.sql

package db

import (
	"context"
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
RETURNING Id
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
    cli_user, 
    credential_id, 
    field_value, 
    field_name, 
    parent_field_id, 
    env_id
) VALUES (
    $1, 
    $2, 
    $3, 
    $4, 
    $5, 
    $6
)
RETURNING id
`

type CreateEnvFieldsParams struct {
	CliUser       uuid.UUID `json:"cliUser"`
	CredentialID  uuid.UUID `json:"credentialId"`
	FieldValue    string    `json:"fieldValue"`
	FieldName     string    `json:"fieldName"`
	ParentFieldID uuid.UUID `json:"parentFieldId"`
	EnvID         uuid.UUID `json:"envId"`
}

func (q *Queries) CreateEnvFields(ctx context.Context, arg CreateEnvFieldsParams) (uuid.UUID, error) {
	row := q.db.QueryRowContext(ctx, createEnvFields,
		arg.CliUser,
		arg.CredentialID,
		arg.FieldValue,
		arg.FieldName,
		arg.ParentFieldID,
		arg.EnvID,
	)
	var id uuid.UUID
	err := row.Scan(&id)
	return id, err
}

const getEnvFields = `-- name: GetEnvFields :many
SELECT pf.field_value, ef.field_name, ef.id ,ef.credential_id 
FROM environment_fields ef
JOIN fields f ON ef.parent_field_id = f.id
JOIN fields pf ON ef.parent_field_id = pf.id
WHERE ef.env_id = $1
`

type GetEnvFieldsRow struct {
	FieldValue   string    `json:"fieldValue"`
	FieldName    string    `json:"fieldName"`
	ID           uuid.UUID `json:"id"`
	CredentialID uuid.UUID `json:"credentialId"`
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
SELECT e.id, e.cli_user, e.name, e.createdat, e.updatedat, e.created_by,   COALESCE( u.encryption_key, '') as "publicKey"
FROM environments e
JOIN users u ON e.cli_user = u.id
WHERE e.cli_user IN (
    SELECT id 
    FROM users 
    WHERE u.created_by = $1 AND type = 'cli'
)
`

type GetEnvironmentsForUserRow struct {
	ID        uuid.UUID `json:"id"`
	CliUser   uuid.UUID `json:"cliUser"`
	Name      string    `json:"name"`
	Createdat time.Time `json:"createdat"`
	Updatedat time.Time `json:"updatedat"`
	CreatedBy uuid.UUID `json:"createdBy"`
	PublicKey string    `json:"publicKey"`
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
