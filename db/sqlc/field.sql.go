// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.24.0
// source: field.sql

package db

import (
	"context"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const addField = `-- name: AddField :one
INSERT INTO
    fields (field_name, field_value, credential_id, field_type, user_id, created_by)
VALUES
    ($1, $2, $3, $4, $5, $6) RETURNING id
`

type AddFieldParams struct {
	FieldName    string        `json:"fieldName"`
	FieldValue   string        `json:"fieldValue"`
	CredentialID uuid.UUID     `json:"credentialId"`
	FieldType    string        `json:"fieldType"`
	UserID       uuid.UUID     `json:"userId"`
	CreatedBy    uuid.NullUUID `json:"createdBy"`
}

func (q *Queries) AddField(ctx context.Context, arg AddFieldParams) (uuid.UUID, error) {
	row := q.db.QueryRowContext(ctx, addField,
		arg.FieldName,
		arg.FieldValue,
		arg.CredentialID,
		arg.FieldType,
		arg.UserID,
		arg.CreatedBy,
	)
	var id uuid.UUID
	err := row.Scan(&id)
	return id, err
}

const checkFieldEntryExists = `-- name: CheckFieldEntryExists :one
SELECT EXISTS (
    SELECT 1
    FROM fields
    WHERE credential_id = $1 AND user_id = $2
)
`

type CheckFieldEntryExistsParams struct {
	CredentialID uuid.UUID `json:"credentialId"`
	UserID       uuid.UUID `json:"userId"`
}

func (q *Queries) CheckFieldEntryExists(ctx context.Context, arg CheckFieldEntryExistsParams) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkFieldEntryExists, arg.CredentialID, arg.UserID)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const deleteAccessRemovedFields = `-- name: DeleteAccessRemovedFields :exec
DELETE FROM fields
WHERE
    EXISTS (
        -- Select fields rows that don't have a corresponding entry in credential_access
        SELECT 1
        FROM fields f
        WHERE
            NOT EXISTS (
                -- Look for a matching entry in credential_access
                SELECT 1
                FROM credential_access ca
                WHERE
                    ca.credential_id = f.credential_id
                    AND ca.user_id = f.user_id
            )
            AND f.credential_id = fields.credential_id
            AND f.user_id = fields.user_id
    )
`

func (q *Queries) DeleteAccessRemovedFields(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAccessRemovedFields)
	return err
}

const deleteCredentialFields = `-- name: DeleteCredentialFields :exec
DELETE FROM fields
WHERE credential_id = $1
`

func (q *Queries) DeleteCredentialFields(ctx context.Context, credentialID uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteCredentialFields, credentialID)
	return err
}

const getAllFieldsForCredentialIDs = `-- name: GetAllFieldsForCredentialIDs :many
SELECT
    fd.id,
    fd.field_name,
    fv.field_value,
    fd.field_type,
    fd.credential_id
FROM field_data as fd
JOIN field_values as fv ON fd.id = fv.field_id
WHERE
fv.user_id = $1 
AND fd.credential_id = ANY($2::UUID[])
`

type GetAllFieldsForCredentialIDsParams struct {
	UserID      uuid.UUID   `json:"userId"`
	Credentials []uuid.UUID `json:"credentials"`
}

type GetAllFieldsForCredentialIDsRow struct {
	ID           uuid.UUID `json:"id"`
	FieldName    string    `json:"fieldName"`
	FieldValue   string    `json:"fieldValue"`
	FieldType    string    `json:"fieldType"`
	CredentialID uuid.UUID `json:"credentialId"`
}

func (q *Queries) GetAllFieldsForCredentialIDs(ctx context.Context, arg GetAllFieldsForCredentialIDsParams) ([]GetAllFieldsForCredentialIDsRow, error) {
	rows, err := q.db.QueryContext(ctx, getAllFieldsForCredentialIDs, arg.UserID, pq.Array(arg.Credentials))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetAllFieldsForCredentialIDsRow{}
	for rows.Next() {
		var i GetAllFieldsForCredentialIDsRow
		if err := rows.Scan(
			&i.ID,
			&i.FieldName,
			&i.FieldValue,
			&i.FieldType,
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

const getNonSensitiveFieldsForCredentialIDs = `-- name: GetNonSensitiveFieldsForCredentialIDs :many
SELECT
    fd.id,
    fd.credential_id,
    fd.field_name,
    fv.field_value,
    fd.field_type
FROM field_data as fd
JOIN field_values as fv ON fd.id = fv.field_id
WHERE
fd.field_type != 'sensitive' 
AND fv.user_id = $1 
AND fd.credential_id = ANY($2::UUID[])
`

type GetNonSensitiveFieldsForCredentialIDsParams struct {
	UserID        uuid.UUID   `json:"userId"`
	Credentialids []uuid.UUID `json:"credentialids"`
}

type GetNonSensitiveFieldsForCredentialIDsRow struct {
	ID           uuid.UUID `json:"id"`
	CredentialID uuid.UUID `json:"credentialId"`
	FieldName    string    `json:"fieldName"`
	FieldValue   string    `json:"fieldValue"`
	FieldType    string    `json:"fieldType"`
}

func (q *Queries) GetNonSensitiveFieldsForCredentialIDs(ctx context.Context, arg GetNonSensitiveFieldsForCredentialIDsParams) ([]GetNonSensitiveFieldsForCredentialIDsRow, error) {
	rows, err := q.db.QueryContext(ctx, getNonSensitiveFieldsForCredentialIDs, arg.UserID, pq.Array(arg.Credentialids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetNonSensitiveFieldsForCredentialIDsRow{}
	for rows.Next() {
		var i GetNonSensitiveFieldsForCredentialIDsRow
		if err := rows.Scan(
			&i.ID,
			&i.CredentialID,
			&i.FieldName,
			&i.FieldValue,
			&i.FieldType,
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

const getSensitiveFields = `-- name: GetSensitiveFields :many
SELECT
    fd.id,
    fd.field_name,
    fv.field_value,
    fd.field_type
FROM field_data as fd
JOIN field_values as fv ON fd.id = fv.field_id
WHERE
(fd.field_type = 'sensitive' OR fd.field_type = 'totp')
AND fd.credential_id = $1
AND fv.user_id = $2
`

type GetSensitiveFieldsParams struct {
	CredentialID uuid.UUID `json:"credentialId"`
	UserID       uuid.UUID `json:"userId"`
}

type GetSensitiveFieldsRow struct {
	ID         uuid.UUID `json:"id"`
	FieldName  string    `json:"fieldName"`
	FieldValue string    `json:"fieldValue"`
	FieldType  string    `json:"fieldType"`
}

func (q *Queries) GetSensitiveFields(ctx context.Context, arg GetSensitiveFieldsParams) ([]GetSensitiveFieldsRow, error) {
	rows, err := q.db.QueryContext(ctx, getSensitiveFields, arg.CredentialID, arg.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetSensitiveFieldsRow{}
	for rows.Next() {
		var i GetSensitiveFieldsRow
		if err := rows.Scan(
			&i.ID,
			&i.FieldName,
			&i.FieldValue,
			&i.FieldType,
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

const removeCredentialFieldsForUsers = `-- name: RemoveCredentialFieldsForUsers :exec
DELETE FROM fields WHERE credential_id = $1 AND user_id = ANY($2::UUID[])
`

type RemoveCredentialFieldsForUsersParams struct {
	CredentialID uuid.UUID   `json:"credentialId"`
	UserIds      []uuid.UUID `json:"userIds"`
}

func (q *Queries) RemoveCredentialFieldsForUsers(ctx context.Context, arg RemoveCredentialFieldsForUsersParams) error {
	_, err := q.db.ExecContext(ctx, removeCredentialFieldsForUsers, arg.CredentialID, pq.Array(arg.UserIds))
	return err
}
