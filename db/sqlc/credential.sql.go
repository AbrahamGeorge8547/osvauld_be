// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.24.0
// source: credential.sql

package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const addCredential = `-- name: AddCredential :one
SELECT
    add_credential_with_access($1 :: JSONB)
`

func (q *Queries) AddCredential(ctx context.Context, dollar_1 json.RawMessage) (interface{}, error) {
	row := q.db.QueryRowContext(ctx, addCredential, dollar_1)
	var add_credential_with_access interface{}
	err := row.Scan(&add_credential_with_access)
	return add_credential_with_access, err
}

const createCredential = `-- name: CreateCredential :one
INSERT INTO
    credentials (NAME, description, credential_type, folder_id, created_by)
VALUES
    ($1, $2, $3, $4, $5) RETURNING id
`

type CreateCredentialParams struct {
	Name           string         `json:"name"`
	Description    sql.NullString `json:"description"`
	CredentialType string         `json:"credentialType"`
	FolderID       uuid.UUID      `json:"folderId"`
	CreatedBy      uuid.UUID      `json:"createdBy"`
}

// sql/create_credential.sql
func (q *Queries) CreateCredential(ctx context.Context, arg CreateCredentialParams) (uuid.UUID, error) {
	row := q.db.QueryRowContext(ctx, createCredential,
		arg.Name,
		arg.Description,
		arg.CredentialType,
		arg.FolderID,
		arg.CreatedBy,
	)
	var id uuid.UUID
	err := row.Scan(&id)
	return id, err
}

const fetchCredentialDataByID = `-- name: FetchCredentialDataByID :one
SELECT
    id,
    created_at,
    updated_at,
    name,
    description,
    folder_id,
    created_by
FROM
    credentials
WHERE
    id = $1
`

type FetchCredentialDataByIDRow struct {
	ID          uuid.UUID      `json:"id"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
	Name        string         `json:"name"`
	Description sql.NullString `json:"description"`
	FolderID    uuid.UUID      `json:"folderId"`
	CreatedBy   uuid.UUID      `json:"createdBy"`
}

func (q *Queries) FetchCredentialDataByID(ctx context.Context, id uuid.UUID) (FetchCredentialDataByIDRow, error) {
	row := q.db.QueryRowContext(ctx, fetchCredentialDataByID, id)
	var i FetchCredentialDataByIDRow
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Name,
		&i.Description,
		&i.FolderID,
		&i.CreatedBy,
	)
	return i, err
}

const fetchCredentialDetailsForUserByFolderId = `-- name: FetchCredentialDetailsForUserByFolderId :many
SELECT
    C.id AS "credentialID",
    C.name,
    COALESCE(C.description, '') AS "description",
    C.credential_type AS "credentialType",
    C.created_at AS "createdAt",
    C.updated_at AS "updatedAt",
    C.created_by AS "createdBy",
    A.access_type AS "accessType"
FROM
    credentials AS C,
    access_list AS A
WHERE
    C.id = A .credential_id
    AND C.folder_id = $1
    AND A.user_id = $2
`

type FetchCredentialDetailsForUserByFolderIdParams struct {
	FolderID uuid.UUID `json:"folderId"`
	UserID   uuid.UUID `json:"userId"`
}

type FetchCredentialDetailsForUserByFolderIdRow struct {
	CredentialID   uuid.UUID `json:"credentialID"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	CredentialType string    `json:"credentialType"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	CreatedBy      uuid.UUID `json:"createdBy"`
	AccessType     string    `json:"accessType"`
}

func (q *Queries) FetchCredentialDetailsForUserByFolderId(ctx context.Context, arg FetchCredentialDetailsForUserByFolderIdParams) ([]FetchCredentialDetailsForUserByFolderIdRow, error) {
	rows, err := q.db.QueryContext(ctx, fetchCredentialDetailsForUserByFolderId, arg.FolderID, arg.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []FetchCredentialDetailsForUserByFolderIdRow{}
	for rows.Next() {
		var i FetchCredentialDetailsForUserByFolderIdRow
		if err := rows.Scan(
			&i.CredentialID,
			&i.Name,
			&i.Description,
			&i.CredentialType,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.CreatedBy,
			&i.AccessType,
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

const fetchCredentialFieldsForUserByCredentialIds = `-- name: FetchCredentialFieldsForUserByCredentialIds :many
SELECT
    credential_id AS "credentialID",
    id AS "fieldID",
    field_name as "fieldName",
    field_value as "fieldValue",
    field_type as "fieldType"
FROM
    encrypted_data
WHERE
    field_type != 'sensitive'
    AND credential_id = ANY($1::UUID[])
    AND user_id = $2
`

type FetchCredentialFieldsForUserByCredentialIdsParams struct {
	Column1 []uuid.UUID `json:"column1"`
	UserID  uuid.UUID   `json:"userId"`
}

type FetchCredentialFieldsForUserByCredentialIdsRow struct {
	CredentialID uuid.UUID `json:"credentialID"`
	FieldID      uuid.UUID `json:"fieldID"`
	FieldName    string    `json:"fieldName"`
	FieldValue   string    `json:"fieldValue"`
	FieldType    string    `json:"fieldType"`
}

func (q *Queries) FetchCredentialFieldsForUserByCredentialIds(ctx context.Context, arg FetchCredentialFieldsForUserByCredentialIdsParams) ([]FetchCredentialFieldsForUserByCredentialIdsRow, error) {
	rows, err := q.db.QueryContext(ctx, fetchCredentialFieldsForUserByCredentialIds, pq.Array(arg.Column1), arg.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []FetchCredentialFieldsForUserByCredentialIdsRow{}
	for rows.Next() {
		var i FetchCredentialFieldsForUserByCredentialIdsRow
		if err := rows.Scan(
			&i.CredentialID,
			&i.FieldID,
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

const getAllUrlsForUser = `-- name: GetAllUrlsForUser :many



SELECT DISTINCT
    field_value as value, credential_id as "credentialId"
FROM 
    encrypted_data
WHERE 
    user_id = $1 AND field_name = 'Domain'
`

type GetAllUrlsForUserRow struct {
	Value        string    `json:"value"`
	CredentialId uuid.UUID `json:"credentialId"`
}

// -- name: GetCredentialsByUrl :many
// WITH CredentialWithUnencrypted AS (
//
//	SELECT
//	    C.id AS "id",
//	    C.name AS "name",
//	    COALESCE(C.description, '') AS "description",
//	    json_agg(
//	        json_build_object(
//	            'fieldName', u.field_name,
//	            'fieldValue', u.field_value,
//	            'isUrl', u.is_url,
//	            'url', u.url
//	        )
//	    ) FILTER (WHERE u.field_name IS NOT NULL) AS "unencryptedFields"
//	FROM
//	    credentials C
//	    LEFT JOIN unencrypted_data u ON C.id = u.credential_id
//	WHERE
//	    C.id IN (SELECT credential_id FROM unencrypted_data as und WHERE und.url = $1)
//	GROUP BY
//	    C.id
//
// ),
// DistinctAccess AS (
//
//	SELECT DISTINCT credential_id
//	FROM access_list
//	WHERE user_id = $2
//
// )
// SELECT
//
//	cwu.*
//
// FROM
//
//	CredentialWithUnencrypted cwu
//
// JOIN
//
//	DistinctAccess DA ON cwu.id = DA.credential_id;
func (q *Queries) GetAllUrlsForUser(ctx context.Context, userID uuid.UUID) ([]GetAllUrlsForUserRow, error) {
	rows, err := q.db.QueryContext(ctx, getAllUrlsForUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetAllUrlsForUserRow{}
	for rows.Next() {
		var i GetAllUrlsForUserRow
		if err := rows.Scan(&i.Value, &i.CredentialId); err != nil {
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

const getCredentialDetails = `-- name: GetCredentialDetails :one
SELECT
    id,
    NAME,
    COALESCE(description, '') AS "description"
FROM
    credentials
WHERE
    id = $1
`

type GetCredentialDetailsRow struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

func (q *Queries) GetCredentialDetails(ctx context.Context, id uuid.UUID) (GetCredentialDetailsRow, error) {
	row := q.db.QueryRowContext(ctx, getCredentialDetails, id)
	var i GetCredentialDetailsRow
	err := row.Scan(&i.ID, &i.Name, &i.Description)
	return i, err
}

const getCredentialDetailsByIds = `-- name: GetCredentialDetailsByIds :many
SELECT
    C.id AS "credentialId",
    C.name,
    COALESCE(C.description, '') AS description,
    json_agg(
        json_build_object(
            'fieldName', COALESCE(ED.field_name, ''),
            'fieldValue', ED.field_value
        )
    ) AS "fields"
FROM
    credentials C
LEFT JOIN encrypted_data ED ON C.id = ED.credential_id AND ED.user_id = $2
WHERE
    C.id = ANY($1::UUID[])
GROUP BY C.id
`

type GetCredentialDetailsByIdsParams struct {
	Column1 []uuid.UUID `json:"column1"`
	UserID  uuid.UUID   `json:"userId"`
}

type GetCredentialDetailsByIdsRow struct {
	CredentialId uuid.UUID       `json:"credentialId"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Fields       json.RawMessage `json:"fields"`
}

func (q *Queries) GetCredentialDetailsByIds(ctx context.Context, arg GetCredentialDetailsByIdsParams) ([]GetCredentialDetailsByIdsRow, error) {
	rows, err := q.db.QueryContext(ctx, getCredentialDetailsByIds, pq.Array(arg.Column1), arg.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetCredentialDetailsByIdsRow{}
	for rows.Next() {
		var i GetCredentialDetailsByIdsRow
		if err := rows.Scan(
			&i.CredentialId,
			&i.Name,
			&i.Description,
			&i.Fields,
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

const getCredentialIdsByFolder = `-- name: GetCredentialIdsByFolder :many
SELECT 
    c.id AS "credentialId"
FROM 
    credentials c
JOIN 
    access_list a ON c.id = a.credential_id
WHERE 
    a.user_id = $1
    AND c.folder_id = $2
`

type GetCredentialIdsByFolderParams struct {
	UserID   uuid.UUID `json:"userId"`
	FolderID uuid.UUID `json:"folderId"`
}

func (q *Queries) GetCredentialIdsByFolder(ctx context.Context, arg GetCredentialIdsByFolderParams) ([]uuid.UUID, error) {
	rows, err := q.db.QueryContext(ctx, getCredentialIdsByFolder, arg.UserID, arg.FolderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []uuid.UUID{}
	for rows.Next() {
		var credentialId uuid.UUID
		if err := rows.Scan(&credentialId); err != nil {
			return nil, err
		}
		items = append(items, credentialId)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getCredentialUnencryptedData = `-- name: GetCredentialUnencryptedData :many
SELECT
    field_name AS "fieldName",
    field_value AS "fieldValue"
FROM
    unencrypted_data
WHERE
    credential_id = $1
`

type GetCredentialUnencryptedDataRow struct {
	FieldName  string `json:"fieldName"`
	FieldValue string `json:"fieldValue"`
}

func (q *Queries) GetCredentialUnencryptedData(ctx context.Context, credentialID uuid.UUID) ([]GetCredentialUnencryptedDataRow, error) {
	rows, err := q.db.QueryContext(ctx, getCredentialUnencryptedData, credentialID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetCredentialUnencryptedDataRow{}
	for rows.Next() {
		var i GetCredentialUnencryptedDataRow
		if err := rows.Scan(&i.FieldName, &i.FieldValue); err != nil {
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

const getCredentialsFieldsByIds = `-- name: GetCredentialsFieldsByIds :many
SELECT
    e.credential_id AS "credentialId",
    json_agg(
        json_build_object(
            'fieldId',
            e.id,
            'fieldValue',
            e.field_value
        )
    ) AS "fields"
FROM
    encrypted_data e
WHERE
    e.credential_id = ANY($1 :: uuid [ ])
    AND e.user_id = $2
GROUP BY
    e.credential_id
ORDER BY
    e.credential_id
`

type GetCredentialsFieldsByIdsParams struct {
	Column1 []uuid.UUID `json:"column1"`
	UserID  uuid.UUID   `json:"userId"`
}

type GetCredentialsFieldsByIdsRow struct {
	CredentialId uuid.UUID       `json:"credentialId"`
	Fields       json.RawMessage `json:"fields"`
}

func (q *Queries) GetCredentialsFieldsByIds(ctx context.Context, arg GetCredentialsFieldsByIdsParams) ([]GetCredentialsFieldsByIdsRow, error) {
	rows, err := q.db.QueryContext(ctx, getCredentialsFieldsByIds, pq.Array(arg.Column1), arg.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetCredentialsFieldsByIdsRow{}
	for rows.Next() {
		var i GetCredentialsFieldsByIdsRow
		if err := rows.Scan(&i.CredentialId, &i.Fields); err != nil {
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

const getEncryptedCredentialsByFolder = `-- name: GetEncryptedCredentialsByFolder :many
SELECT
    C .id as "credentialId",
    json_agg(
        json_build_object(
            'fieldName',
            e.field_name,
            'fieldValue',
            e.field_value
        )
    ) AS "encryptedFields"
FROM
    credentials C
    JOIN encrypted_data e ON C .id = e.credential_id
WHERE
    C .folder_id = $1
    AND e.user_id = $2
GROUP BY
    C .id
ORDER BY
    C .id
`

type GetEncryptedCredentialsByFolderParams struct {
	FolderID uuid.UUID `json:"folderId"`
	UserID   uuid.UUID `json:"userId"`
}

type GetEncryptedCredentialsByFolderRow struct {
	CredentialId    uuid.UUID       `json:"credentialId"`
	EncryptedFields json.RawMessage `json:"encryptedFields"`
}

func (q *Queries) GetEncryptedCredentialsByFolder(ctx context.Context, arg GetEncryptedCredentialsByFolderParams) ([]GetEncryptedCredentialsByFolderRow, error) {
	rows, err := q.db.QueryContext(ctx, getEncryptedCredentialsByFolder, arg.FolderID, arg.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetEncryptedCredentialsByFolderRow{}
	for rows.Next() {
		var i GetEncryptedCredentialsByFolderRow
		if err := rows.Scan(&i.CredentialId, &i.EncryptedFields); err != nil {
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
    field_name as "fieldName", 
    field_value as "fieldValue", 
    credential_id as "credentialId"
FROM 
    encrypted_data
WHERE 
    user_id = $1 AND credential_id = $2 AND field_type = 'sensitive'
`

type GetSensitiveFieldsParams struct {
	UserID       uuid.UUID `json:"userId"`
	CredentialID uuid.UUID `json:"credentialId"`
}

type GetSensitiveFieldsRow struct {
	FieldName    string    `json:"fieldName"`
	FieldValue   string    `json:"fieldValue"`
	CredentialId uuid.UUID `json:"credentialId"`
}

func (q *Queries) GetSensitiveFields(ctx context.Context, arg GetSensitiveFieldsParams) ([]GetSensitiveFieldsRow, error) {
	rows, err := q.db.QueryContext(ctx, getSensitiveFields, arg.UserID, arg.CredentialID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetSensitiveFieldsRow{}
	for rows.Next() {
		var i GetSensitiveFieldsRow
		if err := rows.Scan(&i.FieldName, &i.FieldValue, &i.CredentialId); err != nil {
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

const getUserEncryptedData = `-- name: GetUserEncryptedData :many
SELECT
    field_name AS "fieldName",
    field_value AS "fieldValue"
FROM
    encrypted_data
WHERE
    user_id = $1
    AND credential_id = $2
`

type GetUserEncryptedDataParams struct {
	UserID       uuid.UUID `json:"userId"`
	CredentialID uuid.UUID `json:"credentialId"`
}

type GetUserEncryptedDataRow struct {
	FieldName  string `json:"fieldName"`
	FieldValue string `json:"fieldValue"`
}

func (q *Queries) GetUserEncryptedData(ctx context.Context, arg GetUserEncryptedDataParams) ([]GetUserEncryptedDataRow, error) {
	rows, err := q.db.QueryContext(ctx, getUserEncryptedData, arg.UserID, arg.CredentialID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetUserEncryptedDataRow{}
	for rows.Next() {
		var i GetUserEncryptedDataRow
		if err := rows.Scan(&i.FieldName, &i.FieldValue); err != nil {
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
