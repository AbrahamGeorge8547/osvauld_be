// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.24.0
// source: folder.sql

package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const addFolder = `-- name: AddFolder :one
INSERT INTO folders (name, description, created_by)
VALUES ($1, $2, $3)
RETURNING id, created_at
`

type AddFolderParams struct {
	Name        string         `json:"name"`
	Description sql.NullString `json:"description"`
	CreatedBy   uuid.UUID      `json:"createdBy"`
}

type AddFolderRow struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
}

func (q *Queries) AddFolder(ctx context.Context, arg AddFolderParams) (AddFolderRow, error) {
	row := q.db.QueryRowContext(ctx, addFolder, arg.Name, arg.Description, arg.CreatedBy)
	var i AddFolderRow
	err := row.Scan(&i.ID, &i.CreatedAt)
	return i, err
}

const addFolderAccess = `-- name: AddFolderAccess :exec
INSERT INTO folder_access (folder_id, user_id, access_type, group_id)
VALUES ($1, $2, $3, $4)
`

type AddFolderAccessParams struct {
	FolderID   uuid.UUID     `json:"folderId"`
	UserID     uuid.UUID     `json:"userId"`
	AccessType string        `json:"accessType"`
	GroupID    uuid.NullUUID `json:"groupId"`
}

func (q *Queries) AddFolderAccess(ctx context.Context, arg AddFolderAccessParams) error {
	_, err := q.db.ExecContext(ctx, addFolderAccess,
		arg.FolderID,
		arg.UserID,
		arg.AccessType,
		arg.GroupID,
	)
	return err
}

const checkFolderAccessEntryExists = `-- name: CheckFolderAccessEntryExists :one
SELECT EXISTS (
    SELECT 1
    FROM folder_access
    WHERE user_id = $1 AND folder_id = $2 
    AND ((group_id IS NOT NULL AND group_id = $3) OR (group_id is null and $3 is null)) 
)
`

type CheckFolderAccessEntryExistsParams struct {
	UserID   uuid.UUID     `json:"userId"`
	FolderID uuid.UUID     `json:"folderId"`
	GroupID  uuid.NullUUID `json:"groupId"`
}

func (q *Queries) CheckFolderAccessEntryExists(ctx context.Context, arg CheckFolderAccessEntryExistsParams) (bool, error) {
	row := q.db.QueryRowContext(ctx, checkFolderAccessEntryExists, arg.UserID, arg.FolderID, arg.GroupID)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const fetchAccessibleFoldersForUser = `-- name: FetchAccessibleFoldersForUser :many
SELECT id, name, description, created_at, created_by
FROM folders
WHERE id IN (
  SELECT DISTINCT(folder_id)
  FROM folder_access
  WHERE folder_access.user_id = $1
  UNION
  SELECT DISTINCT(c.folder_id)
  FROM credentials as c
  JOIN credential_access as a ON c.id = a.credential_id
  WHERE a.user_id = $1
)
`

type FetchAccessibleFoldersForUserRow struct {
	ID          uuid.UUID      `json:"id"`
	Name        string         `json:"name"`
	Description sql.NullString `json:"description"`
	CreatedAt   time.Time      `json:"createdAt"`
	CreatedBy   uuid.UUID      `json:"createdBy"`
}

func (q *Queries) FetchAccessibleFoldersForUser(ctx context.Context, userID uuid.UUID) ([]FetchAccessibleFoldersForUserRow, error) {
	rows, err := q.db.QueryContext(ctx, fetchAccessibleFoldersForUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []FetchAccessibleFoldersForUserRow{}
	for rows.Next() {
		var i FetchAccessibleFoldersForUserRow
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Description,
			&i.CreatedAt,
			&i.CreatedBy,
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

const getAccessTypeAndUserByFolder = `-- name: GetAccessTypeAndUserByFolder :many
SELECT user_id, access_type
FROM folder_access
WHERE folder_id = $1
`

type GetAccessTypeAndUserByFolderRow struct {
	UserID     uuid.UUID `json:"userId"`
	AccessType string    `json:"accessType"`
}

func (q *Queries) GetAccessTypeAndUserByFolder(ctx context.Context, folderID uuid.UUID) ([]GetAccessTypeAndUserByFolderRow, error) {
	rows, err := q.db.QueryContext(ctx, getAccessTypeAndUserByFolder, folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetAccessTypeAndUserByFolderRow{}
	for rows.Next() {
		var i GetAccessTypeAndUserByFolderRow
		if err := rows.Scan(&i.UserID, &i.AccessType); err != nil {
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

const getFolderAccessForUser = `-- name: GetFolderAccessForUser :many
SELECT access_type FROM folder_access
WHERE folder_id = $1 AND user_id = $2
`

type GetFolderAccessForUserParams struct {
	FolderID uuid.UUID `json:"folderId"`
	UserID   uuid.UUID `json:"userId"`
}

func (q *Queries) GetFolderAccessForUser(ctx context.Context, arg GetFolderAccessForUserParams) ([]string, error) {
	rows, err := q.db.QueryContext(ctx, getFolderAccessForUser, arg.FolderID, arg.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []string{}
	for rows.Next() {
		var access_type string
		if err := rows.Scan(&access_type); err != nil {
			return nil, err
		}
		items = append(items, access_type)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getSharedGroupsForFolder = `-- name: GetSharedGroupsForFolder :many
SELECT g.id, g.name, f.access_type
FROM folder_access AS f JOIN groupings AS g ON f.group_id = g.id
WHERE f.folder_id = $1
group by g.id, g.name, f.access_type
`

type GetSharedGroupsForFolderRow struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	AccessType string    `json:"accessType"`
}

func (q *Queries) GetSharedGroupsForFolder(ctx context.Context, folderID uuid.UUID) ([]GetSharedGroupsForFolderRow, error) {
	rows, err := q.db.QueryContext(ctx, getSharedGroupsForFolder, folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetSharedGroupsForFolderRow{}
	for rows.Next() {
		var i GetSharedGroupsForFolderRow
		if err := rows.Scan(&i.ID, &i.Name, &i.AccessType); err != nil {
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

const getSharedUsersForFolder = `-- name: GetSharedUsersForFolder :many
SELECT users.id, users.name, users.username, COALESCE(users.encryption_key,'') as "publicKey", folder_access.access_type as "accessType"
FROM folder_access
JOIN users ON folder_access.user_id = users.id
WHERE folder_access.folder_id = $1
`

type GetSharedUsersForFolderRow struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Username   string    `json:"username"`
	PublicKey  string    `json:"publicKey"`
	AccessType string    `json:"accessType"`
}

func (q *Queries) GetSharedUsersForFolder(ctx context.Context, folderID uuid.UUID) ([]GetSharedUsersForFolderRow, error) {
	rows, err := q.db.QueryContext(ctx, getSharedUsersForFolder, folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetSharedUsersForFolderRow{}
	for rows.Next() {
		var i GetSharedUsersForFolderRow
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Username,
			&i.PublicKey,
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

const hasOwnerAccessForFolder = `-- name: HasOwnerAccessForFolder :one
SELECT EXISTS (
  SELECT 1 FROM folder_access
  WHERE folder_id = $1 AND user_id = $2 AND access_type = 'owner'
)
`

type HasOwnerAccessForFolderParams struct {
	FolderID uuid.UUID `json:"folderId"`
	UserID   uuid.UUID `json:"userId"`
}

func (q *Queries) HasOwnerAccessForFolder(ctx context.Context, arg HasOwnerAccessForFolderParams) (bool, error) {
	row := q.db.QueryRowContext(ctx, hasOwnerAccessForFolder, arg.FolderID, arg.UserID)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}

const isUserManagerOrOwner = `-- name: IsUserManagerOrOwner :one
SELECT EXISTS (
  SELECT 1 FROM folder_access
  WHERE folder_id = $1 AND user_id = $2 AND access_type IN ('owner', 'manager')
)
`

type IsUserManagerOrOwnerParams struct {
	FolderID uuid.UUID `json:"folderId"`
	UserID   uuid.UUID `json:"userId"`
}

func (q *Queries) IsUserManagerOrOwner(ctx context.Context, arg IsUserManagerOrOwnerParams) (bool, error) {
	row := q.db.QueryRowContext(ctx, isUserManagerOrOwner, arg.FolderID, arg.UserID)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}
