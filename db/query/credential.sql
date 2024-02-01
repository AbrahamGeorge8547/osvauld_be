-- sql/create_credential.sql
-- name: CreateCredential :one
INSERT INTO
    credentials (NAME, description, credential_type, folder_id, created_by)
VALUES
    ($1, $2, $3, $4, $5) RETURNING id;


-- name: FetchCredentialDataByID :one
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
    id = $1;

-- name: FetchCredentialFieldsForUserByCredentialIds :many
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
    AND user_id = $2;


-- name: FetchCredentialDetailsForUserByFolderId :many
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
    AND A.user_id = $2;


-- name: GetCredentialDetails :one
SELECT
    id,
    NAME,
    COALESCE(description, '') AS "description"
FROM
    credentials
WHERE
    id = $1;

-- name: GetUserEncryptedData :many
SELECT
    field_name AS "fieldName",
    field_value AS "fieldValue"
FROM
    encrypted_data
WHERE
    user_id = $1
    AND credential_id = $2;

-- name: GetCredentialUnencryptedData :many
SELECT
    field_name AS "fieldName",
    field_value AS "fieldValue"
FROM
    unencrypted_data
WHERE
    credential_id = $1;

-- name: AddCredential :one
SELECT
    add_credential_with_access($1 :: JSONB);

-- name: GetEncryptedCredentialsByFolder :many
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
    C .id;

-- name: GetCredentialsFieldsByIds :many
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
    e.credential_id;


-- name: GetAllUrlsForUser :many
SELECT DISTINCT
    field_value as value, credential_id as "credentialId"
FROM 
    encrypted_data
WHERE 
    user_id = $1 AND field_name = 'Domain';


-- name: GetCredentialDetailsByIds :many
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
GROUP BY C.id;

-- name: GetSensitiveFields :many
SELECT 
    field_name as "fieldName", 
    field_value as "fieldValue", 
    credential_id as "credentialId"
FROM 
    encrypted_data
WHERE 
    user_id = $1 AND credential_id = $2 AND field_type = 'sensitive';

-- name: GetCredentialIdsByFolder :many
SELECT 
    c.id AS "credentialId"
FROM 
    credentials c
JOIN 
    access_list a ON c.id = a.credential_id
WHERE 
    a.user_id = $1
    AND c.folder_id = $2;

-- name: GetAccessTypeAndUsersByCredentialId :many
SELECT 
    al.user_id as "id",
    u.name, 
    al.access_type,
    COALESCE(u.rsa_pub_key, '') AS "publicKey"
FROM 
    access_list al
JOIN 
    users u ON al.user_id = u.id
WHERE 
    al.credential_id = $1 AND al.group_id IS NULL;

-- name: GetAccessTypeAndGroupsByCredentialId :many
    SELECT DISTINCT
        al.group_id, 
        g.name,
        al.access_type
    FROM 
        access_list al
    JOIN 
        groupings g ON al.group_id = g.id
    WHERE 
        al.credential_id = $1;