package db

import (
	"context"
	"fmt"
	dto "osvauld/dtos"

	"github.com/google/uuid"
)

func (store *SQLStore) ShareCredentialWithUserTransaction(ctx context.Context, args dto.CredentialEncryptedFieldsForUserDto) error {

	err := store.execTx(ctx, func(q *Queries) error {

		// Create encrypted data records
		for _, field := range args.EncryptedFields {
			_, err := q.CreateEncryptedData(ctx, CreateEncryptedDataParams{
				FieldName:    field.FieldName,
				FieldValue:   field.FieldValue,
				CredentialID: args.CredentialID,
				UserID:       args.UserID,
			})
			if err != nil {
				return err
			}
		}

		// Add row in access list
		accessListParams := AddToAccessListParams{
			CredentialID: args.CredentialID,
			UserID:       args.UserID,
			AccessType:   args.AccessType,
		}
		_, err := q.AddToAccessList(ctx, accessListParams)
		if err != nil {
			return err
		}

		return nil
	})

	return err
}

func (store *SQLStore) ShareMultipleCredentialsWithMultipleUsersTransaction(ctx context.Context, args []dto.CredentialEncryptedFieldsForUserDto) error {

	err := store.execTx(ctx, func(q *Queries) error {

		for _, credentialData := range args {

			// Create encrypted data records
			for _, field := range credentialData.EncryptedFields {
				_, err := q.CreateEncryptedData(ctx, CreateEncryptedDataParams{
					FieldName:    field.FieldName,
					FieldValue:   field.FieldValue,
					CredentialID: credentialData.CredentialID,
					UserID:       credentialData.UserID,
				})
				if err != nil {
					return err
				}
			}

			// Add row in access list
			accessListParams := AddToAccessListParams{
				CredentialID: credentialData.CredentialID,
				UserID:       credentialData.UserID,
				AccessType:   credentialData.AccessType,
			}
			_, err := q.AddToAccessList(ctx, accessListParams)
			if err != nil {
				return err
			}

		}

		return nil
	})

	return err
}

func (store *SQLStore) ShareCredentialWithGroupTransaction(ctx context.Context, args dto.CredentialEncryptedFieldsForGroupDto) error {

	err := store.execTx(ctx, func(q *Queries) error {

		// Create encrypted data records
		for _, userData := range args.UserEncryptedFields {
			for _, field := range userData.EncryptedFields {
				_, err := q.CreateEncryptedData(ctx, CreateEncryptedDataParams{
					FieldName:    field.FieldName,
					FieldValue:   field.FieldValue,
					CredentialID: args.CredentialID,
					UserID:       userData.UserID,
				})
				if err != nil {
					return err
				}
			}

			accessListParams := AddToAccessListParams{
				CredentialID: args.CredentialID,
				UserID:       userData.UserID,
				AccessType:   args.AccessType,
				GroupID:      uuid.NullUUID{Valid: true, UUID: args.GroupID},
			}
			_, err := q.AddToAccessList(ctx, accessListParams)
			if err != nil {
				return err
			}
		}

		return nil
	})

	return err
}

func (store *SQLStore) ShareMultipleCredentialsWithMultipleGroupsTransaction(ctx context.Context, args []dto.CredentialEncryptedFieldsForGroupDto) error {

	fmt.Println("started transaction")
	err := store.execTx(ctx, func(q *Queries) error {

		for _, credentialData := range args {
			// Create encrypted data records
			for _, userData := range credentialData.UserEncryptedFields {
				for _, field := range userData.EncryptedFields {
					_, err := q.CreateEncryptedData(ctx, CreateEncryptedDataParams{
						FieldName:    field.FieldName,
						FieldValue:   field.FieldValue,
						CredentialID: credentialData.CredentialID,
						UserID:       userData.UserID,
					})
					if err != nil {
						return err
					}
				}

				accessListParams := AddToAccessListParams{
					CredentialID: credentialData.CredentialID,
					UserID:       userData.UserID,
					AccessType:   credentialData.AccessType,
					GroupID:      uuid.NullUUID{Valid: true, UUID: credentialData.GroupID},
				}
				_, err := q.AddToAccessList(ctx, accessListParams)
				if err != nil {
					return err
				}
			}
		}

		return nil
	})

	fmt.Println("ended transaction")

	return err
}

func (store *SQLStore) ShareFolderWithUsersTransaction(ctx context.Context, folderId uuid.UUID, credentialPayloads []dto.CredentialsForUsersPayload) error {

	err := store.execTx(ctx, func(q *Queries) error {

		for _, credentialPayload := range credentialPayloads {
			userId := credentialPayload.UserID
			accessType := credentialPayload.AccessType
			// Create encrypted data records
			for _, credential := range credentialPayload.CredentialData {
				exists, err := q.CheckAccessListEntryExists(ctx, CheckAccessListEntryExistsParams{
					CredentialID: credential.CredentialID,
					UserID:       userId,
				})
				if err != nil {
					return err
				}
				if !exists {
					for _, field := range credential.EncryptedFields {
						_, err = q.CreateEncryptedData(ctx, CreateEncryptedDataParams{
							FieldName:    field.FieldName,
							FieldValue:   field.FieldValue,
							CredentialID: credential.CredentialID,
							UserID:       userId,
						})
						if err != nil {
							return err
						}
					}
				}
				_, err = q.AddToAccessList(ctx, AddToAccessListParams{
					CredentialID: credential.CredentialID,
					UserID:       userId,
					AccessType:   accessType,
				})
				if err != nil {
					return err
				}
			}
			q.AddFolderAccess(ctx, AddFolderAccessParams{
				FolderID:   folderId,
				UserID:     userId,
				AccessType: accessType,
			})

		}

		return nil
	})

	return err
}
