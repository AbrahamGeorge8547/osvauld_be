package service

import (
	"database/sql"
	"osvauld/customerrors"
	db "osvauld/db/sqlc"
	dto "osvauld/dtos"
	"osvauld/infra/logger"
	"osvauld/repository"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func AddCredential(ctx *gin.Context, request dto.AddCredentialRequest, caller uuid.UUID) (uuid.UUID, error) {

	isOwner, err := CheckFolderOwner(ctx, request.FolderID, caller)
	if err != nil {
		return uuid.UUID{}, err
	}
	if !isOwner {
		return uuid.UUID{}, &customerrors.UserNotAuthenticatedError{Message: "user does not have owner access to the folder"}
	}

	// Retrieve access types for the folder
	accessList, err := repository.GetFolderAccess(ctx, request.FolderID)
	if err != nil {
		return uuid.UUID{}, err
	}

	accessTypeMap := make(map[uuid.UUID]string)

	for _, access := range accessList {
		if access.UserID != caller {
			accessTypeMap[access.UserID] = access.AccessType

			// TODO: this check is redundant since only owner can add credentials
		} else {
			//caller should be owner
			accessTypeMap[access.UserID] = "owner"
		}
	}

	/* Convert UserFields to UserFieldsWithAccessType
	 * access type is derived from the users forlder access
	 */
	var UserFieldsWithAccessTypeSlice []dto.UserFieldsWithAccessType
	for _, userFields := range request.UserFields {
		accessType, exists := accessTypeMap[userFields.UserID]
		if !exists {
			// TODO: send appropriate error
			continue
		}
		userFieldsWithAccessType := dto.UserFieldsWithAccessType{
			UserID:     userFields.UserID,
			Fields:     userFields.Fields,
			AccessType: accessType,
		}

		UserFieldsWithAccessTypeSlice = append(UserFieldsWithAccessTypeSlice, userFieldsWithAccessType)
	}

	payload := db.AddCredentialTransactionParams{
		Name:                     request.Name,
		Description:              sql.NullString{String: request.Description, Valid: true},
		FolderID:                 request.FolderID,
		CredentialType:           request.CredentialType,
		CreatedBy:                caller,
		UserFieldsWithAccessType: UserFieldsWithAccessTypeSlice,
	}

	credentialID, err := repository.AddCredential(ctx, payload)
	if err != nil {
		return uuid.UUID{}, err
	}
	return credentialID, nil
}

// GetCredentialByID returns the credential details and non sensitive fields for the given credentialID
func GetCredentialDataByID(ctx *gin.Context, credentialID uuid.UUID, caller uuid.UUID) (dto.CredentialForUser, error) {

	accessType, err := GetAccessTypeForCredential(ctx, credentialID, caller)
	if err != nil {
		return dto.CredentialForUser{}, err
	}

	if !CheckHasReadAccessForCredential(ctx, accessType) {
		logger.Errorf("user %s does not have access to the credential %s", caller, credentialID)
		return dto.CredentialForUser{}, &customerrors.UserNotAuthenticatedError{Message: "user does not have access to the credential"}
	}

	credential, err := repository.GetCredentialDataByID(ctx, credentialID)
	if err != nil {
		return dto.CredentialForUser{}, err
	}

	fields, err := repository.GetNonSensitiveFieldsForCredentialIDs(ctx, db.GetNonSensitiveFieldsForCredentialIDsParams{
		Credentials: []uuid.UUID{credentialID},
		UserID:      caller,
	})
	if err != nil {
		return dto.CredentialForUser{}, err
	}

	fieldDtos := []dto.Field{}
	for _, field := range fields {
		fieldDtos = append(fieldDtos, dto.Field{
			ID:         field.ID,
			FieldName:  field.FieldName,
			FieldValue: field.FieldValue,
			FieldType:  field.FieldType,
		})
	}

	credentialDetails := dto.CredentialForUser{
		CredentialID:   credential.ID,
		Name:           credential.Name,
		Description:    credential.Description.String,
		CredentialType: credential.CredentialType,
		AccessType:     accessType,
		FolderID:       credential.FolderID,
		CreatedAt:      credential.CreatedAt,
		UpdatedAt:      credential.UpdatedAt,
		CreatedBy:      credential.CreatedBy,
		Fields:         fieldDtos,
	}
	return credentialDetails, err
}

func GetUniqueCredentialsWithHighestAccess(credentials []db.FetchCredentialDetailsForUserByFolderIdRow) []db.FetchCredentialDetailsForUserByFolderIdRow {
	credentialMap := make(map[uuid.UUID]db.FetchCredentialDetailsForUserByFolderIdRow)
	for _, credential := range credentials {
		if _, ok := credentialMap[credential.CredentialID]; ok {

			existingAccessType := credentialMap[credential.CredentialID].AccessType
			newAccessType := credential.AccessType

			if CredentialAccessLevels[newAccessType] > CredentialAccessLevels[existingAccessType] {
				credentialMap[credential.CredentialID] = credential
			}
		} else {
			credentialMap[credential.CredentialID] = credential
		}
	}

	uniqueCredentials := []db.FetchCredentialDetailsForUserByFolderIdRow{}
	for _, credential := range credentialMap {
		uniqueCredentials = append(uniqueCredentials, credential)
	}

	return uniqueCredentials
}

func GetCredentialsByFolder(ctx *gin.Context, folderID uuid.UUID, userID uuid.UUID) ([]dto.CredentialForUser, error) {

	// Users can have access to only some of the credentials in a folder.
	// So check the access_list table to see which credentials the user has access to
	credentialDetails, err := repository.FetchCredentialDetailsForUserByFolderId(ctx, db.FetchCredentialDetailsForUserByFolderIdParams{
		FolderID: folderID,
		UserID:   userID,
	})
	if err != nil {
		return []dto.CredentialForUser{}, err
	}

	uniqueCredentialDetails := GetUniqueCredentialsWithHighestAccess(credentialDetails)

	credentialIDs := []uuid.UUID{}
	for _, credential := range uniqueCredentialDetails {
		credentialIDs = append(credentialIDs, credential.CredentialID)
	}

	FieldsData, err := repository.GetNonSensitiveFieldsForCredentialIDs(ctx, db.GetNonSensitiveFieldsForCredentialIDsParams{
		Credentials: credentialIDs,
		UserID:      userID,
	})
	if err != nil {
		return []dto.CredentialForUser{}, err
	}

	credentialFieldGroups := map[uuid.UUID][]dto.Field{}

	for _, field := range FieldsData {
		// if credential.CredentialID does not exist add it to the map and add the field to the array
		credentialFieldGroups[field.CredentialID] = append(credentialFieldGroups[field.CredentialID], dto.Field{
			ID:         field.ID,
			FieldName:  field.FieldName,
			FieldValue: field.FieldValue,
			FieldType:  field.FieldType,
		})
	}

	credentials := []dto.CredentialForUser{}
	for _, credential := range uniqueCredentialDetails {
		credentialForUser := dto.CredentialForUser{}

		credentialForUser.CredentialID = credential.CredentialID
		credentialForUser.Name = credential.Name
		credentialForUser.Description = credential.Description
		credentialForUser.CredentialType = credential.CredentialType
		credentialForUser.AccessType = credential.AccessType
		credentialForUser.FolderID = folderID
		credentialForUser.CreatedAt = credential.CreatedAt
		credentialForUser.UpdatedAt = credential.UpdatedAt
		credentialForUser.CreatedBy = credential.CreatedBy
		credentialForUser.Fields = credentialFieldGroups[credential.CredentialID]

		credentials = append(credentials, credentialForUser)
	}

	return credentials, nil
}

func GetCredentialsByIDs(ctx *gin.Context, credentialIDs []uuid.UUID, userID uuid.UUID) ([]dto.CredentialForUser, error) {

	// TODO: Add access checks

	FieldsData, err := repository.GetNonSensitiveFieldsForCredentialIDs(ctx, db.GetNonSensitiveFieldsForCredentialIDsParams{
		Credentials: credentialIDs,
		UserID:      userID,
	})
	if err != nil {
		return nil, err
	}
	credentialFieldGroups := map[uuid.UUID][]dto.Field{}

	for _, field := range FieldsData {
		// if credential.CredentialID does not exist add it to the map and add the field to the array
		credentialFieldGroups[field.CredentialID] = append(credentialFieldGroups[field.CredentialID], dto.Field{
			ID:         field.ID,
			FieldName:  field.FieldName,
			FieldValue: field.FieldValue,
			FieldType:  field.FieldType,
		})
	}

	credentialDetails, err := repository.GetCredentialDetailsByIDs(ctx, credentialIDs)

	credentials := []dto.CredentialForUser{}
	for _, credential := range credentialDetails {
		credentialForUser := dto.CredentialForUser{}

		credentialForUser.CredentialID = credential.ID
		credentialForUser.Name = credential.Name
		credentialForUser.Description = credential.Description.String
		credentialForUser.CredentialType = credential.CredentialType
		credentialForUser.FolderID = credential.FolderID
		credentialForUser.CreatedAt = credential.CreatedAt
		credentialForUser.UpdatedAt = credential.UpdatedAt
		credentialForUser.CreatedBy = credential.CreatedBy
		credentialForUser.Fields = credentialFieldGroups[credential.ID]

		credentials = append(credentials, credentialForUser)
	}

	if err != nil {
		return nil, err
	}
	return credentials, nil
}

func GetAllUrlsForUser(ctx *gin.Context, userID uuid.UUID) ([]db.GetAllUrlsForUserRow, error) {
	urls, err := repository.GetAllUrlsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return urls, nil
}

func EditCredential(ctx *gin.Context, credentialID uuid.UUID, request dto.EditCredentialRequest, caller uuid.UUID) error {

	isOwner, err := HasWriteAccessForCredential(ctx, credentialID, caller)
	if err != nil {
		return err
	}
	if !isOwner {
		return &customerrors.UserNotAuthenticatedError{Message: "user does not have manager access to the credential"}
	}

	err = repository.EditCredential(ctx, db.EditCredentialTransactionParams{
		CredentialID:   credentialID,
		Name:           request.Name,
		Description:    sql.NullString{String: request.Description, Valid: true},
		CredentialType: request.CredentialType,
		UserFields:     request.UserFields,
		EditedBy:       caller,
	})

	if err != nil {
		return err
	}

	return nil

}
