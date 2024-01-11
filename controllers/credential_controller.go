package controllers

import (
	"errors"
	"net/http"
	"osvauld/customerrors"
	dto "osvauld/dtos"
	"osvauld/service"
	"osvauld/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func AddCredential(ctx *gin.Context) {

	var req dto.AddCredentialDto
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	caller, err := utils.FetchUserIDFromCtx(ctx)
	if err != nil {
		SendResponse(ctx, 401, nil, "Unauthorized", errors.New("unauthorized"))
		return
	}

	req.CreatedBy = caller

	credentialID, err := service.AddCredential(ctx, req)
	if err != nil {
		SendResponse(ctx, 500, nil, "Failed to add credential", errors.New("failed to add credential"))
		return
	}
	SendResponse(ctx, 200, credentialID, "Added credential", nil)
}

func FetchCredentialByID(ctx *gin.Context) {
	userIdInterface, _ := ctx.Get("userId")
	userID, _ := userIdInterface.(uuid.UUID)
	credentialIDStr := ctx.Param("id")
	credentailaID, _ := uuid.Parse(credentialIDStr)
	credential, err := service.FetchCredentialByID(ctx, credentailaID, userID)
	if err != nil {
		if _, ok := err.(*customerrors.UserNotAuthenticatedError); ok {
			SendResponse(ctx, 401, nil, "Unauthorized", errors.New("unauthorized"))
			return
		}
		SendResponse(ctx, 200, nil, "Failed to fetch credential", errors.New("failed to fetch credential"))
		return
	}
	SendResponse(ctx, 200, credential, "Fetched credential", nil)
}

func GetCredentialsByFolder(ctx *gin.Context) {
	// Parse user_id from headerss
	userIdInterface, _ := ctx.Get("userId")
	userID, _ := userIdInterface.(uuid.UUID)
	// Get folder_id from query params
	folderIDStr := ctx.Param("id")
	folderID, err := uuid.Parse(folderIDStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid folder_id query parameter."})
		return
	}
	credentials, err := service.GetCredentialsByFolder(ctx, folderID, userID)
	if err != nil {
		SendResponse(ctx, 500, nil, "Failed to fetch credential", errors.New("failed to fetch credential"))
		return
	}
	SendResponse(ctx, 200, credentials, "Fetched credentials", nil)

}

func GetAllEncryptedCredentailsForFolderID(ctx *gin.Context) {
	userIdInterface, _ := ctx.Get("userId")
	userID, _ := userIdInterface.(uuid.UUID)
	folderIDStr := ctx.Param("folderId")
	folderID, _ := uuid.Parse(folderIDStr)
	credential, err := service.GetEncryptedCredentials(ctx, folderID, userID)
	if err != nil {
		SendResponse(ctx, 200, nil, "Failed to fetch credential", errors.New("failed to fetch credential"))
		return
	}
	SendResponse(ctx, 200, credential, "Fetched credential", nil)
}

func GetEncryptedCredentailsByIds(ctx *gin.Context) {
	userIdInterface, _ := ctx.Get("userId")
	userID, _ := userIdInterface.(uuid.UUID)
	var req dto.GetEncryptedCredentialsByIdsRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	credentials, err := service.GetEncryptedCredentialsByIds(ctx, req.CredentialIds, userID)
	if err != nil {
		SendResponse(ctx, 200, nil, "Failed to fetch credential", errors.New("failed to fetch credential"))
		return
	}
	SendResponse(ctx, 200, credentials, "Fetched credential", nil)
}
