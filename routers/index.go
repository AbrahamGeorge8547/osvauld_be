package routers

import (
	"net/http"
	"osvauld/controllers"
	"osvauld/routers/middleware"

	"github.com/gin-gonic/gin"
)

// RegisterRoutes add all routing list here automatically get main router
func RegisterRoutes(route *gin.Engine) {
	route.NoRoute(func(ctx *gin.Context) {
		ctx.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "Route Not Found"})
	})
	route.GET("/admin", controllers.GetAdminPage)
	route.POST("/admin", controllers.CreateFirstAdmin)
	route.GET("/health", func(ctx *gin.Context) { ctx.JSON(http.StatusOK, gin.H{"live": "ok"}) })
	route.POST("/user/", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.CreateUser)
	route.GET("/user", middleware.JWTAuthMiddleware(), controllers.GetUser)
	route.POST("user/environment", middleware.JWTAuthMiddleware(), controllers.AddEnvironment)
	route.POST("/user/cli-user", middleware.JWTAuthMiddleware(), controllers.CreateCLIUser)
	route.GET("/user/cli-users", middleware.JWTAuthMiddleware(), controllers.GetCliUsers)
	route.POST("/user/temp-login", controllers.TempLogin)
	route.POST("/user/name-availability", middleware.JWTAuthMiddleware(), controllers.CheckUserAvailability)
	route.DELETE("/user/:id", controllers.RemoveUserFromAll)
	route.GET("/user/environments", middleware.JWTAuthMiddleware(), controllers.GetEnvironments)
	route.GET("/user/environment/:id", middleware.JWTAuthMiddleware(), controllers.GetEnvironmentFields)
	route.POST("/user/register", controllers.Register)
	route.POST("/user/challenge", controllers.GetChallenge)
	route.POST("/user/verify", controllers.VerifyChallenge)
	route.GET("/users/signed-up", middleware.JWTAuthMiddleware(), controllers.GetAllSignedUpUsers)
	route.GET("/users/all", middleware.JWTAuthMiddleware(), controllers.GetAllUsers)
	route.POST("/folder", middleware.JWTAuthMiddleware(), controllers.CreateFolder)
	route.GET("/folder/:id/credential", middleware.JWTAuthMiddleware(), controllers.GetCredentialsByFolder)
	route.GET("/folders", middleware.JWTAuthMiddleware(), controllers.FetchAccessibleFoldersForUser)

	route.POST("/share-credentials/users", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.ShareCredentialsWithUsers)
	route.POST("/share-credentials/groups", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.ShareCredentialsWithGroups)
	route.POST("/share-credentials/environment", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.ShareCredentialsWithEnvironment)
	route.POST("share-folder/users", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.ShareFolderWithUsers)
	route.POST("share-folder/groups", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.ShareFolderWithGroups)

	route.POST("/credential", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.AddCredential)
	route.GET("/credential/:id", middleware.JWTAuthMiddleware(), controllers.GetCredentialDataByID)
	route.PUT("/credential/:id", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.EditCredential)
	route.PUT("/credential/:id/details", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.EditCredentialDetails)
	route.GET("/credential/:id/sensitive", middleware.JWTAuthMiddleware(), controllers.GetSensitiveFieldsByCredentialID)

	route.GET("/credential/:id/users-data-sync", middleware.JWTAuthMiddleware(), controllers.GetCredentialUsersForDataSync)
	route.GET("/credential/:id/groups", middleware.JWTAuthMiddleware(), controllers.GetCredentialGroups)
	route.GET("/credential/:id/users", middleware.JWTAuthMiddleware(), controllers.GetCredentialUsersWithDirectAccess)

	route.GET("/folder/:id/users-data-sync", middleware.JWTAuthMiddleware(), controllers.GetFolderUsersForDataSync)
	route.GET("/folder/:id/users", middleware.JWTAuthMiddleware(), controllers.GetFolderUsersWithDirectAccess)
	route.GET("/folder/:id/groups", middleware.JWTAuthMiddleware(), controllers.GetFolderGroups)
	route.DELETE("/folder/:id", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware("id"), controllers.RemoveFolder)

	route.POST("/group", middleware.JWTAuthMiddleware(), controllers.CreateGroup)
	route.GET("/group/:groupId", middleware.JWTAuthMiddleware(), controllers.GetGroupMembers)

	route.GET("/groups", middleware.JWTAuthMiddleware(), controllers.GetUserGroups)
	route.POST("/group/members", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.AddMemberToGroup)
	// TODO: maybe change the route to include groupId and memberId
	route.DELETE("/group/member", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.RemoveMemberFromGroup)
	route.DELETE("/group/:groupId", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware("groupId"), controllers.RemoveGroup)
	route.POST("/groups/members", middleware.JWTAuthMiddleware(), controllers.GetUsersOfGroups)
	route.GET("/groups/without-access/:folderId", middleware.JWTAuthMiddleware(), controllers.GetGroupsWithoutAccess)

	route.GET("/credentials/fields/:folderId", middleware.JWTAuthMiddleware(), controllers.GetCredentialsFieldsByFolderID)
	route.POST("/credentials/fields/", middleware.JWTAuthMiddleware(), controllers.GetCredentialsFieldsByIds)
	route.POST("/credentials/by-ids", middleware.JWTAuthMiddleware(), controllers.GetCredentialsByIDs)
	route.GET("/credentials/search", middleware.JWTAuthMiddleware(), controllers.GetSearchData)
	route.GET("/urls", middleware.JWTAuthMiddleware(), controllers.GetAllUrlsForUser)

	route.GET("/group/:groupId/credential-fields", middleware.JWTAuthMiddleware(), controllers.GetAllCredentialFieldsByGroupID)
	route.GET("/groups/:groupId/users/without-access", middleware.JWTAuthMiddleware(), controllers.GetUsersWithoutGroupAccess)

	route.POST("/credential/:id/remove-user-access", middleware.JWTAuthMiddleware(), controllers.RemoveCredentialAccessForUsers)
	route.POST("/credential/:id/remove-group-access", middleware.JWTAuthMiddleware(), controllers.RemoveCredentialAccessForGroups)
	route.DELETE("/credential/:id", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware("id"), controllers.RemoveCredential)

	route.POST("/folder/:id/remove-user-access", middleware.JWTAuthMiddleware(), controllers.RemoveFolderAccessForUsers)
	route.POST("/folder/:id/remove-group-access", middleware.JWTAuthMiddleware(), controllers.RemoveFolderAccessForGroups)

	route.POST("/credential/:id/edit-user-access", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.EditCredentialAccessForUser)
	route.POST("/credential/:id/edit-group-access", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.EditCredentialAccessForGroup)

	route.POST("/folder/:id/edit-user-access", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.EditFolderAccessForUser)
	route.POST("/folder/:id/edit-group-access", middleware.JWTAuthMiddleware(), middleware.SignatureMiddleware(), controllers.EditFolderAccessForGroup)

	route.PUT("/folder/:id", middleware.JWTAuthMiddleware(), controllers.EditFolder)
	route.PUT("/group/:id", middleware.JWTAuthMiddleware(), controllers.EditGroup)

	route.GET("/environment/:name", middleware.JWTAuthMiddleware(), controllers.GetEnvironmentByName)

	route.POST("/environment/edit-field-name", middleware.JWTAuthMiddleware(), controllers.EditEnvironmentFieldName)
	route.GET("/environments/:credentialId/fields", middleware.JWTAuthMiddleware(), controllers.GetCredentialEnvFieldsForEditDataSync)
	route.GET("/environments/:credentialId", middleware.JWTAuthMiddleware(), controllers.GetEnvsForCredential)

}
