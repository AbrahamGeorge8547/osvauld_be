package middleware

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	"osvauld/auth"
	"osvauld/config"
	"osvauld/infra/logger"
	"osvauld/service"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must start with Bearer"})
			return
		}

		claims := &auth.Claims{}

		keyFunc := func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, errors.New("invalid token")
			}
			return []byte(config.GetJWTSecret()), nil
		}

		token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)

		if err != nil {
			logger.Errorf(err.Error())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		if !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			logger.Errorf("Parse UUID error: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID in token"})
			return
		}

		// Token is valid, set the username in the context so it can be used by the route handler if needed
		c.Set("username", claims.Username)
		c.Set("userId", userID)

		c.Next() // Proceed to the route handler
	}
}

func SignatureMiddleware(paramName ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract userId from JWT token
		userId := c.MustGet("userId").(uuid.UUID)

		// Extract signature from header
		signature := c.GetHeader("Signature")
		if signature == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No signature provided"})
			c.Abort()
			return
		}

		var hashedStr string
		if len(paramName) > 0 {
			// Extract the parameter from the route
			paramValue := c.Param(paramName[0])
			if paramValue == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "No parameter provided"})
				c.Abort()
				return
			}

			hashedParam := sha512.Sum512([]byte(paramValue))
			hashedStr = base64.StdEncoding.EncodeToString(hashedParam[:])
		} else {
			// Extract the body
			body, err := c.GetRawData()
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
				c.Abort()
				return
			}

			// Replace the body so it can be read again later
			c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))

			hashedBody := sha512.Sum512([]byte(body))
			hashedStr = base64.StdEncoding.EncodeToString(hashedBody[:])
		}

		// Get the public key
		publicKey, err := service.GetUserDeviceKey(c, userId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get public key"})
			c.Abort()
			return
		}

		// Verify the signature
		isValid, err := auth.VerifySignature(signature, publicKey, hashedStr)
		if err != nil || !isValid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid signature"})
			c.Abort()
			return
		}

		c.Next()
	}
}
