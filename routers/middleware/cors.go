package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func CORSMiddleware() gin.HandlerFunc {
	allowedOrigins := []string{
		"http://localhost:5173",
		"tauri://localhost",
	}
	return func(ctx *gin.Context) {
		origin := ctx.Request.Header.Get("Origin")
		fmt.Printf("CORS Middleware - Request URL: %s\n", ctx.Request.URL.String())
		fmt.Printf("CORS Middleware - Origin: %s\n", origin)

		// Check if the Origin is in the allowed list
		isAllowed := false
		for _, o := range allowedOrigins {
			if o == origin {
				isAllowed = true
				break
			}
		}

		if isAllowed {
			ctx.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			ctx.Writer.Header().Set("Access-Control-Allow-Origin", "null")
		}
		ctx.Writer.Header().Set("Access-Control-Max-Age", "86400")
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, api_key, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Signature")
		ctx.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		ctx.Writer.Header().Set("Access-Control-Allow-Credentials", "true") // Changed to true
		ctx.Writer.Header().Set("Cache-Control", "no-cache")

		if ctx.Request.Method == "OPTIONS" {
			ctx.AbortWithStatus(204)
		} else {
			ctx.Next()
		}
	}
}
