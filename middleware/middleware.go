package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/c4p741nth/Exam_Backend/initializers"
	"github.com/c4p741nth/Exam_Backend/models"
	"github.com/c4p741nth/Exam_Backend/utils"
	"github.com/gin-gonic/gin"
)

func MiddlewareUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var token string
		//cookie, err := ctx.Cookie("token")

		authorizationHeader := ctx.Request.Header.Get("Authorization")
		fields := strings.Fields(authorizationHeader)

		if len(fields) != 2 || fields[0] != "Bearer" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		token = fields[1]

		if token == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": "You are not logged in"})
			return
		}

		config, _ := initializers.LoadConfig(".")
		sub, err := utils.ValidateToken(token, config.TokenSecret)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": err.Error()})
			return
		}

		var tokenData models.Token
		//var tokenData models.Token
		checkUserID := initializers.DB.First(&tokenData, "user_id = ?", fmt.Sprint(sub))

		if checkUserID.Error != nil {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": "the user belonging to this token no logger exists"})
			return
		}

		checkToken := initializers.DB.First(&tokenData, "token = ?", token)

		if checkToken.Error != nil {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "fail", "message": "this token no logger exists"})
			return
		}

		ctx.Set("currentUser", tokenData)
		ctx.Next()
	}
}
