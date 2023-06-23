package routes

import (
	"github.com/c4p741nth/Exam_Backend/controllers"
	"github.com/c4p741nth/Exam_Backend/middleware"
	"github.com/gin-gonic/gin"
)

type AuthRouteController struct {
	authController controllers.AuthController
}

func NewAuthRouteController(authController controllers.AuthController) AuthRouteController {
	return AuthRouteController{authController}
}

func (rc *AuthRouteController) AuthRoute(rg *gin.RouterGroup) {
	router := rg.Group("/auth")

	router.POST("/register", rc.authController.Register)
	router.POST("/login", rc.authController.Login)
	router.POST("/logout", middleware.MiddlewareUser(), rc.authController.LogoutUser)
	router.POST("/forgotpassword", rc.authController.ForgotPassword)
	router.GET("/getuserbytoken", middleware.MiddlewareUser(), rc.authController.GetUserDataByTokenFromFront)
}
