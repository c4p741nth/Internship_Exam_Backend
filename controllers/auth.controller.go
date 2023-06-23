package controllers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/c4p741nth/Exam_Backend/constants"
	"github.com/c4p741nth/Exam_Backend/initializers"
	"github.com/c4p741nth/Exam_Backend/models"
	"github.com/c4p741nth/Exam_Backend/utils"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthController struct {
	DB *gorm.DB
}

func NewAuthController(DB *gorm.DB) AuthController {
	return AuthController{DB}
}

// [...] SignUp User
func (ac *AuthController) Register(ctx *gin.Context) {
	var payload *models.RegisterInput

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
		return
	}

	if payload.Password != payload.PasswordConfirm {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Passwords do not match"})
		return
	}

	hashedPassword, err := utils.HashPassword(payload.Password)
	if err != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"status": "error", "message": err.Error()})
		return
	}

	now := time.Now().Unix()
	newUser := models.User{
		PrefixName: payload.PrefixName,
		FirstName:  payload.Firstname,
		Lastname:   payload.Lastname,
		CitizenID:  payload.CitizenID,
		Password:   hashedPassword,
		Email:      payload.Email,
		Role:       int(constants.Customer),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	result := ac.DB.Create(&newUser)

	if result.Error != nil && strings.Contains(result.Error.Error(), "duplicate key value violates unique") {
		ctx.JSON(http.StatusConflict, gin.H{"status": "fail", "message": "User with that email already exists"})
		return
	} else if result.Error != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"status": "error", "message": "Something bad happened"})
		return
	}

	config, _ := initializers.LoadConfig(".")

	ac.DB.Save(newUser)

	var firstName = newUser.FirstName
	var lastName = newUser.Lastname
	var email = newUser.Email
	var citizenid = newUser.CitizenID
	var password = payload.Password

	if strings.Contains(firstName, " ") {
		firstName = strings.Split(firstName, " ")[1]
	}

	// ? Send Email
	emailData := utils.EmailData{
		URL:       config.ClientOrigin + "/login",
		FirstName: firstName,
		Lastname:  lastName,
		Email:     email,
		CitizenID: citizenid,
		Password:  password,
		Subject:   "Registration Completed",
	}

	utils.SendEmail(&newUser, &emailData)

	message := "We sent an email with a verification code to " + newUser.Email
	ctx.JSON(http.StatusCreated, gin.H{"status": "success", "message": message})
}

// [...] SignIn User
func (ac *AuthController) Login(ctx *gin.Context) {
	var payload models.LoginInput
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
		return
	}

	var userData models.User
	var result *gorm.DB
	var tokenData models.Token
	if strings.Contains(payload.Username, "@") {
		result = ac.DB.Where("email = ?", strings.ToLower(payload.Username)).First(&userData)
	} else {
		result = ac.DB.Where("citizen_id = ?", payload.Username).First(&userData)
	}

	if result.Error != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Invalid email or Password"})
		return
	}

	if err := utils.VerifyPassword(userData.Password, payload.Password); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Invalid email or Password"})
		return
	}

	config, _ := initializers.LoadConfig(".")

	// Generate token that expire in 24 hours
	token, err := utils.GenerateToken(config.TokenExpiresIn, userData.ID, config.TokenSecret)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
		return
	}

	tokenData = models.Token{
		User_ID:   userData.ID.String(),
		Token:     token,
		CreatedAt: time.Now().Unix(),
	}

	if ac.DB.Where("user_id = ?", userData.ID) != nil {
		ac.DB.Model(&tokenData).Where("user_id = ?", userData.ID).Delete(&tokenData)
	}

	ac.DB.Save(&tokenData)

	ctx.JSON(http.StatusOK, gin.H{"status": "success", "token": token, "position": userData.Role})
}

func (ac *AuthController) GetUserDataByTokenFromFront(ctx *gin.Context) {
	getUserDataByToken := ac.GetUserDataByToken(ctx)

	userData := models.User{
		ID:         getUserDataByToken.ID,
		PrefixName: getUserDataByToken.PrefixName,
		FirstName:  getUserDataByToken.FirstName,
		Lastname:   getUserDataByToken.Lastname,
		Email:      getUserDataByToken.Email,
		Role:       getUserDataByToken.Role,
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "success", "firstname": userData.FirstName, "lastname": userData.Lastname, "role": userData.Role})
}

// [...] Forgot Password
func (ac *AuthController) ForgotPassword(ctx *gin.Context) {
	var payload *models.ForgotPasswordInput

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
		return
	}

	// Check if the user exists in the database
	var userData models.User
	if strings.Contains(payload.Email, "@") {
		result := ac.DB.Where("email = ?", strings.ToLower(payload.Email)).First(&userData)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				ctx.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "User does not exist"})
			} else {
				ctx.JSON(http.StatusBadGateway, gin.H{"status": "error", "message": "Something bad happened"})
			}
			return
		}
	} else {
		result := ac.DB.Where("citizen_id = ?", payload.Email).First(&userData)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				ctx.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "User does not exist"})
			} else {
				ctx.JSON(http.StatusBadGateway, gin.H{"status": "error", "message": "Something bad happened"})
			}
			return
		}
	}

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
		return
	}

	hashedPassword, err := utils.HashPassword(payload.Password)
	if err != nil {
		ctx.JSON(http.StatusBadGateway, gin.H{"status": "error", "message": err.Error()})
		return
	}

	resetPassword := models.User{
		Email:    payload.Email,
		Password: hashedPassword,
	}

	var tokenData *models.Token
	userData.UpdatedAt = time.Now().Unix()
	userData.Password = resetPassword.Password
	ac.DB.Save(&userData)
	ac.DB.Model(&tokenData).Where("user_id = ?", userData.ID).Delete(&tokenData)

	ctx.JSON(http.StatusOK, gin.H{"status": "success", "message": "Reset Password Completed"})
}

// [...] SignOut User
func (ac *AuthController) LogoutUser(ctx *gin.Context) {
	userID := GetUserIDByToken(ctx)
	var tokenData *models.Token
	if ac.DB.First(&tokenData, "user_id", userID).Delete(&tokenData).Error != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"status": "fail", "message": "You're already logged out"})
		return
	} else {
		ctx.JSON(http.StatusOK, gin.H{"status": "success"})
	}
}

func GetUserIDByToken(ctx *gin.Context) (response string) {
	var token string
	authorizationHeader := ctx.Request.Header.Get("Authorization")
	fields := strings.Fields(authorizationHeader)

	if authorizationHeader == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	if len(fields) != 2 || fields[0] != "Bearer" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	token = fields[1]

	config, _ := initializers.LoadConfig(".")
	sub, err := utils.ValidateToken(token, config.TokenSecret)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "fail", "message": err.Error()})
		return
	}

	useridstring := fmt.Sprint(sub)
	// fmt.Println(useridstring)
	return useridstring
}

func (ac *AuthController) GetUserDataByToken(ctx *gin.Context) (res models.User) {
	authorizationHeader := ctx.GetHeader("Authorization")
	if authorizationHeader == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	fields := strings.Fields(authorizationHeader)
	if len(fields) != 2 || fields[0] != "Bearer" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	config, err := initializers.LoadConfig(".")
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	sub, err := utils.ValidateToken(fields[1], config.TokenSecret)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userID := fmt.Sprint(sub)
	var user models.User
	if err := ac.DB.First(&user, "id = ?", userID).Error; err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	return user
}
