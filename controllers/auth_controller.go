package controllers

import (
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
	"yeebotech-auth/config"
	"yeebotech-auth/models"
	"yeebotech-auth/utils"
)

// RegisterInput 定义注册的输入参数
type RegisterInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Register godoc
// @Summary 用户注册
// @Description 用户通过用户名和密码进行注册
// @Tags 用户
// @Accept json
// @Produce json
// @Param body body RegisterInput true "注册信息"
// @Success 200 {object} map[string]interface{} "User registered successfully"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 500 {object} map[string]interface{} "Failed to register user"
// @Router /register [post]
func Register(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 检查用户名是否已存在
	if err := config.DB.Where("username = ?", user.Username).First(&user).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	// 密码加密
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt password"})
		return
	}
	user.Password = string(hashedPassword)

	// 保存用户到数据库
	if err := config.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

// LoginInput 定义登录的输入参数
type LoginInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login godoc
// @Summary 用户登录
// @Description 用户通过用户名和密码进行登录
// @Tags 用户
// @Accept json
// @Produce json
// @Param body body LoginInput true "登录信息"
// @Success 200 {object} map[string]interface{} "token"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Invalid password"
// @Router /login [post]
func Login(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	config.DB.Where("username = ?", input.Username).First(&user)
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	token, _ := utils.GenerateToken(user.ID)
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// GetProfile godoc
// @Summary 获取用户信息
// @Description 获取当前登录用户的信息
// @Tags 用户
// @Security ApiKeyAuth
// @Produce json
// @Param userID path int true "User ID"  // 描述路径参数 userID
// @Success 200 {object} map[string]interface{} "用户信息"
// @Router /profile [get]
func GetProfile(c *gin.Context) {
	userID := c.MustGet("userID").(uint)
	var user models.User
	config.DB.First(&user, userID)

	c.JSON(http.StatusOK, gin.H{"user": user})
}

// RefreshTokenInput 定义刷新 Token 的输入参数
type RefreshTokenInput struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// RefreshToken godoc
// @Summary 刷新 Token
// @Description 使用刷新 Token 获取新的访问 Token
// @Tags 用户
// @Accept json
// @Produce json
// @Param body body RefreshTokenInput true "刷新信息"
// @Success 200 {object} map[string]interface{} "New token"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Invalid refresh token"
// @Router /refresh-token [post]
func RefreshToken(c *gin.Context) {
	var request RefreshTokenInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证并解析刷新 token
	claims, err := utils.ParseToken(request.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// 生成新的访问 token
	newToken, err := utils.GenerateToken(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": newToken})
}

// CheckTokenRequest 定义检查 Token 的请求体
type CheckTokenRequest struct {
	Token string `json:"token" example:"your_jwt_token_here"`
}

// CheckToken godoc
// @Summary 检查 Token 是否快过期
// @Description 检查当前 Token 的有效时间
// @Tags 用户
// @Accept json
// @Produce json
// @Param body body CheckTokenRequest true "Token"
// @Success 200 {object} map[string]interface{} "Token status"
// @Failure 400 {object} map[string]interface{} "Invalid input"
// @Failure 401 {object} map[string]interface{} "Invalid token"
// @Router /check-token [post]
func CheckToken(c *gin.Context) {
	var request CheckTokenRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token := request.Token
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	claims, err := utils.ParseToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// 计算剩余有效时间
	expirationTime := time.Unix(claims.ExpiresAt, 0)
	timeLeft := expirationTime.Sub(time.Now())

	c.JSON(http.StatusOK, gin.H{"expires_in": timeLeft.Seconds()})
}
