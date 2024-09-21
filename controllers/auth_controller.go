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

// ApiResult 定义统一返回结构
type ApiResult[T any] struct {
	Status       string     `json:"status"`
	Code         int        `json:"code"`
	Message      string     `json:"message"`
	Data         ApiData[T] `json:"data,omitempty"`
	ErrorDetails string     `json:"error_details,omitempty"`
}

// ApiData 包含实际数据和过期时间
type ApiData[T any] struct {
	Content   interface{} `json:"content"`    // 改为 interface{} 类型
	ExpiresIn int64       `json:"expires_in"` // 以秒为单位的剩余时间
}

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
// @Success 200 {object} ApiResult[string] "User registered successfully"
// @Failure 400 {object} ApiResult[string] "Invalid input"
// @Failure 500 {object} ApiResult[string] "Failed to register user"
// @Router /auth/register [post]
func Register(c *gin.Context) {
	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, ApiResult[any]{Status: "error", Code: 400, Message: err.Error()})
		return
	}

	// 检查用户名是否已存在
	var user models.User
	if err := config.DB.Where("username = ?", input.Username).First(&user).Error; err == nil {
		c.JSON(http.StatusBadRequest, ApiResult[any]{Status: "error", Code: 400, Message: "Username already exists"})
		return
	}

	// 密码加密
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ApiResult[any]{Status: "error", Code: 500, Message: "Failed to encrypt password"})
		return
	}
	user.Username = input.Username
	user.Password = string(hashedPassword)

	// 保存用户到数据库
	if err := config.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, ApiResult[any]{Status: "error", Code: 500, Message: "Failed to register user"})
		return
	}

	c.JSON(http.StatusOK, ApiResult[any]{Status: "success", Code: 200, Message: "User registered successfully"})
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
// @Success 200 {object} ApiResult[string] "token"
// @Failure 400 {object} ApiResult[string] "Invalid input"
// @Failure 401 {object} ApiResult[string] "Invalid password"
// @Router /auth/login [post]
func Login(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, ApiResult[any]{Status: "error", Code: 400, Message: err.Error()})
		return
	}

	var user models.User
	if err := config.DB.Where("username = ?", input.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, ApiResult[any]{Status: "error", Code: 400, Message: "User not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, ApiResult[any]{Status: "error", Code: 401, Message: "Invalid password"})
		return
	}

	token, _ := utils.GenerateToken(user.ID)
	c.JSON(http.StatusOK, ApiResult[string]{Status: "success", Code: 200, Message: "Login successful", Data: ApiData[string]{Content: token}})
}

// GetProfile godoc
// @Summary 获取用户信息
// @Description 获取当前登录用户的信息
// @Tags 用户
// @Security ApiKeyAuth
// @Produce json
// @Param userID path uint true "用户 userID"
// @Success 200 {object} ApiResult[models.User] "用户信息"
// @Router /user/profile [get]
func GetProfile(c *gin.Context) {
	userID := c.MustGet("userID").(uint)
	var user models.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, ApiResult[any]{Status: "error", Code: 404, Message: "User not found"})
		return
	}

	c.JSON(http.StatusOK, ApiResult[models.User]{Status: "success", Code: 200, Message: "User profile retrieved", Data: ApiData[models.User]{Content: user}})
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
// @Success 200 {object} ApiResult[string] "New token"
// @Failure 400 {object} ApiResult[string] "Invalid input"
// @Failure 401 {object} ApiResult[string] "Invalid refresh token"
// @Router /auth/refresh-token [post]
func RefreshToken(c *gin.Context) {
	var request RefreshTokenInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, ApiResult[any]{Status: "error", Code: 400, Message: err.Error()})
		return
	}

	// 验证并解析刷新 token
	claims, err := utils.ParseToken(request.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ApiResult[any]{Status: "error", Code: 401, Message: "Invalid refresh token"})
		return
	}

	// 生成新的访问 token
	newToken, err := utils.GenerateToken(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ApiResult[any]{Status: "error", Code: 500, Message: "Failed to generate new token"})
		return
	}

	c.JSON(http.StatusOK, ApiResult[string]{Status: "success", Code: 200, Message: "Token refreshed", Data: ApiData[string]{Content: newToken}})
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
// @Success 200 {object} ApiResult[float64] "Token status"
// @Failure 400 {object} ApiResult[string] "Invalid input"
// @Failure 401 {object} ApiResult[string] "Invalid token"
// @Router /auth/check-token [post]
func CheckToken(c *gin.Context) {
	var request CheckTokenRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, ApiResult[any]{Status: "error", Code: 400, Message: err.Error()})
		return
	}

	token := request.Token
	if token == "" {
		c.JSON(http.StatusBadRequest, ApiResult[any]{Status: "error", Code: 400, Message: "Token is required"})
		return
	}

	claims, err := utils.ParseToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ApiResult[any]{Status: "error", Code: 401, Message: "Invalid token"})
		return
	}

	// 计算剩余有效时间
	expirationTime := time.Unix(claims.ExpiresAt, 0)
	timeLeft := expirationTime.Sub(time.Now())

	response := ApiResult[ApiData[float64]]{
		Status:  "success",
		Code:    200,
		Message: "Token status retrieved",
		Data: ApiData[ApiData[float64]](ApiData[float64]{
			ExpiresIn: int64(timeLeft.Seconds()), // 设置 ExpiresIn 为剩余时间（秒）
		}),
	}

	c.JSON(http.StatusOK, response)
}
