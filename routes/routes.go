package routes

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"yeebotech-auth/controllers"
	"yeebotech-auth/middlewares"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()

	// Auth routes
	r.POST("/register", controllers.Register)
	r.POST("/login", controllers.Login)
	// 检查 token 和刷新 token 路由
	r.POST("/check-token", controllers.CheckToken)
	r.POST("/refresh-token", controllers.RefreshToken)
	// Swagger 路由
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	// 使用 JWT 中间件保护的路由
	auth := r.Group("/").Use(middlewares.JWTAuthMiddleware())
	{
		auth.GET("/profile", controllers.GetProfile)
	}
	return r
}
