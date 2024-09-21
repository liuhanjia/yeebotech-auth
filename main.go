package main

import (
	"yeebotech-auth/config"
	_ "yeebotech-auth/docs" // 替换成你的实际路径
	"yeebotech-auth/routes"
)

// @title JWT Auth API
// @version 1.0
// @description This is a sample server for JWT authentication using Gin and Gorm.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8082
// @BasePath /
// @securityDefinitions.apiKey ApiKeyAuth
// @in header
// @name Authorization
// @description JWT Token (format: Bearer <token>)

func main() {
	config.ConnectDatabase()

	r := routes.SetupRouter()

	r.Run(":8082")
}
