package main

import (
	"log"
	"os"

	"auth/controllers"
	"auth/database"

	"auth/models"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

var DB *gorm.DB

func main() {
	var dbErr error

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(err)
	}

	config := &database.Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Password: os.Getenv("DB_PASS"),
		User:     os.Getenv("DB_USER"),
		DBName:   os.Getenv("DB_NAME"),
		SSLMode:  os.Getenv("DB_SSL_MODE"),
	}

	DB, dbErr = database.NewConnection(config)

	if dbErr != nil {
		log.Fatal("could not load DB", dbErr)
	}

	err = models.MigrateUsers(DB)
	if err != nil {
		log.Fatal("could not migrate")
	}

	router := initRouter()

	router.Run(":8080")

}

func initRouter() *gin.Engine {
	router := gin.Default()
	api := router.Group("/api")
	{
		api.POST("/user/login", func(req *gin.Context) {
			controllers.LoginController(req, DB)
		})
		api.POST("/user/register", func(req *gin.Context) {
			controllers.RegisterUser(req, DB)
		})
		api.POST("/user/otp", func(req *gin.Context) {
			controllers.CheckOtp(req, DB)
		})

	}
	return router
}
