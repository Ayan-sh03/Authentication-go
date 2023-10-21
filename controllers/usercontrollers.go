package controllers

import (
	"auth/authorization"
	"auth/models"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/smtp"
	"os"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var cache = make(map[string]string)

type TokenRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type OTPRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

// RegisterUser registers a user in the system.
//
// It takes two parameters:
// - context: a pointer to the gin.Context object.
// - DB: a pointer to the gorm.DB object.
//
// It does the following:
// 1. Binds the JSON request body to the user object.
// 2. Hashes the user's password.
// 3. Creates a record in the database.
// 4. Sends an OTP (One-Time Password) to the user's email address.
// 5. Returns the user ID and email in the response.
func RegisterUser(context *gin.Context, DB *gorm.DB) {
	var user models.User
	if err := context.ShouldBindJSON(&user); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		context.Abort()
		return
	}
	if err := user.HashPassword(user.Password); err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		context.Abort()
		return
	}
	record := DB.Create(&user)
	//! Sending OTP logic //

	/*
		1. Generate a random 6-digit number
		2. Send the OTP to the user's email
		3. Store the OTP in the map

	*/

	auth := smtp.PlainAuth("", os.Getenv("EMAIL"), os.Getenv("PASSWORD"), "smtp.gmail.com")

	to := []string{user.Email}
	otp, err := generateOTP()
	cache[user.Email] = otp

	if err != nil {
		log.Fatal("error in generating OTP", err)
	}
	message := []byte("To : " + user.Email + "Subject : OTP for Registration \r\n  \r\n" +
		"Your OTP For registration is " + otp + "\n")

	go func() {
		err := smtp.SendMail("smtp.gmail.com:587", auth, os.Getenv("EMAIL"), to, message)
		if err != nil {
			log.Println("Error in sending OTP:", err)
		}
	}()

	////-------///////

	if record.Error != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": record.Error.Error()})
		context.Abort()
		return
	}
	context.JSON(http.StatusCreated, gin.H{"userId": user.ID, "email": user.Email})
}

// CheckOtp checks the OTP provided by the user.
//
// It takes in two parameters:
// - context: a pointer to a gin.Context object representing the HTTP request context.
// - DB: a pointer to a gorm.DB object representing the database connection.
//
// This function first parses the OTP request from the JSON payload of the HTTP request.
// If the JSON parsing fails, it returns a JSON response with the corresponding error and aborts the request.
//
// Then it checks if the OTP exists in the cache. If it doesn't exist, it returns a JSON response with an "invalid credentials" error and aborts the request.
//
// Next, it compares the received OTP with the OTP in the cache. If they don't match, it returns a JSON response with a "Please Enter Valid OTP" error.
//
// After that, it updates the IsVerified field of the user with the matching email in the database.
// If the update fails, it returns a JSON response with the corresponding error.
//
// Finally, it returns a JSON response with a "OTP Verified" message indicating successful verification.
func CheckOtp(context *gin.Context, DB *gorm.DB) {

	var otp OTPRequest
	if err := context.ShouldBindJSON(&otp); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		context.Abort()
		return
	}

	value, exists := cache[otp.Email]
	if !exists {
		context.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		context.Abort()
		return
	}

	if value != otp.OTP {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Please Enter Valid OTP"})
	}

	go func() {
		// var user models.User
		err := DB.Model(&models.User{}).Where("email = ?", otp.Email).Updates(models.User{IsVerified: true}).Error
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

	}()

	context.JSON(http.StatusOK, gin.H{"message": "OTP Verified"})

}

// LoginController handles the login request and generates a JWT token if the credentials are valid.
//
// It takes two parameters:
// - context: a pointer to the gin.Context object for handling HTTP requests and responses.
// - DB: a pointer to the gorm.DB object for interacting with the database.
//
// The function does the following:
// - Binds the incoming JSON request to a TokenRequest struct.
// - Checks if the email exists and the password is correct in the database.
// - Generates a JWT token if the credentials are valid.
// - Sends the token in the response body if the login is successful.
//
// It returns nothing.
func LoginController(context *gin.Context, DB *gorm.DB) {
	var request TokenRequest
	var user models.User
	if err := context.ShouldBindJSON(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		context.Abort()
		return
	}
	// check if email exists and password is correct
	record := DB.Where("email = ?", request.Email).First(&user)
	if record.Error != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": record.Error.Error()})
		context.Abort()
		return
	}
	credentialError := user.CheckPassword(request.Password)
	if credentialError != nil {
		context.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		context.Abort()
		return
	}
	tokenString, err := authorization.GenerateJWT(user.Email)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		context.Abort()
		return
	}
	context.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func generateOTP() (string, error) {
	// Define the range for the OTP (5 digits)
	min := int64(10000)
	max := int64(99999)

	// Generate a cryptographically secure random number within the defined range

	randomInt, err := rand.Int(rand.Reader, new(big.Int).Sub(big.NewInt(max), big.NewInt(min)))
	if err != nil {
		return "", err
	}

	// Add the minimum value to ensure a 5-digit OTP
	otpValue := randomInt.Int64() + min

	// Format the OTP as a string with leading zeros
	otp := fmt.Sprintf("%05d", otpValue)

	return (otp), nil
}
