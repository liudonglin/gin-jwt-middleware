package handlers

import (
	"gin-jwt/middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

var secret = "123456"

type UserClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

func New() *gin.Engine {
	router := gin.Default()

	router.GET("/login", login)

	router.GET("/auth", middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey:  []byte(secret),
		TokenLookup: "query:Authorization",
	}), auth)

	return router
}

func login(c *gin.Context) {
	// Set custom claims
	claims := &UserClaims{
		"gavin",
		true,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString([]byte(secret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"Code":     http.StatusInternalServerError,
			"Message":  "token Signed error",
			"Internal": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"Code":  http.StatusOK,
		"Token": t})
}

func auth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"Code": http.StatusOK,
		"Data": "Authentication succeeded"})
}
