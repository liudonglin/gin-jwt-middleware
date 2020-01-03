package middleware

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"reflect"
	"strings"
)

type JWTConfig struct {

	// Skipper defines a function to skip middleware.
	Skipper Skipper

	// BeforeFunc defines a function which is executed just before the middleware.
	BeforeFunc BeforeFunc

	// SuccessHandler defines a function which is executed for a valid token.
	SuccessHandler JWTSuccessHandler

	// ErrorHandler defines a function which is executed for an invalid token.
	// It may be used to define a custom JWT error.
	ErrorHandler JWTErrorHandler

	// Signing key to validate token.
	// Required.
	SigningKey interface{}

	// Signing method, used to check token signing method.
	// Optional. Default value HS256.
	SigningMethod string

	// Context key to store user information from the token into context.
	// Optional. Default value "user".
	ContextKey string

	// Claims are extendable claims data defining token content.
	// Optional. Default value jwt.MapClaims
	Claims jwt.Claims

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// AuthScheme to be used in the Authorization header.
	// Optional. Default value "Bearer".
	AuthScheme string

	keyFunc jwt.Keyfunc
}

// JWTSuccessHandler defines a function which is executed for a valid token.
type JWTSuccessHandler func(*gin.Context)

// JWTErrorHandler defines a function which is executed for an invalid token.
type JWTErrorHandler func(error) error

type jwtExtractor func(*gin.Context) (string, error)

// Algorithms
const (
	AlgorithmHS256      = "HS256"
	HeaderAuthorization = "Authorization"
)

type (
	// Skipper defines a function to skip middleware. Returning true skips processing
	// the middleware.
	Skipper func(*gin.Context) bool

	// BeforeFunc defines a function which is executed just before the middleware.
	BeforeFunc func(*gin.Context)
)

// DefaultSkipper returns false which processes the middleware.
func DefaultSkipper(*gin.Context) bool {
	return false
}

//DefaultJWTConfig is the default JWT auth middleware config.
var DefaultJWTConfig = JWTConfig{
	Skipper:       DefaultSkipper,
	SigningMethod: AlgorithmHS256,
	ContextKey:    "user",
	TokenLookup:   "header:" + HeaderAuthorization,
	AuthScheme:    "Bearer",
	Claims:        jwt.MapClaims{},
}

func JWT(key interface{}) gin.HandlerFunc {
	c := DefaultJWTConfig
	c.SigningKey = key
	return JWTWithConfig(c)
}

func JWTWithConfig(config JWTConfig) gin.HandlerFunc {

	if config.Skipper == nil {
		config.Skipper = DefaultJWTConfig.Skipper
	}
	if config.SigningKey == nil {
		panic("gin: jwt middleware requires signing key")
	}
	if config.SigningMethod == "" {
		config.SigningMethod = DefaultJWTConfig.SigningMethod
	}
	if config.ContextKey == "" {
		config.ContextKey = DefaultJWTConfig.ContextKey
	}
	if config.Claims == nil {
		config.Claims = DefaultJWTConfig.Claims
	}
	if config.TokenLookup == "" {
		config.TokenLookup = DefaultJWTConfig.TokenLookup
	}
	if config.AuthScheme == "" {
		config.AuthScheme = DefaultJWTConfig.AuthScheme
	}

	config.keyFunc = func(t *jwt.Token) (interface{}, error) {
		// Check the signing method
		if t.Method.Alg() != config.SigningMethod {
			return nil, fmt.Errorf("unexpected jwt signing method=%v", t.Header["alg"])
		}
		return config.SigningKey, nil
	}

	parts := strings.Split(config.TokenLookup, ":")
	var extractor jwtExtractor

	switch parts[0] {
	case "query":
		extractor = jwtFromQuery(parts[1])
	case "cookie":
		extractor = jwtFromCookie(parts[1])
	default:
		extractor = jwtFromHeader(parts[1], config.AuthScheme)
	}

	return func(c *gin.Context) {
		if config.Skipper(c) {
			c.Next()
			return
		}

		if config.BeforeFunc != nil {
			config.BeforeFunc(c)
		}

		auth, err := extractor(c)
		if err != nil {
			if config.ErrorHandler != nil {
				config.ErrorHandler(err)
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"Code":     http.StatusBadRequest,
				"Message":  "extracts token error",
				"Internal": err.Error()})
			c.Abort()
			return
		}

		token := new(jwt.Token)
		if _, ok := config.Claims.(jwt.MapClaims); ok {
			token, err = jwt.Parse(auth, config.keyFunc)
		} else {
			t := reflect.ValueOf(config.Claims).Type().Elem()
			claims := reflect.New(t).Interface().(jwt.Claims)
			token, err = jwt.ParseWithClaims(auth, claims, config.keyFunc)
		}
		if err == nil && token.Valid {
			// Store user information from token into context.
			c.Set(config.ContextKey, token)
			if config.SuccessHandler != nil {
				config.SuccessHandler(c)
			}
			c.Next()
			return
		}
		if config.ErrorHandler != nil {
			config.ErrorHandler(err)
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{
			"Code":     http.StatusUnauthorized,
			"Message":  "invalid or expired jwt",
			"Internal": err.Error()})
		c.Abort()
	}
}

var (
	ErrHeaderJWTMissing = errors.New("missing or malformed jwt in the header")
	ErrQueryJWTMissing  = errors.New("missing or malformed jwt in the query")
	ErrCookieJWTMissing = errors.New("missing or malformed jwt in the cookie")
)

//仅header模式需要authScheme
func jwtFromHeader(header string, authScheme string) jwtExtractor {
	return func(c *gin.Context) (string, error) {
		auth := c.GetHeader(header)
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", ErrHeaderJWTMissing
	}
}

func jwtFromQuery(param string) jwtExtractor {
	return func(c *gin.Context) (string, error) {
		token := c.Query(param)
		if token == "" {
			return "", ErrQueryJWTMissing
		}
		return token, nil
	}
}

func jwtFromCookie(name string) jwtExtractor {
	return func(c *gin.Context) (string, error) {
		cookie, err := c.Cookie(name)
		if err != nil {
			return "", ErrCookieJWTMissing
		}
		return cookie, nil
	}
}
