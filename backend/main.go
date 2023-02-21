package main

import (
	"encoding/json"
	"errors"
	"example/backend/config"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type GoogleAuth struct {
	Token string `json:"token" binding:"required"`
}

type GoogleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	FirstName     string `json:"given_name"`
	LastName      string `json:"family_name"`
	jwt.StandardClaims
}

type Payload struct {
	Email    string    `json:"email"`
	IssuedAt time.Time `json:"issuedAt"`
	jwt.RegisteredClaims
}

func createToken(email string, secretKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":    email,
		"issuedAt": time.Now(),
	})

	return token.SignedString([]byte(secretKey))
}

func verifyToken(tokenString string, secretKey string) (Payload, error) {
	claimsStruct := Payload{}
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, errors.New("invalid token")
		}
		return []byte(secretKey), nil
	}

	token, err := jwt.ParseWithClaims(tokenString, &claimsStruct, keyFunc)

	if err != nil {
		return Payload{}, err
	}

	claims, ok := token.Claims.(*Payload)
	if !ok {
		return Payload{}, errors.New("invalid token")
	}

	return *claims, nil
}

func getGooglePublicKey(keyID string) (string, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v1/certs")
	if err != nil {
		return "", err
	}
	dat, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	myResp := map[string]string{}
	err = json.Unmarshal(dat, &myResp)
	if err != nil {
		return "", err
	}
	key, ok := myResp[keyID]
	if !ok {
		return "", errors.New("key not found")
	}
	return key, nil
}

func validateToken(tokenString string) (GoogleClaims, error) {
	claimsStruct := GoogleClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&claimsStruct,
		func(token *jwt.Token) (interface{}, error) {
			pem, err := getGooglePublicKey(fmt.Sprintf("%s", token.Header["kid"]))
			if err != nil {
				return nil, err
			}
			key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
			if err != nil {
				return nil, err
			}
			return key, nil
		},
	)
	if err != nil {
		return GoogleClaims{}, err
	}

	claims, ok := token.Claims.(*GoogleClaims)
	if !ok {
		return GoogleClaims{}, errors.New("invalid Google JWT")
	}

	if claims.Issuer != "accounts.google.com" && claims.Issuer != "https://accounts.google.com" {
		return GoogleClaims{}, errors.New("iss is invalid")
	}

	if claims.Audience != config.CLIENT_ID {
		return GoogleClaims{}, errors.New("aud is invalid")
	}

	if claims.ExpiresAt < time.Now().UTC().Unix() {
		return GoogleClaims{}, errors.New("JWT is expired")
	}

	return *claims, nil
}

func googleAuthHandler(c *gin.Context) {
	var googleAuth GoogleAuth
	err := c.BindJSON(&googleAuth)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("could not decode token").Error()})
		return
	}

	claims, err := validateToken(googleAuth.Token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("invalid google auth").Error()})
		return
	}

	token, err := createToken(claims.Email, config.SECRET_KEY)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errors.New("couldn't make authentication token").Error()})
		return
	}
	newClaim, err := verifyToken(token, config.SECRET_KEY)
	fmt.Println("Hello", newClaim)
	fmt.Println("Anime", err)
	c.JSON(http.StatusOK, gin.H{"accessToken": token})
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST,HEAD,PATCH, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func main() {
	router := gin.Default()
	router.Use(CORSMiddleware())
	router.POST("/auth/google", googleAuthHandler)

	router.Run("localhost:8080")
}
