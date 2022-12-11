package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

var singingKey = []byte(os.Getenv("SIGNING_KEY"))

var sessions = make(map[string]string)

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	r.GET("/oauth/authorize", func(ctx *gin.Context) {
		clientId := ctx.Query("client_id")
		responseType := ctx.Query("response_type")
		state := ctx.Query("state")
		redirectUri := ctx.Query("redirect_uri")
		scope := ctx.Query("scope")

		log.Printf("clientId: %s; responseType: %s, state: %s, redirectUri: %s, scope: %s\n",
			clientId, responseType, state, redirectUri, scope)

	})
	r.POST("/login", func(ctx *gin.Context) {
		username := ctx.PostForm("username")
		password := ctx.PostForm("password")
		log.Printf("authentication for user %s:%s\n", username, password)
		if username == "dias.arifin@gmail.com" && password == "asdf12345" {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"name": username,
				"iat":  time.Now().Unix(),
			})
			tokenString, err := token.SignedString(singingKey)
			if err != nil {
				log.Printf("err.Error(): %v\n", err.Error())
			}
			sessions[username] = tokenString
			ctx.SetCookie("session", tokenString, 60*60*24, "/", "", false, true)
			log.Printf("generated token for user %s: %s\n", username, tokenString)
			ctx.Redirect(http.StatusFound, "/")
		}
		ctx.Redirect(http.StatusFound, "/login")
	})
	r.GET("/login", func(ctx *gin.Context) {
		if session, err := ctx.Cookie("session"); err == nil {
			user := currentUser(session)
			if user != "" {
				ctx.Redirect(http.StatusFound, "/")
			}
		}
		ctx.HTML(http.StatusOK, "login.html", gin.H{})
	})
	r.POST("/logout", func(ctx *gin.Context) {
		if session, err := ctx.Cookie("session"); err == nil {
			user := currentUser(session)
			if user != "" {
				delete(sessions, user)
				ctx.SetCookie("session", "", 0, "/", "", false, true)
			}
		}
		ctx.Redirect(http.StatusFound, "/login")
	})
	r.GET("/", func(ctx *gin.Context) {
		session, err := ctx.Cookie("session")
		if err != nil {
			ctx.Redirect(http.StatusFound, "/login")
			return
		}
		user := currentUser(session)
		if user == "" {
			ctx.Redirect(http.StatusFound, "/login")
			return
		}

		ctx.HTML(http.StatusOK, "index.html", gin.H{
			"currentUser": user,
		})
	})
	r.Run()
}

func currentUser(session string) string {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(session, claims, func(token *jwt.Token) (interface{}, error) {
		return singingKey, nil
	})
	if err != nil {
		return ""
	}
	if _, found := sessions[claims["name"].(string)]; !found {
		if !found {
			log.Printf("token for user %s is not found in the db", claims["name"])
			return ""
		}
	}
	log.Printf("current user: %s\n", claims["name"])
	return claims["name"].(string)
}
