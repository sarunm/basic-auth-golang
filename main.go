package main

import (
    "fmt"
    "github.com/golang-jwt/jwt/v5"
    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    "log"
    "net/http"
    "strings"
    "time"
)

type jwtCustomClaims struct {
    Name  string `json:"name"`
    Admin bool   `json:"admin"`
    Type  string `json:"type"`
    jwt.RegisteredClaims
}

func login(e echo.Context) error {

    username := e.FormValue("username")
    password := e.FormValue("password")

    if username != "nick" || password != "1234" {
        return echo.ErrUnauthorized
    }

    claims := &jwtCustomClaims{
        "Nick", true, "accessToken", jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 30)),
        },
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    accessToken, err := token.SignedString([]byte("secret"))
    if err != nil {
        return err
    }

    refreshTokenClaims := &jwtCustomClaims{
        "Nick", true, "refreshToken", jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
        }}

    refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
    refreshTokenStr, err := refreshToken.SignedString([]byte("secret"))
    if err != nil {
        return err
    }

    return e.JSON(http.StatusOK, echo.Map{
        "accessToken":  accessToken,
        "refreshToken": refreshTokenStr,
    })
}

func jwtMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        authorizationToken := c.Request().Header.Get("Authorization")
        if authorizationToken == "" {
            return echo.ErrUnauthorized
        }
        part := strings.Split(authorizationToken, " ")
        if !(len(part) == 2 && part[0] == "Bearer") {
            return echo.ErrUnauthorized
        }

        jwtToken := part[1]

        token, err := jwt.ParseWithClaims(jwtToken, &jwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
            return []byte("secret"), nil
        })

        claims, ok := token.Claims.(*jwtCustomClaims)
        if !ok {
            return echo.ErrUnauthorized
        }

        fmt.Println("claimed : %s", claims)
        c.Set("user", claims)

        if err != nil {
            return echo.ErrUnauthorized
        }

        return next(c)
    }
}

func refreshToken(c echo.Context) error {
    refrestTokenString := c.FormValue("refresh_token")

    jwtSecretKey := []byte("secret")

    token, err := jwt.ParseWithClaims(refrestTokenString, &jwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
        return jwtSecretKey, nil
    })

    if err != nil {
        return echo.ErrUnauthorized
    }
    claims, ok := token.Claims.(*jwtCustomClaims)
    if !ok || !token.Valid || claims.Type != "refresh" {
        return echo.ErrUnauthorized
    }

    newAccessTokenClaims := &jwtCustomClaims{
        claims.Name, claims.Admin, "access", jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
        },
    }

    newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newAccessTokenClaims)
    newAccessTokenString, err := newAccessToken.SignedString(jwtSecretKey)
    if err != nil {
        return err
    }

    return c.JSON(http.StatusOK, echo.Map{
        "access_token":  newAccessTokenString,
        "refresh_token": refrestTokenString,
    })

}

func main() {
    e := echo.New()

    e.Use(middleware.Logger())
    e.Use(middleware.Recover())

    e.GET("/health", func(c echo.Context) error {
        return c.String(200, "OK")
    })

    g := e.Group("/api")
    g.POST("/login", login)
    g.POST("/refresh", refreshToken)

    g.Use(jwtMiddleware)

    g.GET("/hello", func(c echo.Context) error {
        return c.String(200, "Hello, World!")
    })

    log.Fatal(e.Start(":8080"))
}
