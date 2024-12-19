package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

func generateSecret() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal("JWTシークレットの生成に失敗しました:", err)
	}
	return hex.EncodeToString(bytes)
}

var jwtSecret = generateSecret()
const cookieName = "auth_token"

var users = map[string]User{
	"admin": {Username: "admin", Password: "admin123", Role: "admin"},
	"user":  {Username: "user", Password: "user123", Role: "user"},
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

func generateToken(user User) (string, error) {
	expirationTime := time.Now().Add(30 * time.Minute)
	claims := &Claims{
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func setTokenCookie(w http.ResponseWriter, tokenString string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    tokenString,
		Expires:  time.Now().Add(30 * time.Minute),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "login.html")
		return
	}

	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, exists := users[username]
		if !exists || user.Password != password {
			http.Error(w, "無効な認証情報です", http.StatusUnauthorized)
			return
		}

		tokenString, err := generateToken(user)
		if err != nil {
			http.Error(w, "トークン生成に失敗しました", http.StatusInternalServerError)
			return
		}

		setTokenCookie(w, tokenString)
		if user.Role == "admin" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/user", http.StatusSeeOther)
		}
	}
}

func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			http.Error(w, "認証が必要です", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "無効なトークンです", http.StatusUnauthorized)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), claimsContextKey, claims))
		next.ServeHTTP(w, r)
	})
}

func adminOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil || claims.Role != "admin" {
			http.Error(w, "権限がありません", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	json.NewEncoder(w).Encode(map[string]string{
		"message": "保護されたコンテンツです",
		"user":    claims.Username,
		"role":    claims.Role,
	})
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	json.NewEncoder(w).Encode(map[string]string{
		"message": "管理者専用コンテンツです",
		"user":    claims.Username,
	})
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	json.NewEncoder(w).Encode(map[string]string{
		"message": "ユーザー専用コンテンツです",
		"user":    claims.Username,
	})
}

type contextKey string

const claimsContextKey contextKey = "claims"

func ClaimsFromContext(ctx context.Context) *Claims {
	claims, _ := ctx.Value(claimsContextKey).(*Claims)
	return claims
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/login", loginHandler)

	protected := r.PathPrefix("").Subrouter()
	protected.Use(authenticateMiddleware)
	protected.HandleFunc("/protected", protectedHandler).Methods("GET")
	protected.HandleFunc("/user", userHandler).Methods("GET")

	admin := r.PathPrefix("/admin").Subrouter()
	admin.Use(authenticateMiddleware, adminOnlyMiddleware)
	admin.HandleFunc("", adminHandler).Methods("GET")

	log.Println("サーバーが http://localhost:8080 で稼働中です")
	log.Fatal(http.ListenAndServe(":8080", r))
}
