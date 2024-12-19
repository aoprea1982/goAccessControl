package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

func generateSecret() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal("Failed to generate JWT secret:", err)
	}
	return hex.EncodeToString(bytes)
}

var jwtSecret = generateSecret()

const headerName = "Authorization"

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
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		tokenString, err := generateToken(user)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Issue the token in the response header
		w.Header().Set(headerName, "Bearer "+tokenString)

		response := map[string]string{
			"message": "Login successful",
			"role":    user.Role,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get(headerName)
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
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
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Protected content",
		"user":    claims.Username,
		"role":    claims.Role,
	})
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Admin-only content",
		"user":    claims.Username,
	})
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User-only content",
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

	r.HandleFunc("/login", loginHandler).Methods("POST", "GET")

	protected := r.PathPrefix("").Subrouter()
	protected.Use(authenticateMiddleware)
	protected.HandleFunc("/user", userHandler).Methods("GET")

	admin := r.PathPrefix("/admin").Subrouter()
	admin.Use(authenticateMiddleware, adminOnlyMiddleware)
	admin.HandleFunc("", adminHandler).Methods("GET")

	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
