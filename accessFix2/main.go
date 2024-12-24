package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"crypto/rand" 
        "encoding/hex"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

const (
	cookieName = "auth_token"
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

// Secure password hash for users
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
	Email    string `json:"email"`
	ApiKey   string `json:"api_key"`
}

type UserProfile struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	UserID   int    `json:"user_id"`
	jwt.RegisteredClaims
}

// In-memory storage for hashed users
var users = map[int]User{
	1: {ID: 1, Username: "admin", Password: hashPassword("admin123"), Role: "admin", Email: "admin@example.com", ApiKey: "admin-key-123"},
	2: {ID: 2, Username: "user1", Password: hashPassword("user123"), Role: "user", Email: "user1@example.com", ApiKey: "user-key-456"},
	3: {ID: 3, Username: "user2", Password: hashPassword("user456"), Role: "user", Email: "user2@example.com", ApiKey: "user-key-789"},
}

type contextKey string

const claimsContextKey contextKey = "claims"

func hashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Error hashing password: %v", err)
	}
	return string(hash)
}

func checkPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func generateToken(user User) (string, error) {
	claims := &Claims{
		Username: user.Username,
		Role:     user.Role,
		UserID:   user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			http.Error(w, "認証されていません", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "無効なトークン", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "無効なリクエスト", http.StatusBadRequest)
			return
		}

		var foundUser User
		for _, u := range users {
			if u.Username == creds.Username && checkPasswordHash(creds.Password, u.Password) {
				foundUser = u
				break
			}
		}

		if foundUser.Username == "" {
			http.Error(w, "認証情報が無効です", http.StatusUnauthorized)
			return
		}

		token, err := generateToken(foundUser)
		if err != nil {
			http.Error(w, "トークン生成エラー", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    token,
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":   token,
			"role":    foundUser.Role,
			"user_id": foundUser.ID,
		})
		return
	}

	tmpl := template.Must(template.ParseFiles("login.html"))
	tmpl.Execute(w, nil)
}

func getUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "無効なユーザーID", http.StatusBadRequest)
		return
	}

	claims, ok := r.Context().Value(claimsContextKey).(*Claims)
	if !ok || claims == nil {
		http.Error(w, "認証されていません", http.StatusUnauthorized)
		return
	}

	if claims.UserID != userID && claims.Role != "admin" {
		http.Error(w, "アクセス権限がありません", http.StatusForbidden)
		return
	}

	if user, exists := users[userID]; exists {
		profile := UserProfile{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
		}
		json.NewEncoder(w).Encode(profile)
		return
	}

	http.Error(w, "ユーザーが見つかりません", http.StatusNotFound)
}

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(claimsContextKey).(*Claims)
	if !ok || claims.Role != "admin" {
		http.Error(w, "アクセス権限がありません", http.StatusForbidden)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "管理者ダッシュボード",
		"users":   users,
	})
}

func getUserAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        userID, err := strconv.Atoi(vars["id"])
        if err != nil {
                http.Error(w, "無効なユーザーID", http.StatusBadRequest)
                return
        }

        claims, ok := r.Context().Value(claimsContextKey).(*Claims)
        if !ok || claims == nil {
                http.Error(w, "認証されていません", http.StatusUnauthorized)
                return
        }

        if claims.UserID != userID {
                http.Error(w, "アクセス権限がありません", http.StatusForbidden)
                return
        }

        if user, exists := users[userID]; exists {
                json.NewEncoder(w).Encode(map[string]string{
                        "api_key": user.ApiKey,
                })
                return
        }

        http.Error(w, "ユーザーが見つかりません", http.StatusNotFound)
}


func main() {
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is not set")
	}

	r := mux.NewRouter()

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")

	api := r.PathPrefix("/api").Subrouter()
	api.Use(authenticateMiddleware)

	api.HandleFunc("/users/{id}", getUserProfileHandler).Methods("GET")
	api.HandleFunc("/admin/dashboard", adminDashboardHandler).Methods("GET")
        api.HandleFunc("/users/{id}/apikey", getUserAPIKeyHandler).Methods("GET")


	log.Printf("サーバーが https://localhost:8080 で実行中")
	log.Fatal(http.ListenAndServeTLS(":8080", "server.crt", "server.key", r))
}
