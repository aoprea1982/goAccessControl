package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

const (
	jwtSecret  = "secret" // JWTのシークレットキー
	cookieName = "auth_token"          // 認証用クッキーの名前
)

// ユーザー情報を表す構造体
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// ログイン資格情報を表す構造体
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// JWTのクレーム情報を表す構造体
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// ユーザー情報のマップ（シンプルなデータベースの代用）
var users = map[string]User{
	"admin": {Username: "admin", Password: "admin123", Role: "admin"},
	"user":  {Username: "user", Password: "user123", Role: "user"},
}

// JWTトークンを生成する関数
func generateToken(user User) (string, error) {
	expirationTime := time.Now().Add(30 * time.Minute) // トークンの有効期限
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

// JWTトークンをクッキーにセットする関数
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

// 認証ミドルウェア
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

// 脆弱な管理者専用ミドルウェア: 誰でも管理者エンドポイントにアクセス可能
func adminOnlyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			http.Error(w, "認証が必要です", http.StatusUnauthorized)
			return
		}

		// 脆弱性: ユーザーの役割を確認せずに続行
		next.ServeHTTP(w, r)
	})
}

// ログイン処理のハンドラー
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "login.html") // ログインページを提供
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "フォームデータが無効です", http.StatusBadRequest)
			return
		}

		creds := Credentials{
			Username: r.FormValue("username"),
			Password: r.FormValue("password"),
		}

		user, exists := users[creds.Username]
		if !exists || user.Password != creds.Password {
			http.Error(w, "無効な資格情報です", http.StatusUnauthorized)
			return
		}

		tokenString, err := generateToken(user)
		if err != nil {
			http.Error(w, "トークン生成に失敗しました", http.StatusInternalServerError)
			return
		}

		setTokenCookie(w, tokenString)

		// ユーザーの役割に基づいてリダイレクト
		if user.Role == "admin" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/user", http.StatusSeeOther)
		}
	}
}

// 保護されたエンドポイントのハンドラー
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	json.NewEncoder(w).Encode(map[string]string{
		"message": "保護されたコンテンツです",
		"user":    claims.Username,
		"role":    claims.Role,
	})
}

// 管理者専用エンドポイントのハンドラー
func adminHandler(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	json.NewEncoder(w).Encode(map[string]string{
		"message": "管理者専用コンテンツです",
		"user":    claims.Username,
	})
}

type contextKey string

const claimsContextKey contextKey = "claims"

// コンテキストからクレーム情報を取得
func ClaimsFromContext(ctx context.Context) *Claims {
	claims, _ := ctx.Value(claimsContextKey).(*Claims)
	return claims
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/login", loginHandler)

	protected := r.PathPrefix("").Subrouter()
	protected.Use(authenticateMiddleware)
	protected.HandleFunc("/user", protectedHandler).Methods("GET")

	admin := r.PathPrefix("/admin").Subrouter()
	admin.Use(authenticateMiddleware, adminOnlyMiddleware)
	admin.HandleFunc("", adminHandler).Methods("GET")

	log.Println("サーバーが http://localhost:8080 で実行中")
	log.Fatal(http.ListenAndServe(":8080", r))
}
