package main

import (
    "context"
    "encoding/json"
    "html/template"
    "log"
    "net/http"
    "strconv"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/gorilla/mux"
)

const (
    jwtSecret  = "非常に秘密の鍵_123"  // 脆弱性: ハードコードされた秘密
    cookieName = "auth_token"
)

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

// 脆弱性: 予測可能なIDを持つインメモリストレージ
var users = map[int]User{
    1: {ID: 1, Username: "admin", Password: "admin123", Role: "admin", Email: "admin@example.com", ApiKey: "admin-key-123"},
    2: {ID: 2, Username: "user1", Password: "user123", Role: "user", Email: "user1@example.com", ApiKey: "user-key-456"},
    3: {ID: 3, Username: "user2", Password: "user456", Role: "user", Email: "user2@example.com", ApiKey: "user-key-789"},
}

// 脆弱性: メモリ内に機密データを保存
var userSessions = make(map[string]User)

type contextKey string
const claimsContextKey contextKey = "claims"

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

        // 成功時、クレームを次のハンドラーに渡す
        ctx := context.WithValue(r.Context(), claimsContextKey, claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// 脆弱性: レート制限なし
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

        // 脆弱性: ユーザーを線形検索
        var foundUser User
        for _, u := range users {
            if u.Username == creds.Username && u.Password == creds.Password {
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

        // 脆弱性: 安全でないクッキー設定
        http.SetCookie(w, &http.Cookie{
            Name:     cookieName,
            Value:    token,
            Path:     "/",
            Expires:  time.Now().Add(24 * time.Hour),
            HttpOnly: true,
        })

        json.NewEncoder(w).Encode(map[string]interface{}{
            "token": token,
            "role":  foundUser.Role,
            "user_id": foundUser.ID,
        })
        return
    }

    // GETリクエストでログインページを提供
    tmpl := template.Must(template.ParseFiles("login.html"))
    tmpl.Execute(w, nil)
}

// 脆弱性: 適切な権限チェックなし
func getUserProfileHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID, _ := strconv.Atoi(vars["id"])
    
    // 脆弱性: IDOR - ユーザーアクセス権の検証なし
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

// 脆弱性: 情報漏洩
func getUserAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID, _ := strconv.Atoi(vars["id"])
    
    // 脆弱性: リクエストしたユーザーの権限を検証せずにAPIキーを提供
    if user, exists := users[userID]; exists {
        json.NewEncoder(w).Encode(map[string]string{
            "api_key": user.ApiKey,
        })
        return
    }
    
    http.Error(w, "ユーザーが見つかりません", http.StatusNotFound)
}

// 脆弱性: 適切なロールチェックなし
func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": "管理者ダッシュボード",
        "users":   users,
    })
}

func main() {
    r := mux.NewRouter()

    // 静的ファイルを提供
    r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

    // 公開エンドポイント
    r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
    
    // 保護されたルート
    api := r.PathPrefix("/api").Subrouter()
    api.Use(authenticateMiddleware)
    
    // ユーザーエンドポイント
    api.HandleFunc("/users/{id}", getUserProfileHandler).Methods("GET")
    api.HandleFunc("/users/{id}/apikey", getUserAPIKeyHandler).Methods("GET")
    
    // 管理者エンドポイント
    api.HandleFunc("/admin/dashboard", adminDashboardHandler).Methods("GET")

    log.Printf("サーバーが http://localhost:8080 で実行中")
    log.Fatal(http.ListenAndServe(":8080", r))
}
