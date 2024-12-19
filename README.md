# goAccessControl
go code vulnerable to access control issue and the fix

アクセス制御の問題があるGoコードとその修正

使い方

**accessVulnerable 脆弱なコード**

リポジトリをクローンする
```
git clone https://github.com/aoprea1982/goAccessControl
```

accessVulnerableへ移動
```
cd accessVulnerable
```

プログラムを実行
```
go run main.go
```

ブラウザから`http://127.0.0.1:8080/login`　へアクセス
```
一般ユーザーアカウントクレデンシャル
ユーザー名:user
パスワード:user123

管理者アカウントクレデンシャル
ユーザー名:admin
パスワード:admin123
```

ユーザーアカウントでログインした後、管理者エンドポイント"/admin"にアクセスします。ユーザーがそれにアクセス可能です。
```
http://127.0.0.1:8080/admin
```


**accessFix 修正したコード**

リポジトリをクローンする
```
git clone https://github.com/aoprea1982/goAccessControl
```

accessFixへ移動
```
cd accessFix
```

プログラムを実行
```
go run main.go
```

ブラウザから`http://127.0.0.1:8080/login`　へアクセス
```
一般ユーザーアカウントクレデンシャル
ユーザー名:user
パスワード:user123

管理者アカウントクレデンシャル
ユーザー名:admin
パスワード:admin123
```

ユーザーアカウントでログインした後、”管理者コンテンツを取得”ボタンをクリックします。ユーザーがそれにアクセスできません。
```
管理者コンテンツを取得ボタンクリック後は

サーバのレスポンス
Status
403
Forbidden
Access denied

```
