# Lab 03: Webアプリケーションセキュリティ

**難易度**: ⭐⭐ 初中級  
**所要時間**: 2〜3時間

## 学習目標

- OWASP Top 10 の主要な脆弱性を理解する
- 脆弱なコードと安全なコードの違いを実際に確認する
- 各脆弱性に対する防御の実装方法を習得する

---

## セットアップ

```bash
# 脆弱なWebアプリを起動
cd vulnerable-app
pip install flask
python app.py

# ブラウザで http://localhost:5000 にアクセス
```

---

## 演習 1: SQLインジェクション

### 脆弱なコードの例

```python
# ❌ 脆弱: ユーザー入力を直接クエリに埋め込んでいる
query = f"SELECT * FROM users WHERE username = '{username}'"
```

### 攻撃の確認（自分のアプリのみ）

```
ユーザー名: admin'--
→ クエリが: SELECT * FROM users WHERE username = 'admin'--'
→ パスワードチェックをバイパスできる
```

### 安全なコードへの修正

```python
# ✓ 安全: パラメータ化クエリを使用
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

**演習の流れ**:
1. 脆弱なアプリにSQLiを試みる
2. コードを修正して防御する
3. 修正後に同じ攻撃が失敗することを確認する

---

## 演習 2: XSS（クロスサイトスクリプティング）

### 脆弱なコードの例

```html
<!-- ❌ 脆弱: ユーザー入力をエスケープせずに表示 -->
<p>こんにちは、{{ username }}！</p>
```

### 攻撃ペイロードの例

```
ユーザー名: <script>alert('XSS')</script>
```

### 安全な実装

```python
# ✓ Flaskでは Jinja2 が自動エスケープ（{{ }}はデフォルトで安全）
# ただし |safe フィルターは絶対に使わない（信頼できないデータには）

# Content Security Policy ヘッダーを追加
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

---

## 演習 3: CSRF（クロスサイトリクエストフォージェリ）

### 脆弱なシナリオ

1. ユーザーが銀行サイトにログイン
2. 悪意あるサイトを訪問
3. 悪意あるサイトからユーザーのセッションで送金リクエストが送られる

### 防御: CSRFトークン

```python
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'random-secret-key'
csrf = CSRFProtect(app)

# フォームにCSRFトークンを埋め込む
# {{ form.csrf_token }} を hidden inputに追加
```

---

## 演習 4: 安全でない直接オブジェクト参照（IDOR）

### 脆弱なコードの例

```python
# ❌ IDのみでアクセス制御なし
@app.route('/profile/<user_id>')
def profile(user_id):
    user = db.get_user(user_id)
    return render_template('profile.html', user=user)
```

### 攻撃: URL を変えるだけで他人のプロフィールを見られる

```
/profile/1 → 自分のプロフィール
/profile/2 → 他人のプロフィール（アクセス制御なし）
```

### 安全な実装

```python
# ✓ ログインユーザーのみ自分のデータにアクセス可能
@app.route('/profile/<user_id>')
@login_required
def profile(user_id):
    if current_user.id != int(user_id):
        abort(403)
    user = db.get_user(user_id)
    return render_template('profile.html', user=user)
```

---

## セキュリティ診断ツールの使用

```bash
# ヘッダーチェック
python ../../tools/web/header_checker.py --url http://localhost:5000

# OWASP ZAP（別途インストール）でのスキャン
zap-cli quick-scan -r http://localhost:5000
```

---

## チェックリスト

- [ ] SQLiの脆弱なコードと安全なコードの違いを理解した
- [ ] XSSの3種類（Reflected, Stored, DOM-based）を学んだ
- [ ] CSRFトークンの実装を確認した
- [ ] セキュリティヘッダーを設定した
- [ ] ヘッダーチェッカーでAグレードを達成した

## 次のステップ

→ `../04-log-analysis/` へ進む
