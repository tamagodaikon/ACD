#!/usr/bin/env python3
"""
学習用の意図的に脆弱なWebアプリケーション
各エンドポイントには脆弱な実装と安全な実装が用意されています

警告: このアプリは学習目的専用です。本番環境では絶対に使用しないでください。
"""

import sqlite3
import os
import secrets
from flask import Flask, request, render_template_string, session, redirect, url_for, abort

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_PATH = "/tmp/demo.db"

SAFE_MODE = os.environ.get("SAFE_MODE", "false").lower() == "true"


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            note TEXT
        )
    """)
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'secret123', 'admin', '管理者アカウント')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'alice', 'password', 'user', '一般ユーザー')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'bob', 'qwerty', 'user', '一般ユーザー2')")
    conn.commit()
    conn.close()


BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>脆弱なアプリ - 学習用</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .vuln { background: #ffe0e0; padding: 15px; border-left: 4px solid #e00; margin: 10px 0; }
        .safe { background: #e0ffe0; padding: 15px; border-left: 4px solid #0a0; margin: 10px 0; }
        .info { background: #e0e8ff; padding: 15px; border-left: 4px solid #00a; margin: 10px 0; }
        input { padding: 8px; margin: 5px; border: 1px solid #ccc; }
        button { padding: 8px 16px; background: #333; color: white; border: none; cursor: pointer; }
        nav a { margin-right: 15px; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>🎓 脆弱なWebアプリ（学習用）</h1>
    <p>モード: <strong>{{ '🔒 安全モード' if safe_mode else '⚠️ 脆弱モード' }}</strong></p>
    <nav>
        <a href="/">ホーム</a>
        <a href="/login">ログイン (SQLi)</a>
        <a href="/search">検索 (XSS)</a>
        <a href="/profile/1">プロフィール (IDOR)</a>
        <a href="/headers">ヘッダー確認</a>
    </nav>
    <hr>
    {% block content %}{% endblock %}
</body>
</html>
"""

INDEX_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
<h2>学習用脆弱Webアプリへようこそ</h2>
<div class="info">
<p>このアプリには意図的な脆弱性が含まれています。各ページで脆弱性を体験・修正してください。</p>
<ul>
    <li><a href="/login">SQLインジェクション</a> - ログインバイパス</li>
    <li><a href="/search">XSS</a> - クロスサイトスクリプティング</li>
    <li><a href="/profile/1">IDOR</a> - 安全でない直接オブジェクト参照</li>
    <li><a href="/headers">HTTPヘッダー</a> - セキュリティヘッダーの確認</li>
</ul>
</div>
<p>環境変数 <code>SAFE_MODE=true</code> を設定して起動すると安全な実装に切り替わります:</p>
<pre>SAFE_MODE=true python app.py</pre>
""")

LOGIN_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
<h2>ログイン - SQLインジェクション</h2>
{% if safe_mode %}
<div class="safe">✓ 安全モード: パラメータ化クエリを使用しています</div>
{% else %}
<div class="vuln">⚠️ 脆弱モード: 試してみよう → ユーザー名: <code>admin'--</code></div>
{% endif %}
<form method="POST">
    <label>ユーザー名: <input type="text" name="username" placeholder="admin'--"></label><br>
    <label>パスワード: <input type="password" name="password" placeholder="任意"></label><br>
    <button type="submit">ログイン</button>
</form>
{% if message %}
<div class="{{ 'safe' if success else 'vuln' }}">{{ message }}</div>
{% endif %}
{% if query %}
<div class="info"><strong>実行されたクエリ:</strong><pre>{{ query }}</pre></div>
{% endif %}
""")

SEARCH_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
<h2>検索 - XSS（クロスサイトスクリプティング）</h2>
{% if safe_mode %}
<div class="safe">✓ 安全モード: Jinja2の自動エスケープが有効</div>
{% else %}
<div class="vuln">⚠️ 脆弱モード: 試してみよう → <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></div>
{% endif %}
<form method="GET">
    <input type="text" name="q" value="{{ query_raw }}" placeholder="検索キーワード">
    <button type="submit">検索</button>
</form>
{% if query_raw %}
<div class="info">
    検索結果: <strong>{{ query_safe if safe_mode else query_unsafe }}</strong>
</div>
{% endif %}
""")

PROFILE_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
<h2>プロフィール - IDOR（安全でない直接オブジェクト参照）</h2>
{% if safe_mode %}
<div class="safe">✓ 安全モード: 認証チェックが有効</div>
{% else %}
<div class="vuln">⚠️ 脆弱モード: URLのIDを変えるだけで他人のデータが見える<br>
試してみよう: <a href="/profile/1">/profile/1</a> → <a href="/profile/2">/profile/2</a></div>
{% endif %}
{% if user %}
<table border="1" style="border-collapse:collapse; padding: 5px;">
    <tr><th>フィールド</th><th>値</th></tr>
    <tr><td>ID</td><td>{{ user.id }}</td></tr>
    <tr><td>ユーザー名</td><td>{{ user.username }}</td></tr>
    <tr><td>ロール</td><td>{{ user.role }}</td></tr>
    <tr><td>メモ</td><td>{{ user.note }}</td></tr>
</table>
{% endif %}
""")


@app.route("/")
def index():
    return render_template_string(INDEX_TEMPLATE, safe_mode=SAFE_MODE)


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    success = False
    query = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        if SAFE_MODE:
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            c.execute(query, (username, password))
            query_display = f"SELECT * FROM users WHERE username = '{username}' AND password = '****'"
        else:
            raw_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            query_display = raw_query
            query = raw_query
            try:
                c.execute(raw_query)
            except sqlite3.OperationalError as e:
                conn.close()
                return render_template_string(LOGIN_TEMPLATE, safe_mode=SAFE_MODE,
                                             message=f"SQLエラー: {e}", success=False,
                                             query=query_display)

        user = c.fetchone()
        conn.close()

        if user:
            session["user"] = user[1]
            message = f"ログイン成功！ようこそ {user[1]} さん（ロール: {user[3]}）"
            success = True
        else:
            message = "ログイン失敗"

        return render_template_string(LOGIN_TEMPLATE, safe_mode=SAFE_MODE,
                                     message=message, success=success, query=query_display)

    return render_template_string(LOGIN_TEMPLATE, safe_mode=SAFE_MODE,
                                  message="", success=False, query="")


@app.route("/search")
def search():
    query_raw = request.args.get("q", "")

    from markupsafe import Markup, escape
    query_safe = escape(query_raw)
    query_unsafe = Markup(query_raw)

    return render_template_string(SEARCH_TEMPLATE, safe_mode=SAFE_MODE,
                                  query_raw=query_raw, query_safe=query_safe,
                                  query_unsafe=query_unsafe)


@app.route("/profile/<int:user_id>")
def profile(user_id: int):
    if SAFE_MODE:
        logged_in_user_id = session.get("user_id", None)
        if logged_in_user_id is None:
            return render_template_string(PROFILE_TEMPLATE, safe_mode=SAFE_MODE,
                                         user=None,
                                         message="ログインが必要です"), 401
        if logged_in_user_id != user_id:
            abort(403)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, role, note FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        abort(404)

    user = {"id": row[0], "username": row[1], "role": row[2], "note": row[3]}
    return render_template_string(PROFILE_TEMPLATE, safe_mode=SAFE_MODE, user=user)


@app.route("/headers")
def headers():
    resp_headers = {
        "Content-Type": "text/html; charset=utf-8",
    }
    if SAFE_MODE:
        resp_headers.update({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        })

    template = BASE_TEMPLATE.replace("{% block content %}{% endblock %}", """
<h2>HTTPレスポンスヘッダー</h2>
<div class="info">
<p>ブラウザの開発者ツール (F12) → Network タブ → このページのレスポンスヘッダーを確認してください。</p>
<p>または: <code>curl -I http://localhost:5000/headers</code></p>
</div>
<p>セキュリティヘッダーの詳細診断は以下を実行:</p>
<pre>python tools/web/header_checker.py --url http://localhost:5000</pre>
""")

    from flask import make_response
    response = make_response(render_template_string(template, safe_mode=SAFE_MODE))
    for key, value in resp_headers.items():
        response.headers[key] = value

    if not SAFE_MODE:
        response.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
        response.headers["X-Powered-By"] = "PHP/7.4.3"

    return response


if __name__ == "__main__":
    init_db()
    mode = "安全モード" if SAFE_MODE else "脆弱モード"
    print(f"[*] 学習用Webアプリ起動 ({mode})")
    print("[*] URL: http://localhost:5000")
    print("[*] 安全モードで起動: SAFE_MODE=true python app.py")
    app.run(debug=False, host="127.0.0.1", port=5000)
