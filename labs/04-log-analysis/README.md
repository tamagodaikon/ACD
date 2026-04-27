# Lab 04: ログ解析と異常検知

**難易度**: ⭐⭐⭐ 中級  
**所要時間**: 2〜3時間

## 学習目標

- Webサーバーアクセスログから攻撃の痕跡を発見する
- 攻撃パターンを正規表現で検出する
- 自動化されたアラートの仕組みを理解する

---

## セットアップ

```bash
# サンプルログファイルで演習を開始
ls sample-logs/

# ログ解析ツールを実行
python ../../tools/log/log_analyzer.py --file sample-logs/access.log
```

---

## 演習 1: ログの読み方

Apacheコモンログ形式:

```
IPアドレス - - [日時] "メソッド パス プロトコル" ステータス サイズ "リファラー" "UA"

例:
192.168.1.100 - - [27/Apr/2026:10:00:01 +0900] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

**重要なフィールド**:
| フィールド | 意味 | 監視のポイント |
|-----------|------|--------------|
| IPアドレス | リクエスト元 | 大量リクエストのIP |
| ステータス | HTTPレスポンスコード | 401(認証失敗), 404(存在しないページ) |
| パス | アクセスされたURL | 不審なパス, 管理画面へのアクセス |
| User-Agent | ブラウザ/ツール情報 | スキャンツールの特徴 |

---

## 演習 2: 攻撃パターンの検出

### 手動での検索

```bash
# SQLインジェクションの痕跡を検索
grep -i "union\|select\|insert\|drop\|sleep(" sample-logs/access.log

# ポートスキャン後のスキャナーを検索
grep -i "nikto\|sqlmap\|nmap\|masscan" sample-logs/access.log

# 404エラーが多いIP（ディレクトリスキャン疑い）
awk '$9 == 404 {print $1}' sample-logs/access.log | sort | uniq -c | sort -rn | head

# 認証失敗が多いIP（ブルートフォース疑い）
awk '$9 == 401 {print $1}' sample-logs/access.log | sort | uniq -c | sort -rn | head

# 管理ページへのアクセス
grep -i "wp-admin\|admin\|login\|phpmyadmin" sample-logs/access.log
```

### ツールを使った自動検出

```bash
# 詳細レポート
python ../../tools/log/log_analyzer.py --file sample-logs/access.log

# JSON形式で出力
python ../../tools/log/log_analyzer.py --file sample-logs/access.log --format json > report.json

# しきい値を調整
python ../../tools/log/log_analyzer.py \
    --file sample-logs/access.log \
    --bf-threshold 5 \
    --scan-threshold 20
```

---

## 演習 3: 攻撃タイムラインの再構築

1. 最初のスキャンはいつ始まったか？
2. どの攻撃ツールが使われたか？
3. 攻撃者はどのページに成功したか？
4. 何か重要なデータにアクセスされたか？

```bash
# 特定IPのアクセス履歴を時系列で確認
grep "10.0.0.5" sample-logs/access.log | awk '{print $4, $5, $6, $7, $9}'

# 成功したリクエスト（200番台）のみ表示
grep "10.0.0.5" sample-logs/access.log | awk '$9 ~ /^2/ {print $7, $9}'
```

---

## 演習 4: リアルタイム監視

```bash
# ログファイルをリアルタイムで監視（攻撃が来たら即座に検知）
tail -f /var/log/apache2/access.log | python exercises/realtime_monitor.py
```

---

## 演習 5: fail2ban の設定

```bash
# インストール
sudo apt install fail2ban -y

# /etc/fail2ban/jail.local
[apache-auth]
enabled = true
port    = http,https
logpath = %(apache_access_log)s
maxretry = 5
bantime = 3600

[apache-scanner]
enabled  = true
port     = http,https
filter   = apache-scanner
logpath  = %(apache_access_log)s
maxretry = 3
bantime  = 86400
```

---

## チェックリスト

- [ ] サンプルログから攻撃の痕跡を3種類以上発見した
- [ ] ブルートフォース攻撃を行ったIPを特定した
- [ ] ディレクトリスキャンを行ったIPを特定した
- [ ] SQLインジェクションの試みを発見した
- [ ] ログ解析ツールのレポートを読み解けた

## 次のステップ

→ `../05-incident-response/` へ進む
