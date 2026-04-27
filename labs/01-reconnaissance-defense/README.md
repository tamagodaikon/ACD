# Lab 01: 偵察攻撃の検知と防御

**難易度**: ⭐ 入門  
**所要時間**: 90〜120分

## 学習目標

- 攻撃者がどのように偵察（Reconnaissance）を行うかを理解する
- 自分のシステムが「外から何に見えているか」を把握する
- 偵察を検知・妨害するための防御設定を実装する

---

## 背景知識

攻撃のほとんどは**偵察から始まります**。攻撃者はターゲットを攻撃する前に:

1. **パッシブ偵察**: ターゲットに直接触れずに情報収集
   - WHOIS、DNS情報の調査
   - LinkedIn等で従業員・技術スタック調査
   - Google Dorking（`site:` `filetype:` 等の検索演算子）

2. **アクティブ偵察**: ターゲットに直接アクセスして情報収集
   - ポートスキャン（nmap等）
   - サービスバナーの取得
   - ディレクトリ探索（dirbuster等）

---

## 演習 1: 自分のサーバーを「攻撃者視点」で見る

### 1-1. 開放ポートの確認

```bash
# 自分のサーバーのポートスキャン
python ../../tools/network/port_scanner.py --target 127.0.0.1 --ports 1-65535

# または nmap を使う場合
nmap -sV -sC -p- 127.0.0.1
```

**確認ポイント**:
- [ ] 意図していないポートが開いていないか？
- [ ] サービスのバージョン情報が漏洩していないか？
- [ ] 外部から接続不要なサービスが外向きになっていないか？

### 1-2. バナー情報の確認

```bash
# HTTPサーバーのバナー取得
curl -I http://localhost/

# SSH バナーの確認
nc -w 3 localhost 22
```

**理想的な状態**:
- Webサーバー: `Server: Apache` のみ（バージョン番号なし）
- SSH: カスタムバナーメッセージなし（デフォルトのOpenSSHバージョンを隠す）

---

## 演習 2: バナー情報を隠す

### Apache の設定

```apache
# /etc/apache2/conf-available/security.conf
ServerTokens Prod        # "Apache" のみ表示（バージョン非表示）
ServerSignature Off      # エラーページからバージョン情報を削除
```

### Nginx の設定

```nginx
# /etc/nginx/nginx.conf の http ブロック内
server_tokens off;       # バージョン情報を非表示
```

### SSH の設定

```bash
# /etc/ssh/sshd_config
DebianBanner no
Banner /etc/ssh/banner.txt  # カスタムバナー（"Unauthorized access prohibited"等）
```

---

## 演習 3: ポートスキャンを検知する

### fail2ban でスキャンを検知

```bash
# fail2ban のインストール
sudo apt install fail2ban -y

# /etc/fail2ban/jail.local に追加
[port-scan]
enabled = true
filter = portscan
action = iptables[name=portscan, port=all, protocol=tcp]
logpath = /var/log/kern.log
maxretry = 5
bantime = 3600
```

### Snort/Suricata でIDS設定

詳細は `exercises/ids-setup.md` を参照

---

## 演習 4: ハニーポットの設置

**ハニーポット**とは: 攻撃者を誘き寄せて、行動を記録するためのおとりシステム

```bash
# シンプルなハニーポット（不使用ポートへのアクセスを検知）
python exercises/honeypot.py --port 8888 --log honeypot.log
```

実装は `exercises/honeypot.py` を参照してください。

---

## チェックリスト

このラボ完了後に確認:

- [ ] 自分のサーバーの開放ポートをすべて把握した
- [ ] 不要なポートをファイアウォールでブロックした
- [ ] Webサーバーのバージョン情報を隠した
- [ ] ポートスキャンを検知する仕組みを設定した
- [ ] ハニーポットの概念を理解した

## 次のステップ

→ `../02-network-security/` へ進む
