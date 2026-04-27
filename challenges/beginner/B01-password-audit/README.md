# B01: パスワード監査チャレンジ

**難易度**: ⭐  
**テーマ**: 弱いパスワードの検出と安全なパスワード管理

## 問題

あなたはセキュリティ担当者です。社内システムのパスワードハッシュが漏洩しました。
`hashes.txt` に含まれるパスワードのうち、最も危険なパスワードを特定してください。

## ファイル

- `hashes.txt` - ユーザー名とパスワードハッシュ（MD5）
- `checker.py` - パスワード強度チェッカー

## 設問

1. `hashes.txt` の中に、よく使われる上位100パスワードに含まれるものがいくつありますか？
2. 最も短いパスワードは何文字ですか？
3. パスワードが "password" のユーザーは誰ですか？（フラグ）

## ヒント

```python
import hashlib

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

# 辞書攻撃のシミュレーション
common_passwords = ["password", "123456", "admin", "qwerty", "letmein"]
for pw in common_passwords:
    print(f"{pw}: {md5(pw)}")
```

## 解答の確認

フラグが見つかったら `checker.py` で検証してください:
```bash
python checker.py --flag "ACD{..."
```

---

## 学習ポイント

このチャレンジから学べること:
- MD5はパスワード保存に**絶対使ってはいけない**（虹の表、辞書攻撃に弱い）
- 安全なパスワードハッシュ: `bcrypt`, `scrypt`, `Argon2`
- パスワードポリシーの重要性

```python
# ✓ 安全なパスワードハッシュ（Python）
import bcrypt

password = b"my-secure-password"
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password, salt)

# 検証
bcrypt.checkpw(password, hashed)  # True
```
