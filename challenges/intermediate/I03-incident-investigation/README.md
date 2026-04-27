# I03: 侵入の足跡チャレンジ

**難易度**: ⭐⭐  
**テーマ**: インシデント調査

## シナリオ

あなたはSOCアナリストです。深夜に以下のアラートが届きました:

```
[ALERT] 2026-04-27 13:00:04
Source IP: 10.0.0.77
Event: Path Traversal Attack Detected
Target: /?page=../../../etc/passwd
Status: 200 OK
```

サーバーへの侵入を確認し、攻撃の全容を特定してください。

## 調査ファイル

- `../../labs/04-log-analysis/sample-logs/access.log`

## 調査タスク

### Task 1: 攻撃者のプロファイリング

10.0.0.77 からのすべてのリクエストを時系列で確認してください。

```bash
grep "10.0.0.77" ../../labs/04-log-analysis/sample-logs/access.log
```

**回答すべき質問**:
- 攻撃者が最初にアクセスした時刻は？
- どんなツールを使用したか？（User-Agentを確認）
- 何種類の攻撃を試みたか？

### Task 2: 成功した攻撃の特定

レスポンスコード200のリクエストのみを抽出してください。

```bash
grep "10.0.0.77" ../../labs/04-log-analysis/sample-logs/access.log | awk '$9 == 200'
```

**フラグ**: 成功した攻撃の中で、`/etc/passwd` にアクセスしたリクエストのパラメータ名は何ですか？  
形式: `ACD{パラメータ名_攻撃手法名}`

### Task 3: 対応策の立案

以下に対する具体的な対策を考えてください:
1. パストラバーサル攻撃への防御
2. ファイルインクルード脆弱性への防御
3. この攻撃者をブロックするfail2banルール

## 解答・解説

```bash
# パストラバーサルの対策（Python/Flask例）
import os

def safe_file_path(user_input, base_dir="/var/www/html"):
    # 正規化して base_dir の外に出ないことを確認
    requested = os.path.realpath(os.path.join(base_dir, user_input))
    if not requested.startswith(base_dir):
        raise ValueError("不正なパスアクセス")
    return requested
```
