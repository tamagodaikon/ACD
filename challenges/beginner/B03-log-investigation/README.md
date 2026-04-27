# B03: ログ捜査チャレンジ

**難易度**: ⭐  
**テーマ**: ログからの攻撃者特定

## 問題

Webサーバーが侵害されました。`../../labs/04-log-analysis/sample-logs/access.log` を解析して、以下の質問に答えてください。

## 設問

### 問1（基礎）
ログ中に登場する攻撃ツールの名前をすべて挙げてください。

### 問2（中級）
ブルートフォース攻撃（認証への繰り返し試行）を行ったIPアドレスはどれですか？  
何回失敗して、最終的に成功しましたか？

### 問3（応用 - フラグ）
SQLインジェクション攻撃を試みたIPアドレスを特定し、  
そのIPが実行した最も危険なSQLクエリを見つけてください。  
フラグ形式: `ACD{攻撃者のIP_使用したSQLキーワード}`

## コマンドヒント

```bash
# ログファイルのパス
LOG=../../labs/04-log-analysis/sample-logs/access.log

# 攻撃ツールを探す
grep -oP '"[^"]*"$' $LOG | sort -u

# ステータスコード別集計
awk '{print $9}' $LOG | sort | uniq -c | sort -rn

# 特定パターンの検索
grep -i "union\|select" $LOG
```

## 自動解析ツールも活用

```bash
python ../../tools/log/log_analyzer.py \
    --file ../../labs/04-log-analysis/sample-logs/access.log
```

## フラグの検証

```bash
# 例（実際のフラグは自分で調査して特定してください）
echo "ACD{10.0.0.XX_UNION_SELECT}" | python -c "
import sys
flag = sys.stdin.read().strip()
print('チェック中:', flag)
"
```
