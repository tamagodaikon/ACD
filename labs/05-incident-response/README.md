# Lab 05: インシデントレスポンス

**難易度**: ⭐⭐⭐ 中〜上級  
**所要時間**: 3〜4時間

## 学習目標

- インシデントレスポンスの手順（PICERL）を実践する
- 侵害の痕跡（IOC）を特定する
- 封じ込めと復旧の手順を習得する

---

## インシデントレスポンスフレームワーク（PICERL）

```
1. Preparation     │ 準備: ツール・手順・体制の整備
2. Identification  │ 検知・識別: 何が起きているか？
3. Containment     │ 封じ込め: 被害の拡大を止める
4. Eradication     │ 根絶: 攻撃者を排除する
5. Recovery        │ 復旧: 正常運用に戻す
6. Lessons Learned │ 教訓: 再発防止策を立てる
```

---

## シナリオ 1: Webサーバー侵害

### 状況

監視システムが以下のアラートを発出しました:
- サーバーからの異常な外部通信（10.0.0.99:4444 へのTCP接続）
- 深夜2時に新規ユーザーアカウントが作成された
- `/var/www/html/` に見覚えのないPHPファイルが出現

### 手順

**Step 1: 識別 (Identification)**

```bash
# 現在のネットワーク接続を確認
ss -tulpn
netstat -antup

# 不審なプロセスを確認
ps auxf
lsof -i

# 最近作成・変更されたファイルを確認
find /var/www/html -mtime -1 -type f
find / -name "*.php" -newer /var/www/html/index.php 2>/dev/null

# ユーザーアカウントを確認
cat /etc/passwd | grep -v nologin
last -20
lastlog | grep -v "Never logged"
```

**Step 2: 封じ込め (Containment)**

```bash
# 不審なネットワーク接続を切断（必要に応じて）
# iptables でIPをブロック
sudo iptables -A INPUT -s 10.0.0.99 -j DROP
sudo iptables -A OUTPUT -d 10.0.0.99 -j DROP

# 侵害されたアカウントを無効化
sudo usermod -L suspicious_user

# WebシェルをWebから隔離（削除前にバックアップ）
sudo cp /var/www/html/shell.php /tmp/evidence/
sudo chmod 000 /var/www/html/shell.php
```

**Step 3: フォレンジクス**

```bash
# Webシェルの解析
cat /tmp/evidence/shell.php
# → PHP実行関数, Base64エンコード, eval() の使用を確認

# 攻撃者のコマンド履歴を確認（bashが使われた場合）
cat /home/attacker/.bash_history

# 変更されたシステムファイル
rpm -Va 2>/dev/null | grep "^..5"    # RPMベース
debsums -c 2>/dev/null                # Debianベース

# Webサーバーログで攻撃の全容を把握
grep "shell.php" /var/log/apache2/access.log
```

**Step 4: 根絶 (Eradication)**

```bash
# バックドアの削除
sudo rm -f /var/www/html/shell.php
sudo rm -f /var/www/html/cmd.php

# 不正ユーザーの削除
sudo userdel -r suspicious_user

# ファイアウォールルールの永続化
sudo iptables-save > /etc/iptables/rules.v4
```

**Step 5: 復旧 (Recovery)**

```bash
# バックアップからの復元（侵害前のもの）
sudo rsync -av /backup/www/ /var/www/html/

# 整合性チェック
sha256sum -c /backup/checksums.txt

# サービス再起動
sudo systemctl restart apache2

# 監視強化
sudo tail -f /var/log/apache2/access.log
```

---

## シナリオ 2: ランサムウェア感染

### 状況

社内のWindowsワークステーションで:
- 大量のファイルが `.encrypted` 拡張子に変更された
- 身代金要求のメッセージが出現
- ネットワーク共有フォルダに感染が広がっている

### 初動対応チェックリスト

```
即座に実行:
□ 感染端末のネットワークケーブルを抜く（WiFiを無効化）
□ 共有フォルダへのアクセスを停止
□ 感染の範囲を確認（他の端末への感染調査）
□ バックアップメディアをオフラインに

30分以内:
□ インシデントの記録開始（何時に何を発見したか）
□ 経営層・法務・広報への報告
□ バックアップの最終日時を確認
□ ランサムウェアの種類を特定（CryptoSherrif等のサービスで確認）

数時間以内:
□ フォレンジクス保全（証拠の保全）
□ 感染経路の調査（フィッシングメール、RDP脆弱性等）
□ 規制当局への報告要否の確認（個人情報保護法等）
```

---

## インシデントレポートのテンプレート

`scenarios/incident-report-template.md` を参照

---

## チェックリスト

- [ ] PICERLフレームワークの各ステップを理解した
- [ ] Webサーバー侵害シナリオの初動対応を実践した
- [ ] 不審なファイル・プロセス・接続の確認コマンドを習得した
- [ ] ランサムウェア対応の優先順位を理解した
- [ ] インシデントレポートを作成した

## 完了おめでとうございます！

全ラボを完了しました。次のステップ:
- `challenges/` で実力を試す
- TryHackMe / Hack The Box で実際のマシンに挑戦
- `docs/resources.md` で認定資格の学習を開始
