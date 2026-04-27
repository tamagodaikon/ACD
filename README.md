# ACD - Active Cyber Defense Learning Environment

自主学習のためのサイバー攻撃対策（防御的セキュリティ）環境です。  
This is a self-study environment for learning Active Cyber Defense.

## 概要 / Overview

本リポジトリは、実際の攻撃手法を理解し、適切な防御策を学ぶための体系的な環境を提供します。  
すべてのラボは**隔離された安全な環境**で実行することを前提としています。

## ディレクトリ構成 / Structure

```
ACD/
├── docs/               # カリキュラムとリソース
│   ├── curriculum.md   # 学習カリキュラム
│   ├── learning-path.md
│   └── resources.md
├── labs/               # ハンズオンラボ
│   ├── 01-reconnaissance-defense/   # 偵察攻撃の検知と防御
│   ├── 02-network-security/         # ネットワークセキュリティ
│   ├── 03-web-security/             # Webアプリケーションセキュリティ
│   ├── 04-log-analysis/             # ログ解析と異常検知
│   └── 05-incident-response/        # インシデントレスポンス
├── tools/              # 防御ツール集
│   ├── network/        # ネットワーク監視ツール
│   ├── web/            # Webセキュリティ診断ツール
│   └── log/            # ログ解析ツール
├── challenges/         # CTF形式の練習問題
│   ├── beginner/
│   ├── intermediate/
│   └── advanced/
└── docker-compose.yml  # 練習環境のセットアップ
```

## 学習ロードマップ / Learning Roadmap

```
Phase 1: 基礎知識          Phase 2: 攻撃の理解         Phase 3: 防御の実装
─────────────────────     ─────────────────────────    ─────────────────────
• ネットワーク基礎    →    • 偵察・スキャン手法    →    • ファイアウォール設定
• Linux/CLI スキル        • Webアプリ攻撃              • IDS/IPS の運用
• 暗号・認証の仕組み      • マルウェアの動作           • ログ監視と分析
                          • ソーシャルエンジニア        • インシデント対応
                            リング
```

## クイックスタート / Quick Start

### 1. 前提ツールのインストール

```bash
# Docker & Docker Compose
sudo apt install docker.io docker-compose -y

# Python依存パッケージ
pip install -r requirements.txt

# ラボ環境の起動
docker-compose up -d
```

### 2. 学習の開始

```bash
# カリキュラムを確認
cat docs/curriculum.md

# 最初のラボへ
cd labs/01-reconnaissance-defense
cat README.md
```

### 3. 防御ツールの実行

```bash
# ネットワークスキャン（自分の環境のみ）
python tools/network/port_scanner.py --target 127.0.0.1

# Webセキュリティヘッダーチェック
python tools/web/header_checker.py --url http://localhost:8080

# ログ解析
python tools/log/log_analyzer.py --file labs/04-log-analysis/sample-logs/access.log
```

## 重要な注意事項 / Important Notes

> **法的・倫理的注意**: 本環境で学んだ技術は、**自分が所有または明示的に許可を得たシステムにのみ**使用してください。
> 無許可のシステムへの攻撃は、不正アクセス禁止法等の法律に違反します。
>
> **Legal Notice**: Apply all techniques learned here **only to systems you own or have explicit authorization to test**.
> Unauthorized access is illegal and unethical.

## ラボ一覧 / Labs

| # | ラボ名 | テーマ | 難易度 |
|---|--------|--------|--------|
| 01 | 偵察防御 | ポートスキャン検知・ハニーポット | ⭐ |
| 02 | ネットワークセキュリティ | パケット解析・ファイアウォール | ⭐⭐ |
| 03 | Webセキュリティ | SQLi・XSS・CSRF の検知と防御 | ⭐⭐ |
| 04 | ログ解析 | 攻撃パターンの検出 | ⭐⭐⭐ |
| 05 | インシデントレスポンス | 侵害対応シナリオ | ⭐⭐⭐ |

## 参考資料 / References

詳細は `docs/resources.md` を参照してください。
