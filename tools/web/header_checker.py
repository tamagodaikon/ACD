#!/usr/bin/env python3
"""
HTTP Security Header Checker - Webサーバーのセキュリティヘッダーをチェックするツール
"""

import urllib.request
import urllib.error
import ssl
import argparse
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HeaderCheck:
    name: str
    present: bool
    value: Optional[str]
    score: int
    max_score: int
    recommendation: str
    details: str = ""


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "score": 20,
        "recommendation": "max-age=31536000; includeSubDomains; preload",
        "details": "HTTPSを強制。中間者攻撃を防ぐ",
    },
    "Content-Security-Policy": {
        "score": 20,
        "recommendation": "default-src 'self'; script-src 'self'; object-src 'none'",
        "details": "XSS攻撃を軽減。信頼するリソースのみ許可",
    },
    "X-Frame-Options": {
        "score": 10,
        "recommendation": "DENY または SAMEORIGIN",
        "details": "クリックジャッキング攻撃を防ぐ",
    },
    "X-Content-Type-Options": {
        "score": 10,
        "recommendation": "nosniff",
        "details": "MIMEタイプスニッフィング攻撃を防ぐ",
    },
    "Referrer-Policy": {
        "score": 5,
        "recommendation": "strict-origin-when-cross-origin",
        "details": "リファラー情報の漏洩を防ぐ",
    },
    "Permissions-Policy": {
        "score": 5,
        "recommendation": "camera=(), microphone=(), geolocation=()",
        "details": "不要なブラウザ機能へのアクセスを制限",
    },
    "X-XSS-Protection": {
        "score": 5,
        "recommendation": "1; mode=block",
        "details": "古いブラウザのXSSフィルターを有効化（CSPの補完）",
    },
    "Cache-Control": {
        "score": 5,
        "recommendation": "no-store (機密ページ) または適切なキャッシュ設定",
        "details": "機密情報のキャッシュを防ぐ",
    },
}

DANGEROUS_HEADERS = {
    "Server": "サーバー情報の公開（バージョン情報を隠すべき）",
    "X-Powered-By": "技術スタックの公開（攻撃者に情報を与える）",
    "X-AspNet-Version": ".NETバージョンの公開",
    "X-AspNetMvc-Version": "ASP.NET MVCバージョンの公開",
}


def fetch_headers(url: str) -> dict:
    """URLのHTTPレスポンスヘッダーを取得"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={"User-Agent": "SecurityHeaderChecker/1.0"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return dict(resp.headers), resp.status, resp.url
    except urllib.error.HTTPError as e:
        return dict(e.headers), e.code, url
    except Exception as e:
        raise RuntimeError(f"接続エラー: {e}")


def check_headers(headers: dict) -> list:
    """セキュリティヘッダーを評価"""
    results = []
    headers_lower = {k.lower(): (k, v) for k, v in headers.items()}

    for header_name, config in SECURITY_HEADERS.items():
        header_lower = header_name.lower()
        if header_lower in headers_lower:
            _, value = headers_lower[header_lower]
            results.append(HeaderCheck(
                name=header_name,
                present=True,
                value=value,
                score=config["score"],
                max_score=config["score"],
                recommendation=config["recommendation"],
                details=config["details"],
            ))
        else:
            results.append(HeaderCheck(
                name=header_name,
                present=False,
                value=None,
                score=0,
                max_score=config["score"],
                recommendation=config["recommendation"],
                details=config["details"],
            ))

    return results


def check_dangerous_headers(headers: dict) -> list:
    """危険な情報漏洩ヘッダーをチェック"""
    found = []
    headers_lower = {k.lower(): (k, v) for k, v in headers.items()}

    for header_name, description in DANGEROUS_HEADERS.items():
        if header_name.lower() in headers_lower:
            _, value = headers_lower[header_name.lower()]
            found.append({"header": header_name, "value": value, "issue": description})

    return found


def check_https(url: str) -> dict:
    """HTTPSの設定をチェック"""
    result = {"uses_https": url.startswith("https://"), "redirects_to_https": False}

    if url.startswith("http://"):
        http_url = url
        try:
            req = urllib.request.Request(http_url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.url.startswith("https://"):
                    result["redirects_to_https"] = True
        except Exception:
            pass

    return result


def print_report(url: str, status: int, header_checks: list,
                 dangerous: list, https_info: dict, output_format: str = "text") -> None:
    total_score = sum(c.score for c in header_checks)
    max_score = sum(c.max_score for c in header_checks)
    percentage = int(total_score / max_score * 100) if max_score > 0 else 0

    if percentage >= 80:
        grade = "A"
    elif percentage >= 60:
        grade = "B"
    elif percentage >= 40:
        grade = "C"
    else:
        grade = "D"

    if output_format == "json":
        report = {
            "url": url,
            "status": status,
            "score": total_score,
            "max_score": max_score,
            "percentage": percentage,
            "grade": grade,
            "https": https_info,
            "headers": [
                {"name": c.name, "present": c.present, "value": c.value,
                 "score": c.score, "recommendation": c.recommendation}
                for c in header_checks
            ],
            "dangerous_headers": dangerous,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    print(f"\n{'='*65}")
    print(f"セキュリティヘッダー診断レポート")
    print(f"URL: {url}")
    print(f"ステータス: {status}")
    print(f"{'='*65}")

    print(f"\n【総合スコア】 {total_score}/{max_score} ({percentage}%) - グレード: {grade}")
    bar = "█" * (percentage // 5) + "░" * (20 - percentage // 5)
    print(f"  [{bar}]\n")

    print("【HTTPS設定】")
    https_ok = "✓" if https_info["uses_https"] else "✗"
    redirect_ok = "✓" if https_info["redirects_to_https"] else "-"
    print(f"  {https_ok} HTTPS使用: {https_info['uses_https']}")
    print(f"  {redirect_ok} HTTPSへのリダイレクト: {https_info['redirects_to_https']}")

    print("\n【セキュリティヘッダー】")
    present = [c for c in header_checks if c.present]
    missing = [c for c in header_checks if not c.present]

    print(f"\n  ✓ 設定済み ({len(present)}件):")
    for c in present:
        print(f"    [{c.score:2d}pt] {c.name}")
        print(f"           値: {c.value[:60]}")

    print(f"\n  ✗ 未設定 ({len(missing)}件):")
    for c in missing:
        print(f"    [  0/{c.max_score:2d}pt] {c.name}")
        print(f"           {c.details}")
        print(f"           推奨値: {c.recommendation}")

    if dangerous:
        print(f"\n【要注意ヘッダー】 ({len(dangerous)}件)")
        for d in dangerous:
            print(f"  [!] {d['header']}: {d['value']}")
            print(f"      → {d['issue']}")

    print(f"\n【改善の優先順位】")
    priority_fixes = sorted(missing, key=lambda x: x.max_score, reverse=True)
    for i, fix in enumerate(priority_fixes[:3], 1):
        print(f"  {i}. {fix.name} ({fix.max_score}pt回復)")
        print(f"     設定例: {fix.recommendation}")

    print(f"\n{'='*65}\n")


def main():
    parser = argparse.ArgumentParser(
        description="WebサーバーのHTTPセキュリティヘッダーをチェック"
    )
    parser.add_argument("--url", required=True, help="チェック対象URL (例: https://example.com)")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="出力形式")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"[*] チェック中: {url}")

    try:
        headers, status, final_url = fetch_headers(url)
        header_checks = check_headers(headers)
        dangerous = check_dangerous_headers(headers)
        https_info = check_https(url)
        print_report(final_url, status, header_checks, dangerous, https_info, args.format)
    except RuntimeError as e:
        print(f"[!] エラー: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
