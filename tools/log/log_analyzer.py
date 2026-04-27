#!/usr/bin/env python3
"""
Log Analyzer - ログファイルから攻撃パターンを検出するツール
Webサーバーアクセスログ (Apache/Nginx 共通ログ形式) に対応
"""

import re
import argparse
import json
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path


# 攻撃パターン検出ルール
ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b)",
        r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\()",
        r"(?i)(\bor\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+|admin[\'\"]?\s*--)",
        r"(?i)(information_schema|sys\.tables|sysobjects)",
        r"'(\s*(or|and)\s*'?1'?\s*=\s*'?1)",
    ],
    "XSS": [
        r"(?i)<script[^>]*>",
        r"(?i)(javascript:|vbscript:|data:text/html)",
        r"(?i)on(load|error|click|mouseover|focus)\s*=",
        r"(?i)(alert|confirm|prompt)\s*\(",
    ],
    "Path Traversal": [
        r"\.\./",
        r"(?i)(etc/passwd|etc/shadow|win/system32)",
        r"%2e%2e%2f",
        r"(?i)\.\./\.\./",
    ],
    "Command Injection": [
        r"(?i)(\bwget\b|\bcurl\b|\bnc\b|\bnetcat\b).*http",
        r"[;&|`]\s*(ls|cat|id|whoami|uname|pwd|echo)",
        r"(?i)\$\(.*\)",
    ],
    "Scanner/Bot": [
        r"(?i)(sqlmap|nikto|nessus|burpsuite|nmap|masscan)",
        r"(?i)(python-requests|go-http-client|libwww-perl).*scan",
        r"(?i)(dirbuster|gobuster|wfuzz|ffuf)",
    ],
    "Brute Force (Auth)": [
        r"(?i)(wp-login|admin/login|login\.php|signin)",
    ],
    "File Inclusion": [
        r"(?i)(php://|file://|expect://|zip://)",
        r"(?i)(include|require).*\.php\?",
    ],
    "Sensitive Files": [
        r"(?i)(\.(env|git|svn|htpasswd|htaccess|bak|backup|sql|dump))",
        r"(?i)(web\.config|application\.yml|database\.yml|secrets\.yml)",
        r"(?i)(\.aws/credentials|\.ssh/id_rsa)",
    ],
}

# Apacheコモンログ形式のパターン
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)")?'
)


def parse_log_line(line: str) -> dict | None:
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    return m.groupdict()


def detect_attacks(entry: dict) -> list:
    """1ログエントリに対して攻撃パターンを検出"""
    found = []
    target = f"{entry.get('path', '')} {entry.get('useragent', '')}"

    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, target):
                found.append(attack_type)
                break

    return found


def analyze_brute_force(ip_status: dict, threshold: int = 10) -> list:
    """特定IPからの認証失敗を検出"""
    suspects = []
    for ip, statuses in ip_status.items():
        fail_count = sum(1 for s in statuses if s in ("401", "403"))
        if fail_count >= threshold:
            suspects.append({"ip": ip, "failures": fail_count})
    return sorted(suspects, key=lambda x: x["failures"], reverse=True)


def analyze_scanning(ip_paths: dict, threshold: int = 30) -> list:
    """大量のパスへのアクセスを検出（スキャン行動）"""
    suspects = []
    for ip, paths in ip_paths.items():
        unique_paths = len(set(paths))
        if unique_paths >= threshold:
            suspects.append({"ip": ip, "unique_paths": unique_paths, "total_requests": len(paths)})
    return sorted(suspects, key=lambda x: x["unique_paths"], reverse=True)


def analyze_log_file(filepath: str, threshold_bf: int = 10,
                     threshold_scan: int = 30) -> dict:
    """ログファイル全体を解析"""
    attack_events = []
    ip_requests = defaultdict(int)
    ip_status = defaultdict(list)
    ip_paths = defaultdict(list)
    status_counter = Counter()
    total_lines = 0
    parse_errors = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total_lines += 1

            entry = parse_log_line(line)
            if not entry:
                parse_errors += 1
                continue

            ip = entry["ip"]
            ip_requests[ip] += 1
            ip_status[ip].append(entry["status"])
            ip_paths[ip].append(entry.get("path", ""))
            status_counter[entry["status"]] += 1

            attacks = detect_attacks(entry)
            if attacks:
                attack_events.append({
                    "time": entry.get("time", ""),
                    "ip": ip,
                    "method": entry.get("method", ""),
                    "path": entry.get("path", "")[:100],
                    "status": entry.get("status", ""),
                    "attacks": attacks,
                })

    brute_force = analyze_brute_force(ip_status, threshold_bf)
    scanning = analyze_scanning(ip_paths, threshold_scan)

    top_ips = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "summary": {
            "total_lines": total_lines,
            "parse_errors": parse_errors,
            "attack_events": len(attack_events),
            "unique_ips": len(ip_requests),
        },
        "status_distribution": dict(status_counter.most_common(10)),
        "attack_events": attack_events[:50],
        "brute_force_suspects": brute_force[:10],
        "scanning_suspects": scanning[:10],
        "top_ips": top_ips,
    }


def print_report(results: dict, output_format: str = "text") -> None:
    if output_format == "json":
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return

    s = results["summary"]
    print(f"\n{'='*65}")
    print("ログ解析レポート")
    print(f"{'='*65}")
    print(f"\n【サマリー】")
    print(f"  総ログ行数:     {s['total_lines']:,}")
    print(f"  ユニークIP数:   {s['unique_ips']:,}")
    print(f"  攻撃イベント数: {s['attack_events']:,}")
    print(f"  パースエラー:   {s['parse_errors']:,}")

    print(f"\n【ステータスコード分布】")
    for status, count in results["status_distribution"].items():
        bar = "█" * min(count // 10, 30)
        print(f"  {status}: {count:6,} {bar}")

    if results["attack_events"]:
        print(f"\n【検出された攻撃 (上位10件)】")
        for ev in results["attack_events"][:10]:
            print(f"  [{ev['time']}] {ev['ip']}")
            print(f"    {ev['method']} {ev['path'][:60]}")
            print(f"    攻撃タイプ: {', '.join(ev['attacks'])}")
            print()

        attack_types = Counter()
        for ev in results["attack_events"]:
            for a in ev["attacks"]:
                attack_types[a] += 1
        print(f"【攻撃タイプ別集計】")
        for atype, count in attack_types.most_common():
            print(f"  {atype:<25}: {count}件")

    if results["brute_force_suspects"]:
        print(f"\n【ブルートフォース疑い ({len(results['brute_force_suspects'])}件)】")
        for s in results["brute_force_suspects"][:5]:
            print(f"  {s['ip']:<20} 認証失敗: {s['failures']}回")

    if results["scanning_suspects"]:
        print(f"\n【スキャン疑い ({len(results['scanning_suspects'])}件)】")
        for s in results["scanning_suspects"][:5]:
            print(f"  {s['ip']:<20} ユニークパス: {s['unique_paths']} 総リクエスト: {s['total_requests']}")

    suspect_ips = set(
        [b["ip"] for b in results["brute_force_suspects"]] +
        [s["ip"] for s in results["scanning_suspects"]] +
        [e["ip"] for e in results["attack_events"]]
    )
    if suspect_ips:
        print(f"\n【推奨: ブロック対象IP ({len(suspect_ips)}件)】")
        for ip in sorted(suspect_ips)[:10]:
            print(f"  iptables -A INPUT -s {ip} -j DROP")

    print(f"\n{'='*65}\n")


def main():
    parser = argparse.ArgumentParser(
        description="ログ解析ツール - アクセスログから攻撃パターンを検出"
    )
    parser.add_argument("--file", required=True, help="解析するログファイルパス")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--bf-threshold", type=int, default=10,
                        help="ブルートフォース検出のしきい値 (デフォルト:10)")
    parser.add_argument("--scan-threshold", type=int, default=30,
                        help="スキャン検出のしきい値 (デフォルト:30)")
    args = parser.parse_args()

    log_path = Path(args.file)
    if not log_path.exists():
        print(f"[!] ファイルが見つかりません: {args.file}")
        raise SystemExit(1)

    print(f"[*] ログ解析中: {args.file}")
    results = analyze_log_file(str(log_path), args.bf_threshold, args.scan_threshold)
    print_report(results, args.format)


if __name__ == "__main__":
    main()
