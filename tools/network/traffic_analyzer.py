#!/usr/bin/env python3
"""
Traffic Analyzer - ネットワーク接続を監視して不審な通信を検知するツール
※ root権限またはCAP_NET_ADMIN が必要な場合があります
"""

import subprocess
import re
import socket
import argparse
from collections import defaultdict
from datetime import datetime


SUSPICIOUS_PORTS = {
    1337, 4444, 5555, 6666, 6667, 7777, 8888, 9999,  # よくあるC2/バックドアポート
    31337, 12345, 54321,
}

KNOWN_MALICIOUS_PATTERNS = [
    r"\.onion$",           # Tor ドメイン
    r"pastebin\.com",      # マルウェアがよく使うデータ外部送信先
    r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}",  # IPアドレスを使ったドメイン
]


def get_active_connections() -> list:
    """現在のネットワーク接続を取得"""
    connections = []
    try:
        result = subprocess.run(
            ["ss", "-tulpn"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    "proto": parts[0],
                    "state": parts[1],
                    "local": parts[4],
                    "remote": parts[5] if len(parts) > 5 else "*",
                    "process": parts[-1] if "pid=" in parts[-1] else "unknown"
                })
    except Exception as e:
        print(f"[!] 接続情報取得エラー: {e}")
    return connections


def get_established_connections() -> list:
    """確立済み接続を取得"""
    connections = []
    try:
        result = subprocess.run(
            ["ss", "-tnp", "state", "established"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")[1:]
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                local_addr = parts[3]
                remote_addr = parts[4] if len(parts) > 4 else "?"
                process = parts[-1] if "pid=" in parts[-1] else "unknown"
                connections.append({
                    "local": local_addr,
                    "remote": remote_addr,
                    "process": process,
                })
    except Exception as e:
        print(f"[!] 確立済み接続取得エラー: {e}")
    return connections


def analyze_connection(conn: dict) -> list:
    """接続の不審点を分析"""
    warnings = []
    remote = conn.get("remote", "")

    # 不審なポートのチェック
    try:
        if ":" in remote:
            remote_port = int(remote.rsplit(":", 1)[-1])
            if remote_port in SUSPICIOUS_PORTS:
                warnings.append(f"不審なポート {remote_port} への接続")
    except ValueError:
        pass

    # 既知の悪性パターンのチェック
    for pattern in KNOWN_MALICIOUS_PATTERNS:
        if re.search(pattern, remote):
            warnings.append(f"不審なパターン検出: {pattern}")

    return warnings


def resolve_ip(ip: str) -> str:
    """IPアドレスをホスト名に解決"""
    try:
        clean_ip = ip.rsplit(":", 1)[0] if ":" in ip else ip
        return socket.gethostbyaddr(clean_ip)[0]
    except Exception:
        return ""


def monitor_connections(interval: int = 5, count: int = None) -> None:
    """接続を継続的に監視"""
    iteration = 0
    seen_connections = set()

    print(f"[*] 接続監視開始 (間隔: {interval}秒)")
    print("[*] Ctrl+C で終了\n")

    try:
        while count is None or iteration < count:
            connections = get_established_connections()
            current = set()

            for conn in connections:
                key = f"{conn['local']}->{conn['remote']}"
                current.add(key)

                if key not in seen_connections:
                    warnings = analyze_connection(conn)
                    timestamp = datetime.now().strftime("%H:%M:%S")

                    if warnings:
                        print(f"[!] {timestamp} 新規接続 (要注意): {key}")
                        for w in warnings:
                            print(f"    警告: {w}")
                        print(f"    プロセス: {conn['process']}")
                    else:
                        print(f"[+] {timestamp} 新規接続: {key} [{conn['process']}]")

            # 切断された接続
            for key in seen_connections - current:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[-] {timestamp} 接続終了: {key}")

            seen_connections = current
            iteration += 1

            if count is None or iteration < count:
                import time
                time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[*] 監視を終了します")


def show_snapshot() -> None:
    """現在の接続状況を表示"""
    print(f"\n{'='*60}")
    print(f"接続スナップショット: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    print("[リスニングポート]")
    connections = get_active_connections()
    for conn in connections:
        print(f"  {conn['proto']:<6} {conn['local']:<30} {conn['process']}")

    print("\n[確立済み接続]")
    established = get_established_connections()
    if not established:
        print("  確立済み接続なし")
    else:
        suspicious = []
        for conn in established:
            warnings = analyze_connection(conn)
            status = "[!] 要注意" if warnings else "[+]"
            print(f"  {status} {conn['local']:<30} -> {conn['remote']}")
            if warnings:
                suspicious.append((conn, warnings))

        if suspicious:
            print(f"\n[!] 不審な接続: {len(suspicious)}件")
            for conn, warnings in suspicious:
                print(f"\n  接続: {conn['local']} -> {conn['remote']}")
                print(f"  プロセス: {conn['process']}")
                for w in warnings:
                    print(f"  警告: {w}")

    print(f"\n{'='*60}")
    print("[推奨アクション]")
    print("  - 不明なプロセスの外部接続を調査する")
    print("  - 不要なリスニングポートを無効化する")
    print("  - ファイアウォールで不要な通信をブロックする")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="ネットワーク接続モニター - 不審な通信を検知するツール"
    )
    parser.add_argument("--monitor", action="store_true", help="継続的な監視モード")
    parser.add_argument("--interval", type=int, default=5, help="監視間隔(秒)")
    args = parser.parse_args()

    if args.monitor:
        monitor_connections(interval=args.interval)
    else:
        show_snapshot()


if __name__ == "__main__":
    main()
