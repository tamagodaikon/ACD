#!/usr/bin/env python3
"""
Port Scanner - 自分のシステムの開放ポートを確認するためのツール
使用目的: 自分が所有または許可を得たシステムのみに使用してください
"""

import socket
import argparse
import concurrent.futures
import ipaddress
from datetime import datetime


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

RISKY_PORTS = {23: "Telnet (暗号化なし)", 21: "FTP (平文認証)", 3389: "RDP (ブルートフォース対象)"}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            try:
                banner = grab_banner(host, port)
            except Exception:
                banner = ""
            return {"port": port, "state": "open", "service": service, "banner": banner}
    except Exception:
        pass
    return {"port": port, "state": "closed"}


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in (80, 8080, 8443, 443):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:100]
    except Exception:
        return ""


def validate_target(target: str) -> str:
    try:
        ip = ipaddress.ip_address(target)
        if not (ip.is_loopback or ip.is_private):
            print(f"[!] 警告: {target} はプライベートIPではありません")
            print("[!] このツールは自分のシステムまたは許可を得たシステムにのみ使用してください")
            confirm = input("[?] 続行しますか？ (yes/no): ")
            if confirm.lower() != "yes":
                raise SystemExit("スキャンを中止しました")
        return target
    except ValueError:
        return target


def print_report(host: str, open_ports: list, start_time: datetime) -> None:
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n{'='*60}")
    print(f"スキャン結果: {host}")
    print(f"スキャン時刻: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"所要時間: {elapsed:.2f}秒")
    print(f"{'='*60}")

    if not open_ports:
        print("開放ポートは見つかりませんでした")
        return

    print(f"\n[+] 開放ポート: {len(open_ports)}個\n")
    print(f"{'PORT':<10} {'SERVICE':<15} {'BANNER'}")
    print("-" * 60)

    for p in sorted(open_ports, key=lambda x: x["port"]):
        banner_preview = p["banner"][:40] if p["banner"] else ""
        print(f"{p['port']:<10} {p['service']:<15} {banner_preview}")

    risks = [p for p in open_ports if p["port"] in RISKY_PORTS]
    if risks:
        print(f"\n[!] セキュリティ上の注意:")
        for p in risks:
            print(f"    Port {p['port']}: {RISKY_PORTS[p['port']]}")

    print(f"\n[i] 推奨アクション:")
    print("    - 不要なポートはファイアウォールで閉じる")
    print("    - Telnet/FTPはSSH/SFTPに移行する")
    print("    - 公開不要なサービスはlocalhostのみにバインドする")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="ポートスキャナー - 自分のシステムのセキュリティ確認用",
        epilog="例: python port_scanner.py --target 127.0.0.1 --ports 1-1024"
    )
    parser.add_argument("--target", default="127.0.0.1", help="スキャン対象ホスト (デフォルト: 127.0.0.1)")
    parser.add_argument("--ports", default="1-1024", help="ポート範囲 例: 1-1024 または 22,80,443")
    parser.add_argument("--threads", type=int, default=50, help="並列スレッド数 (デフォルト: 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="接続タイムアウト秒数")
    args = parser.parse_args()

    target = validate_target(args.target)

    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = list(range(start, end + 1))
    else:
        ports = [int(p) for p in args.ports.split(",")]

    print(f"\n[*] スキャン開始: {target}")
    print(f"[*] ポート範囲: {args.ports} ({len(ports)}ポート)")
    print(f"[*] スレッド数: {args.threads}\n")

    start_time = datetime.now()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, target, port, args.timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                open_ports.append(result)
                print(f"[+] PORT {result['port']:5d}/tcp  open  {result['service']}")

    print_report(target, open_ports, start_time)


if __name__ == "__main__":
    main()
