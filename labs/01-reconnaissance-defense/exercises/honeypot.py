#!/usr/bin/env python3
"""
Simple Honeypot - 不審なアクセスを検知してログを記録するハニーポット
学習用: ポートへの接続試行を検知して攻撃者の行動を観察する
"""

import socket
import threading
import logging
import argparse
import json
from datetime import datetime


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class HoneypotListener:
    def __init__(self, port: int, log_file: str, banner: str):
        self.port = port
        self.log_file = log_file
        self.banner = banner
        self.connection_count = 0
        self.lock = threading.Lock()

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logging.getLogger().addHandler(file_handler)

    def handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        ip, port = addr
        timestamp = datetime.now().isoformat()

        with self.lock:
            self.connection_count += 1
            count = self.connection_count

        log_entry = {
            "event": "connection",
            "id": count,
            "timestamp": timestamp,
            "source_ip": ip,
            "source_port": port,
            "honeypot_port": self.port,
        }

        logging.warning(f"[HONEYPOT] 接続検知 #{count}: {ip}:{port} -> :{self.port}")

        try:
            if self.banner:
                conn.send((self.banner + "\r\n").encode())

            conn.settimeout(5)
            try:
                data = conn.recv(1024)
                if data:
                    log_entry["data_received"] = data.decode("utf-8", errors="replace")[:200]
                    logging.warning(f"[HONEYPOT] データ受信 from {ip}: {log_entry['data_received'][:80]}")
            except socket.timeout:
                pass

        except Exception as e:
            log_entry["error"] = str(e)
        finally:
            conn.close()

        with open(self.log_file + ".json", "a") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind(("0.0.0.0", self.port))
            server.listen(5)
            logging.info(f"[HONEYPOT] ポート {self.port} で待機中...")
            logging.info(f"[HONEYPOT] ログファイル: {self.log_file}")
            logging.info("[HONEYPOT] Ctrl+C で停止")

            while True:
                conn, addr = server.accept()
                t = threading.Thread(target=self.handle_connection, args=(conn, addr))
                t.daemon = True
                t.start()

        except PermissionError:
            print(f"[!] ポート {self.port} へのバインドに失敗しました。")
            print("[!] 1024未満のポートはroot権限が必要です。1024以上のポートを使用してください。")
            raise SystemExit(1)
        except KeyboardInterrupt:
            logging.info(f"[HONEYPOT] 停止。総接続数: {self.connection_count}")
        finally:
            server.close()


def main():
    parser = argparse.ArgumentParser(
        description="ハニーポット - 不審なアクセスを検知して記録"
    )
    parser.add_argument("--port", type=int, default=8888, help="リスンするポート (デフォルト: 8888)")
    parser.add_argument("--log", default="honeypot.log", help="ログファイルパス")
    parser.add_argument("--banner", default="SSH-2.0-OpenSSH_7.4",
                        help="接続時に返すバナー文字列")
    args = parser.parse_args()

    print(f"[*] ハニーポット起動")
    print(f"[*] ポート: {args.port}")
    print(f"[*] ログ: {args.log}")
    print("[*] このポートへの接続は記録されます\n")

    hp = HoneypotListener(args.port, args.log, args.banner)
    hp.start()


if __name__ == "__main__":
    main()
