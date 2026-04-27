#!/usr/bin/env python3
"""B01 チャレンジ - フラグ検証と解説ツール"""

import hashlib
import argparse


CORRECT_FLAG = "ACD{alice_uses_password_md5_is_broken}"

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "admin",
]


def md5_hash(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def crack_hashes(filename: str) -> None:
    print("\n[*] MD5ハッシュの辞書攻撃シミュレーション")
    print("[!] これは学習目的のデモです。自分のシステム以外には使用しないこと\n")

    with open(filename) as f:
        lines = [l.strip() for l in f if not l.startswith("#") and ":" in l]

    cracked = 0
    for line in lines:
        username, hash_val = line.split(":", 1)
        for pw in COMMON_PASSWORDS:
            if md5_hash(pw) == hash_val:
                print(f"[!] クラック成功: {username} → '{pw}'")
                cracked += 1
                break
        else:
            print(f"[ ] クラック失敗: {username}")

    print(f"\n結果: {cracked}/{len(lines)} アカウントが弱いパスワードを使用")


def check_flag(flag: str) -> None:
    if flag == CORRECT_FLAG:
        print("\n✓ 正解！フラグが正しいです")
        print(f"  フラグ: {flag}")
        print("\n【解説】")
        print("  alice のパスワード 'password' の MD5 は:")
        print(f"  5f4dcc3b5aa765d61d8327deb882cf99")
        print("\n  MD5 の問題点:")
        print("  1. 高速なハッシュ（GPUで毎秒数十億回計算可能）")
        print("  2. 虹の表（事前計算されたハッシュ辞書）が存在")
        print("  3. ソルトなしの場合、同じパスワードは同じハッシュになる")
        print("\n  安全な代替手段: bcrypt, scrypt, Argon2")
    else:
        print("\n✗ 不正解です。もう一度 hashes.txt を分析してみましょう")
        print("\nヒント: MD5('password') を計算して hashes.txt と比較してみてください")
        print("  python3 -c \"import hashlib; print(hashlib.md5(b'password').hexdigest())\"")


def main():
    parser = argparse.ArgumentParser(description="B01 パスワード監査チャレンジ")
    parser.add_argument("--crack", metavar="FILE", help="ハッシュファイルを辞書攻撃でクラック")
    parser.add_argument("--flag", metavar="FLAG", help="フラグを検証")
    args = parser.parse_args()

    if args.crack:
        crack_hashes(args.crack)
    elif args.flag:
        check_flag(args.flag)
    else:
        print("使い方:")
        print("  python checker.py --crack hashes.txt   # ハッシュをクラック")
        print("  python checker.py --flag 'ACD{...}'    # フラグを検証")


if __name__ == "__main__":
    main()
