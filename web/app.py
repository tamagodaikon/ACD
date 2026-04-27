#!/usr/bin/env python3
"""
ACD - Active Cyber Defense Learning Platform
サイバーセキュリティ自主学習Webアプリ
"""

import sys
import os
import json
import subprocess
import threading
import queue
import socket
import urllib.request
import urllib.error
import ssl
import re
import hashlib
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, Response
import concurrent.futures

sys.path.insert(0, str(Path(__file__).parent.parent))

app = Flask(__name__)
app.secret_key = os.urandom(32)

BASE_DIR = Path(__file__).parent.parent
LABS_DIR = BASE_DIR / "labs"
TOOLS_DIR = BASE_DIR / "tools"
LOG_SAMPLE = BASE_DIR / "labs" / "04-log-analysis" / "sample-logs" / "access.log"

# CTFフラグ定義
CTF_FLAGS = {
    "B01": "ACD{alice_uses_password_md5_is_broken}",
    "B03": "ACD{10.0.0.99_UNION_SELECT}",
    "I03": "ACD{page_path_traversal}",
}

# 学習進捗（セッションベース）
LABS = [
    {"id": "01", "title": "偵察防御", "icon": "🔍", "difficulty": 1, "duration": "90分"},
    {"id": "02", "title": "ネットワークセキュリティ", "icon": "🌐", "difficulty": 2, "duration": "120分"},
    {"id": "03", "title": "Webセキュリティ", "icon": "🕸️", "difficulty": 2, "duration": "150分"},
    {"id": "04", "title": "ログ解析", "icon": "📋", "difficulty": 3, "duration": "120分"},
    {"id": "05", "title": "インシデントレスポンス", "icon": "🚨", "difficulty": 3, "duration": "180分"},
]

CHALLENGES = [
    {"id": "B01", "title": "パスワード監査", "level": "beginner", "points": 100, "theme": "弱いパスワードの検出"},
    {"id": "B03", "title": "ログ捜査", "level": "beginner", "points": 150, "theme": "ログからの攻撃者特定"},
    {"id": "I03", "title": "侵入の足跡", "level": "intermediate", "points": 200, "theme": "インシデント調査"},
]


def get_progress():
    if "progress" not in session:
        session["progress"] = {"labs": {}, "challenges": {}, "points": 0}
    return session["progress"]


# ─── ページルート ───────────────────────────────────────

@app.route("/")
def dashboard():
    progress = get_progress()
    completed_labs = sum(1 for v in progress["labs"].values() if v)
    completed_challenges = sum(1 for v in progress["challenges"].values() if v)
    total_points = progress.get("points", 0)
    return render_template("dashboard.html",
                           labs=LABS, challenges=CHALLENGES,
                           progress=progress,
                           completed_labs=completed_labs,
                           completed_challenges=completed_challenges,
                           total_points=total_points)


@app.route("/lab/<lab_id>")
def lab(lab_id):
    lab_info = next((l for l in LABS if l["id"] == lab_id), None)
    if not lab_info:
        return "Lab not found", 404
    readme_path = LABS_DIR / f"0{lab_id}-{_lab_dirname(lab_id)}" / "README.md"
    content = readme_path.read_text(encoding="utf-8") if readme_path.exists() else "コンテンツがありません"
    progress = get_progress()
    return render_template("labs/lab.html", lab=lab_info, content=content,
                           completed=progress["labs"].get(lab_id, False))


@app.route("/lab/<lab_id>/complete", methods=["POST"])
def complete_lab(lab_id):
    progress = get_progress()
    if not progress["labs"].get(lab_id):
        progress["labs"][lab_id] = True
        progress["points"] = progress.get("points", 0) + 50
        session["progress"] = progress
    return jsonify({"ok": True, "points": progress["points"]})


@app.route("/tools")
def tools():
    return render_template("tools/index.html")


@app.route("/challenges")
def challenges():
    progress = get_progress()
    return render_template("challenges.html", challenges=CHALLENGES, progress=progress)


@app.route("/challenge/<ch_id>")
def challenge(ch_id):
    ch = next((c for c in CHALLENGES if c["id"] == ch_id), None)
    if not ch:
        return "Challenge not found", 404
    progress = get_progress()
    readme_path = BASE_DIR / "challenges" / _level_dir(ch["level"]) / f"{ch_id}-*"
    import glob
    matches = glob.glob(str(readme_path))
    content = ""
    if matches:
        readme = Path(matches[0]) / "README.md"
        if readme.exists():
            content = readme.read_text(encoding="utf-8")
    return render_template("challenge.html", ch=ch, content=content,
                           solved=progress["challenges"].get(ch_id, False))


@app.route("/challenge/<ch_id>/submit", methods=["POST"])
def submit_flag(ch_id):
    flag = request.json.get("flag", "").strip()
    correct = CTF_FLAGS.get(ch_id)
    progress = get_progress()
    if flag == correct:
        if not progress["challenges"].get(ch_id):
            ch = next((c for c in CHALLENGES if c["id"] == ch_id), {})
            progress["challenges"][ch_id] = True
            progress["points"] = progress.get("points", 0) + ch.get("points", 100)
            session["progress"] = progress
        return jsonify({"correct": True, "message": "正解！フラグが正しいです 🎉",
                        "points": progress["points"]})
    return jsonify({"correct": False, "message": "不正解です。もう一度試してください。"})


# ─── ツール API ────────────────────────────────────────

@app.route("/api/port-scan", methods=["POST"])
def api_port_scan():
    data = request.json or {}
    target = data.get("target", "127.0.0.1").strip()
    ports_str = data.get("ports", "1-1024").strip()

    # 安全チェック: ループバックとプライベートIPのみ許可
    try:
        import ipaddress
        ip = ipaddress.ip_address(target)
        if not (ip.is_loopback or ip.is_private):
            return jsonify({"error": "セキュリティ上の理由から、プライベートIPまたはlocalhostのみスキャン可能です"}), 400
    except ValueError:
        if target not in ("localhost",):
            return jsonify({"error": "有効なIPアドレスまたは localhost を指定してください"}), 400

    def scan_port(host, port, timeout=0.5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                services = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
                            5000: "Flask", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt"}
                return {"port": port, "state": "open", "service": services.get(port, "Unknown")}
        except Exception:
            pass
        return None

    try:
        if "-" in ports_str:
            start, end = map(int, ports_str.split("-"))
            end = min(end, start + 999)  # 最大1000ポート
            ports = list(range(start, end + 1))
        else:
            ports = [int(p) for p in ports_str.split(",")][:50]
    except ValueError:
        return jsonify({"error": "ポート範囲の形式が正しくありません"}), 400

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, target, p): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)

    risky = {23: "Telnet(暗号化なし)", 21: "FTP(平文認証)", 3389: "RDP"}
    warnings = [f"Port {p['port']}: {risky[p['port']]}" for p in open_ports if p["port"] in risky]

    return jsonify({
        "target": target,
        "scanned": len(ports),
        "open": sorted(open_ports, key=lambda x: x["port"]),
        "warnings": warnings,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


@app.route("/api/header-check", methods=["POST"])
def api_header_check():
    data = request.json or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URLを入力してください"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {"score": 20, "desc": "HTTPS強制・中間者攻撃防止"},
        "Content-Security-Policy": {"score": 20, "desc": "XSS攻撃の軽減"},
        "X-Frame-Options": {"score": 10, "desc": "クリックジャッキング防止"},
        "X-Content-Type-Options": {"score": 10, "desc": "MIMEスニッフィング防止"},
        "Referrer-Policy": {"score": 5, "desc": "リファラー漏洩防止"},
        "Permissions-Policy": {"score": 5, "desc": "ブラウザ機能の制限"},
    }
    DANGER_HEADERS = {
        "Server": "サーバー情報の漏洩",
        "X-Powered-By": "技術スタックの漏洩",
    }

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ACD-SecurityChecker/1.0"})
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            headers = dict(resp.headers)
            status = resp.status
    except urllib.error.HTTPError as e:
        headers = dict(e.headers)
        status = e.code
    except Exception as e:
        return jsonify({"error": f"接続エラー: {str(e)}"}), 400

    headers_lower = {k.lower(): v for k, v in headers.items()}
    results = []
    total_score = 0
    max_score = sum(v["score"] for v in SECURITY_HEADERS.values())

    for name, cfg in SECURITY_HEADERS.items():
        present = name.lower() in headers_lower
        value = headers_lower.get(name.lower(), "")
        score = cfg["score"] if present else 0
        total_score += score
        results.append({"name": name, "present": present, "value": value,
                         "score": score, "max_score": cfg["score"], "desc": cfg["desc"]})

    danger = [{"header": h, "value": headers_lower[h.lower()], "issue": desc}
              for h, desc in DANGER_HEADERS.items() if h.lower() in headers_lower]

    pct = int(total_score / max_score * 100)
    grade = "A" if pct >= 80 else "B" if pct >= 60 else "C" if pct >= 40 else "D"

    return jsonify({"url": url, "status": status, "score": total_score,
                    "max_score": max_score, "percentage": pct, "grade": grade,
                    "headers": results, "dangerous": danger})


@app.route("/api/log-analyze", methods=["POST"])
def api_log_analyze():
    data = request.json or {}
    use_sample = data.get("use_sample", True)

    if use_sample:
        if not LOG_SAMPLE.exists():
            return jsonify({"error": "サンプルログが見つかりません"}), 400
        log_content = LOG_SAMPLE.read_text(encoding="utf-8", errors="replace")
    else:
        log_content = data.get("log_text", "")

    ATTACK_PATTERNS = {
        "SQL Injection": [r"(?i)(union.*select|select.*from|sleep\s*\(|benchmark\s*\()"],
        "XSS": [r"(?i)(<script|javascript:|onerror\s*=|alert\s*\()"],
        "Path Traversal": [r"(\.\./|etc/passwd|etc/shadow)"],
        "Scanner/Bot": [r"(?i)(sqlmap|nikto|dirbuster|nmap|masscan)"],
        "File Inclusion": [r"(?i)(php://|file://|\.php\?)"],
        "Sensitive Files": [r"(?i)(\.(env|git|bak|sql|dump)|web\.config)"],
    }

    LOG_RE = re.compile(
        r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\S+)'
        r'(?:\s+"([^"]*)"\s+"([^"]*)")?'
    )

    events, ip_status, ip_paths = [], {}, {}
    status_count = {}

    for line in log_content.splitlines():
        m = LOG_RE.match(line.strip())
        if not m:
            continue
        ip, time_, method, path, status, size = m.group(1,2,3,4,5,6)
        ua = m.group(8) or ""

        ip_status.setdefault(ip, []).append(status)
        ip_paths.setdefault(ip, []).append(path)
        status_count[status] = status_count.get(status, 0) + 1

        target = path + " " + ua
        for atype, patterns in ATTACK_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, target):
                    events.append({"time": time_, "ip": ip, "method": method,
                                   "path": path[:80], "status": status, "attack": atype})
                    break

    bf_suspects = sorted(
        [{"ip": ip, "failures": sum(1 for s in statuses if s in ("401","403"))}
         for ip, statuses in ip_status.items()
         if sum(1 for s in statuses if s in ("401","403")) >= 5],
        key=lambda x: x["failures"], reverse=True
    )
    scan_suspects = sorted(
        [{"ip": ip, "unique_paths": len(set(paths)), "total": len(paths)}
         for ip, paths in ip_paths.items() if len(set(paths)) >= 15],
        key=lambda x: x["unique_paths"], reverse=True
    )

    attack_summary = {}
    for e in events:
        attack_summary[e["attack"]] = attack_summary.get(e["attack"], 0) + 1

    return jsonify({
        "total_lines": len(log_content.splitlines()),
        "attack_events": events[:30],
        "attack_summary": attack_summary,
        "status_distribution": status_count,
        "brute_force": bf_suspects[:5],
        "scanning": scan_suspects[:5],
        "suspect_ips": list({e["ip"] for e in events} |
                            {s["ip"] for s in bf_suspects} |
                            {s["ip"] for s in scan_suspects})[:10],
    })


# ─── ヘルパー ───────────────────────────────────────────

def _lab_dirname(lab_id):
    names = {"01": "reconnaissance-defense", "02": "network-security",
             "03": "web-security", "04": "log-analysis", "05": "incident-response"}
    return names.get(lab_id, lab_id)


def _level_dir(level):
    return {"beginner": "beginner", "intermediate": "intermediate", "advanced": "advanced"}.get(level, "beginner")


if __name__ == "__main__":
    print("=" * 50)
    print("ACD - Active Cyber Defense Learning Platform")
    print("URL: http://localhost:5001")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5001)
