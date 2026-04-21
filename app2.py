from flask import Flask, request, jsonify, send_from_directory, session, redirect, Response
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests as req_lib
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import warnings
from urllib3.exceptions import InsecureRequestWarning
import os
import threading
import time
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from danger_ffjwt import guest_to_jwt

warnings.simplefilter('ignore', InsecureRequestWarning)

app = Flask(__name__, static_folder='.')
app.secret_key = "KAWSARXLIKE0911_SECRET_2025"

# ============================================================
# CONFIG
# ============================================================
ACCOUNTS_FILE                = "accounts.txt"
USERS_FILE                   = "accounts.json"  # users এখানে "users" key-এ থাকবে
TOKEN_REFRESH_INTERVAL_HOURS = 2

# ── Version cache (danger_ffjwt এর জন্য) ─────────────────────
_versions_cache = {
    "ob_version":     "OB53",
    "client_version": "1.123.2",
    "last_fetch":     0
}

def _get_versions():
    """GitHub থেকে latest OB & client version আনো, ১ ঘণ্টা cache করো।"""
    global _versions_cache
    now = time.time()
    if now - _versions_cache["last_fetch"] > 3600:
        try:
            resp = req_lib.get(
                "https://raw.githubusercontent.com/dangerapix/danger-ffjwt/main/versions.json",
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                _versions_cache["ob_version"]     = data.get("ob_version",     "OB53")
                _versions_cache["client_version"] = data.get("client_version", "1.123.2")
                _versions_cache["last_fetch"]     = now
        except Exception:
            pass  # ব্যর্থ হলে default রাখো
    return _versions_cache["ob_version"], _versions_cache["client_version"]

# ============================================================
# CONFIG (continued)
# ============================================================
ADMIN_PASSWORD               = "KAWSARXLIKE0911"
FREE_USER                    = "free"
FREE_PASS                    = "free"
FREE_USER                    = "free"
FREE_PASS                    = "free"

# ============================================================
# IN-MEMORY STATE  (কোনো ফাইল লেখা হবে না)
# ============================================================
_token_store      = []
_token_store_lock = threading.Lock()
_last_refresh_time = None
_next_refresh_time = None
_checking_mode     = False
_checking_lock     = threading.Lock()

# টোকেন generation চলছে কিনা
_gen_running      = False
_gen_running_lock = threading.Lock()

# ─── LOG QUEUE (index.html /logs/poll এর জন্য) ───────────────
_log_queue   = []
_log_id_ctr  = 0
_log_lock    = threading.Lock()
MAX_LOG_KEEP = 500

def _push_log(msg):
    global _log_id_ctr
    with _log_lock:
        _log_id_ctr += 1
        _log_queue.append({"id": _log_id_ctr, "msg": msg})
        if len(_log_queue) > MAX_LOG_KEEP:
            del _log_queue[:-MAX_LOG_KEEP]

# Users — users.json থেকে persist করা হয়
_users_lock = threading.Lock()

def _load_users():
    """
    Render env var KAWSAR_USERS থেকে load করো।
    Format: username1:hash1,username2:hash2
    Fallback: users.json file (Termux/local)
    """
    result = {}
    # 1. Render environment variable
    env = os.environ.get("KAWSAR_USERS", "")
    if env:
        for entry in env.split(","):
            entry = entry.strip()
            if ":" in entry:
                u, h = entry.split(":", 1)
                result[u.strip()] = h.strip()
        if result:
            return result
    # 2. File fallback (Termux)
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, dict) and "users" in data:
                    return data["users"]
    except Exception:
        pass
    return result

def _save_users(users_dict):
    """
    In-memory রাখে (restart পর্যন্ত কাজ করবে)।
    File-এ save করে (Termux-এ persistent)।
    Render-এ permanent করতে: admin panel-এ env var দেখাবে।
    """
    # File-এ save
    try:
        existing = {}
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, "r") as f:
                    existing = json.load(f)
            except Exception:
                existing = {}
        existing["users"] = users_dict
        with open(USERS_FILE, "w") as f:
            json.dump(existing, f, indent=2)
    except Exception:
        pass
    # Render-এর জন্য env var format print
    env_str = ",".join(f"{u}:{h}" for u, h in users_dict.items())
    print(f"[RENDER ENV] Set KAWSAR_USERS={env_str}")

_users = _load_users()

# ============================================================
# HELPERS
# ============================================================
def _hash(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get("logged_in"):
            return redirect("/login")
        return f(*a, **kw)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **kw):
        if not session.get("is_admin"):
            return jsonify({"error": "Admin only"}), 403
        return f(*a, **kw)
    return d

# ============================================================
# AUTH
# ============================================================
@app.route('/login')
def login_page():
    return send_from_directory('.', 'login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    u = data.get("username", "").strip()
    p = data.get("password", "").strip()
    if u == "admin" and p == ADMIN_PASSWORD:
        session.update({"logged_in": True, "username": "admin", "is_admin": True})
        return jsonify({"ok": True, "is_admin": True})
    if u == FREE_USER and p == FREE_PASS:
        session.update({"logged_in": True, "username": FREE_USER, "is_admin": False})
        return jsonify({"ok": True, "is_admin": False})
    with _users_lock:
        h = _users.get(u)
    if h and h == _hash(p):
        session.update({"logged_in": True, "username": u, "is_admin": False})
        return jsonify({"ok": True, "is_admin": False})
    return jsonify({"ok": False, "error": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route('/api/me')
def api_me():
    return jsonify({
        "logged_in": bool(session.get("logged_in")),
        "username":  session.get("username", ""),
        "is_admin":  bool(session.get("is_admin"))
    })

# ============================================================
# ADMIN USER MANAGEMENT
# ============================================================
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    with _users_lock:
        return jsonify({"users": list(_users.keys())})

@app.route('/api/admin/users', methods=['POST'])
@admin_required
def admin_create_user():
    data = request.get_json() or {}
    u = data.get("username", "").strip()
    p = data.get("password", "").strip()
    if not u or not p:
        return jsonify({"ok": False, "error": "Fields required"}), 400
    if u == "admin":
        return jsonify({"ok": False, "error": "Reserved name"}), 400
    with _users_lock:
        _users[u] = _hash(p)
        _save_users(_users)
    return jsonify({"ok": True, "username": u})

@app.route('/api/admin/users/<username>', methods=['DELETE'])
@admin_required
def admin_delete_user(username):
    with _users_lock:
        if username in _users:
            del _users[username]
            _save_users(_users)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "Not found"}), 404

# ============================================================
# TOKEN GENERATION — SSE stream
# browser /api/generate/stream এ connect করলে
# সেখানেই token generate হবে, events পাঠাবে
# কোনো background thread নেই
# ============================================================
def _sse(msg, event="log"):
    """SSE format"""
    return f"event: {event}\ndata: {msg}\n\n"

def _load_accounts():
    accounts = []
    try:
        if not os.path.exists(ACCOUNTS_FILE):
            return accounts
        with open(ACCOUNTS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or ":" not in line:
                    continue
                uid, pw = line.split(":", 1)
                accounts.append({"uid": uid.strip(), "password": pw.strip()})
    except Exception:
        pass
    return accounts

def _fetch_one(uid, password):
    """
    danger_ffjwt লাইব্রেরি দিয়ে সরাসরি JWT generate করো।
    Working API (app.py) এর fetch_token_from_api এর মতো হুবহু।
    """
    ob_ver, client_ver = _get_versions()
    for attempt in range(1, 4):
        try:
            # ✅ ob_version ও client_version অবশ্যই pass করতে হবে
            result = guest_to_jwt(uid, password, ob_version=ob_ver, client_version=client_ver)

            if not isinstance(result, dict):
                _push_log(f"[WARN] guest_to_jwt unexpected type={type(result).__name__} val={str(result)[:150]}")
                if attempt < 3:
                    time.sleep(2 * attempt)
                continue

            # Working API এর মতো হুবহু key extraction
            account_uid = result.get("account_uid") or result.get("uid") or uid
            jwt_token   = result.get("jwt_token")   or result.get("token")
            region      = result.get("region")

            if jwt_token and region:
                return {
                    "uid":    str(account_uid),
                    "token":  jwt_token,
                    "region": region
                }
            else:
                _push_log(f"[WARN] Missing jwt_token or region. Keys={list(result.keys())} val={str(result)[:150]}")

        except Exception as e:
            _push_log(f"[WARN] guest_to_jwt attempt {attempt} failed uid={uid} err={e}")
            if attempt < 3:
                time.sleep(2 * attempt)
    return None

@app.route('/api/generate/stream')
@login_required
def generate_stream():
    """
    SSE endpoint — browser এখানে connect করলে token generate শুরু হয়।
    Termux বা Render terminal-এ কিছু print হবে না।
    """
    global _gen_running, _last_refresh_time, _next_refresh_time, _checking_mode

    # একসাথে দুটো generation চলবে না
    with _gen_running_lock:
        if _gen_running:
            def already():
                yield _sse("⚠ Token generation already in progress!", "log")
                yield _sse("done", "done")
            return Response(already(), mimetype="text/event-stream",
                            headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})
        _gen_running = True

    def generate():
        global _gen_running, _last_refresh_time, _next_refresh_time, _checking_mode
        try:
            ts = lambda: datetime.now().strftime("%H:%M:%S")

            def log(msg):
                _push_log(msg)
                return _sse(msg, "log")

            yield log(f"[{ts()}] ╔══════════════════════════════════╗")
            yield log(f"[{ts()}]   TOKEN GENERATION STARTED")
            yield log(f"[{ts()}] ╚══════════════════════════════════╝")
            yield log(f"[{ts()}] ")

            accounts = _load_accounts()
            if not accounts:
                yield log(f"[{ts()}] [ERROR] accounts.txt not found or empty!")
                yield _sse("error", "done")
                return

            total = len(accounts)
            yield log(f"[{ts()}] [INFO] {total} accounts loaded.")
            yield log(f"[{ts()}] ────────────────────────────────────")

            successful = []
            failed     = 0

            for idx, acc in enumerate(accounts, 1):
                yield log(f"[{ts()}]  [{idx}/{total}] Generating token #{idx}...")

                result = _fetch_one(acc["uid"], acc["password"])
                if result:
                    successful.append(result)
                    yield log(f"[{ts()}]  [{idx}/{total}] ✓ Token #{idx} generated  [REGION: {result['region']}]")
                else:
                    failed += 1
                    yield log(f"[{ts()}]  [{idx}/{total}] ✗ Token #{idx} FAILED")

                yield _sse(f"{idx},{total}", "progress")
                time.sleep(0.1)

            with _token_store_lock:
                uid_map = {t["uid"]: t for t in _token_store}
                for t in successful:
                    uid_map[t["uid"]] = t
                _token_store.clear()
                _token_store.extend(uid_map.values())

            _last_refresh_time = datetime.now()
            _next_refresh_time = _last_refresh_time + timedelta(hours=TOKEN_REFRESH_INTERVAL_HOURS)

            with _checking_lock:
                _checking_mode = False

            yield log(f"[{ts()}] ────────────────────────────────────")
            yield log(f"[{ts()}] [DONE] Generated: {len(successful)}  Failed: {failed}")
            yield log(f"[{ts()}] [INFO] Tokens in memory: {len(_token_store)}")
            yield log(f"[{ts()}] [INFO] Next refresh: {_next_refresh_time.strftime('%H:%M:%S')}")
            yield log(f"[{ts()}] ╔══════════════════════════════════╗")
            yield log(f"[{ts()}]   COMPLETE ✓  ({len(successful)}/{total} OK)")
            yield log(f"[{ts()}] ╚══════════════════════════════════╝")
            yield _sse("done", "done")

        except GeneratorExit:
            pass
        finally:
            with _gen_running_lock:
                _gen_running = False

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route('/api/generate/status')
@login_required
def gen_status():
    with _gen_running_lock:
        running = _gen_running
    return jsonify({"running": running})


# ============================================================
# LOGS POLL — index.html প্রতি ৩ সেকেন্ডে এটা call করে
# ============================================================
@app.route('/logs/poll')
@login_required
def logs_poll():
    after = int(request.args.get("after", 0))
    with _log_lock:
        new_lines = [l for l in _log_queue if l["id"] > after]
        last_id   = _log_queue[-1]["id"] if _log_queue else 0
    return jsonify({"lines": new_lines, "last_id": last_id})


# ============================================================
# 2-HOUR AUTO REFRESH CHECK (web-side timer, no background thread)
# Browser /api/token/check_refresh call করবে
# ============================================================
@app.route('/api/token/check_refresh')
@login_required
def check_refresh():
    """
    Browser প্রতি মিনিটে call করবে।
    ২ ঘণ্টা পার হলে checking mode চালু হবে।
    তখন terminal থেকে generate করতে হবে।
    """
    global _checking_mode
    if _next_refresh_time and datetime.now() >= _next_refresh_time:
        with _checking_lock:
            _checking_mode = True
        return jsonify({"needs_refresh": True})
    return jsonify({"needs_refresh": False})


# ============================================================
# TOKEN STATUS
# ============================================================
@app.route('/token_status')
@login_required
def token_status():
    with _token_store_lock:
        cnt = len(_token_store)
    with _checking_lock:
        checking = _checking_mode
    with _gen_running_lock:
        running = _gen_running
    return jsonify({
        "total_tokens":    cnt,
        "checking_mode":   checking,
        "gen_running":     running,
        "last_refresh":    _last_refresh_time.strftime('%Y-%m-%d %H:%M:%S') if _last_refresh_time else "Never",
        "next_refresh":    _next_refresh_time.strftime('%Y-%m-%d %H:%M:%S') if _next_refresh_time else "—",
        "next_refresh_ts": int(_next_refresh_time.timestamp()) if _next_refresh_time else 0,
    })


# ============================================================
# PAGES
# ============================================================
@app.route('/')
@login_required
def index():
    return send_from_directory('.', 'index.html')

@app.route('/terminal')
@login_required
def terminal():
    return send_from_directory('.', 'terminal.html')

@app.route('/admin')
def admin_page():
    if not session.get("is_admin"):
        return redirect("/login")
    return send_from_directory('.', 'admin.html')


# ============================================================
# LIKE FUNCTIONS
# ============================================================
def _get_tokens(server):
    with _token_store_lock:
        t = [x for x in _token_store if x.get("region") == server]
        return t if t else list(_token_store)

def _encrypt(plaintext):
    try:
        c = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
        return binascii.hexlify(c.encrypt(pad(plaintext, AES.block_size))).decode()
    except Exception:
        return None

def _proto_like(uid, region):
    try:
        m = like_pb2.like(); m.uid = int(uid); m.region = region
        return m.SerializeToString()
    except Exception:
        return None

def _proto_uid(uid):
    try:
        m = uid_generator_pb2.uid_generator()
        m.saturn_ = int(uid); m.garena = 1
        return m.SerializeToString()
    except Exception:
        return None

def _enc_uid(uid):
    pb = _proto_uid(uid)
    return _encrypt(pb) if pb else None

async def _send_one(enc_hex, token, url):
    try:
        h = {'User-Agent':"Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
             'Connection':"Keep-Alive",'Accept-Encoding':"gzip",
             'Authorization':f"Bearer {token}",'Content-Type':"application/x-www-form-urlencoded",
             'Expect':"100-continue",'X-Unity-Version':"1.123.1",
             'X-GA':"v1 1",'ReleaseVersion':"OB53"}
        async with aiohttp.ClientSession() as s:
            async with s.post(url, data=bytes.fromhex(enc_hex), headers=h) as r:
                return r.status if r.status != 200 else await r.text()
    except Exception:
        return None

async def _send_100(uid, server, url):
    pb = _proto_like(uid, server)
    if not pb: return None
    enc = _encrypt(pb)
    if not enc: return None
    tokens = _get_tokens(server)
    if not tokens: return None
    tasks = [_send_one(enc, tokens[i % len(tokens)]["token"], url) for i in range(100)]
    return await asyncio.gather(*tasks, return_exceptions=True)

def _player_info(enc_hex, server, token):
    try:
        url = ("https://client.ind.freefiremobile.com/GetPlayerPersonalShow" if server=="IND"
               else "https://client.us.freefiremobile.com/GetPlayerPersonalShow" if server in {"BR","US","SAC","NA"}
               else "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")
        h = {'User-Agent':"Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
             'Connection':"Keep-Alive",'Accept-Encoding':"gzip",
             'Authorization':f"Bearer {token}",'Content-Type':"application/x-www-form-urlencoded",
             'Expect':"100-continue",'X-Unity-Version':"1.123.1",
             'X-GA':"v1 1",'ReleaseVersion':"OB53"}
        r = req_lib.post(url, data=bytes.fromhex(enc_hex), headers=h, verify=False)
        items = like_count_pb2.Info()
        items.ParseFromString(bytes.fromhex(r.content.hex()))
        return items
    except Exception:
        return None

@app.route('/like', methods=['GET'])
@login_required
def handle_like():
    with _checking_lock:
        if _checking_mode:
            return jsonify({"error": "⏳ CHECKING TOKEN — Go to Terminal and generate tokens."}), 503

    uid    = request.args.get("uid", "").strip()
    server = request.args.get("server_name", "").upper()
    if not uid or not server:
        return jsonify({"error": "uid and server_name required"}), 400

    tokens = _get_tokens(server)
    if not tokens:
        return jsonify({"error": "⏳ No tokens yet — Go to Terminal and generate tokens first."}), 503

    try:
        token = tokens[0]["token"]
        e     = _enc_uid(uid)
        if not e:
            return jsonify({"error": "Encryption failed"}), 500

        before = _player_info(e, server, token)
        if not before:
            return jsonify({"error": "Failed to fetch player info"}), 500
        bd = json.loads(MessageToJson(before))
        bl = int(bd.get("AccountInfo", {}).get("Likes", 0))

        lu = ("https://client.ind.freefiremobile.com/LikeProfile" if server=="IND"
              else "https://client.us.freefiremobile.com/LikeProfile" if server in {"BR","US","SAC","NA"}
              else "https://clientbp.ggblueshark.com/LikeProfile")
        asyncio.run(_send_100(uid, server, lu))

        after = _player_info(e, server, token)
        if not after:
            return jsonify({"error": "Failed to fetch player info after likes"}), 500
        ad   = json.loads(MessageToJson(after))
        al   = int(ad.get("AccountInfo", {}).get("Likes", 0))
        puid = int(ad.get("AccountInfo", {}).get("UID", 0))
        pnm  = str(ad.get("AccountInfo", {}).get("PlayerNickname", ""))

        return jsonify({
            "LikesGivenByAPI":    al - bl,
            "LikesafterCommand":  al,
            "LikesbeforeCommand": bl,
            "PlayerNickname":     pnm,
            "UID":                puid,
            "status":             1 if al > bl else 2
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# BACKGROUND TOKEN GENERATOR — Auto-start + 2hr refresh
# ============================================================
def _run_generate_bg():
    """
    Background thread: server start হলে auto token generate করবে।
    _gen_running flag ব্যবহার করে duplicate থেকে বাঁচবে।
    প্রতি ২ ঘণ্টায় auto refresh করবে।
    """
    global _gen_running, _last_refresh_time, _next_refresh_time, _checking_mode

    def do_generate():
        global _last_refresh_time, _next_refresh_time, _checking_mode
        ts = lambda: datetime.now().strftime("%H:%M:%S")

        _push_log(f"[{ts()}] ╔══════════════════════════════════╗")
        _push_log(f"[{ts()}]   AUTO TOKEN GENERATION STARTED")
        _push_log(f"[{ts()}] ╚══════════════════════════════════╝")

        accounts = _load_accounts()
        if not accounts:
            _push_log(f"[{ts()}] [ERROR] accounts.txt not found or empty!")
            return

        total = len(accounts)
        _push_log(f"[{ts()}] [INFO] {total} accounts loaded.")
        _push_log(f"[{ts()}] ────────────────────────────────────")

        successful = []
        failed = 0

        for idx, acc in enumerate(accounts, 1):
            _push_log(f"[{ts()}]  [{idx}/{total}] Generating token #{idx}...")
            result = _fetch_one(acc["uid"], acc["password"])
            if result:
                successful.append(result)
                _push_log(f"[{ts()}]  [{idx}/{total}] ✓ Token #{idx} generated  [REGION: {result['region']}]")
            else:
                failed += 1
                _push_log(f"[{ts()}]  [{idx}/{total}] ✗ Token #{idx} FAILED")
            time.sleep(0.2)

        with _token_store_lock:
            uid_map = {t["uid"]: t for t in _token_store}
            for t in successful:
                uid_map[t["uid"]] = t
            _token_store.clear()
            _token_store.extend(uid_map.values())

        _last_refresh_time = datetime.now()
        _next_refresh_time = _last_refresh_time + timedelta(hours=TOKEN_REFRESH_INTERVAL_HOURS)

        with _checking_lock:
            _checking_mode = False

        _push_log(f"[{ts()}] [DONE] Generated: {len(successful)}  Failed: {failed}")
        _push_log(f"[{ts()}] [INFO] Total tokens: {len(_token_store)}")
        _push_log(f"[{ts()}] [INFO] Next refresh: {_next_refresh_time.strftime('%H:%M:%S')}")
        _push_log(f"[{ts()}]   COMPLETE ✓  ({len(successful)}/{total} OK)")

    # প্রথমবার — server start হলে ৩ সেকেন্ড পরে auto generate
    time.sleep(3)

    while True:
        with _gen_running_lock:
            if not _gen_running:
                _gen_running = True
                do_generate_now = True
            else:
                do_generate_now = False

        if do_generate_now:
            try:
                do_generate()
            except Exception as e:
                _push_log(f"[ERROR] Auto generate error: {e}")
            finally:
                with _gen_running_lock:
                    _gen_running = False

        # ২ ঘণ্টা পর আবার
        time.sleep(TOKEN_REFRESH_INTERVAL_HOURS * 3600)


# ============================================================
# RUN
# ============================================================
if __name__ == '__main__':
    # Background auto-generate thread start
    t = threading.Thread(target=_run_generate_bg, daemon=True)
    t.start()
    app.run(host='0.0.0.0', port=8381, debug=False, threaded=True)
else:
    # Gunicorn / Render এর জন্য — app import হলেও thread চালু হবে
    t = threading.Thread(target=_run_generate_bg, daemon=True)
    t.start()
