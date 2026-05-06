"""
Auth Gateway API — 統一認證閘道（v4 · 日誌精簡 + 詳細審計）
────────────────────────────────────────────────────────────────
v4 變更（相對 v3）:
  • 新增 access middleware：每個業務請求記一行 key=value 結構化日誌
    內容：user / role / ip / method / path / uri / status / dur_ms
  • /auth/health 完全靜音（不寫任何 access 日誌）
  • /auth/check 額外記錄真實下游 URI 與判定結果（forbidden / no_session）
  • uvicorn 內建 access log 已在 Dockerfile 用 --no-access-log 關閉
    所有 access 行都從這裡發出，格式可控、噪音可控

v3 既有功能（保留）:
  • /auth/apps 端點（從 apps.yaml 過濾出當前用戶可見看板）
  • X-Auth-Extras header（通用 extras 透傳）
  • finance 專用 header 完全保留（kiki_DAta_Analysis 兼容）

對下游 FastAPI 合約（不變）:
  X-Auth-User / X-Auth-Gw-Role / X-Auth-Role / X-Auth-Dept-Scope
  X-Auth-Advisor-Name / X-Auth-Scope / X-Auth-Display-Name / X-Auth-Extras
────────────────────────────────────────────────────────────────
"""
import os
import sys
import time
import json
import logging
from typing import Optional
from urllib.parse import quote

import yaml
from fastapi import FastAPI, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from passlib.hash import bcrypt

# ── 日誌設定 ────────────────────────────────────────────────
# 第一性原理：日誌只為「出事時還原現場」存在。
# 設計：單行 key=value，方便 grep / awk，不引入結構化日誌庫。
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("auth-gateway")
audit = logging.getLogger("auth-gateway.audit")  # 業務審計專用 logger

# 健康檢查路徑：完全不寫日誌
SILENT_PATHS = {"/auth/health"}


def _kv(**kwargs) -> str:
    """把任意 key=value 序列化成單行可 grep 字串。
    None 與空字串自動忽略；含空格的 value 自動加引號。
    """
    parts = []
    for k, v in kwargs.items():
        if v is None or v == "":
            continue
        s = str(v)
        if " " in s or "\t" in s:
            s = '"' + s.replace('"', '\\"') + '"'
        parts.append(f"{k}={s}")
    return " ".join(parts)


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

SECRET = os.environ.get("SECRET_KEY", "")
if not SECRET or len(SECRET) < 32:
    log.error("SECRET_KEY 未設定或長度不足 32")
    sys.exit(1)

COOKIE = "gw_sess"
MAX_AGE = 86400 * 7
YAML_PATH = os.environ.get("USERS_YAML", "/app/users.yaml")
APPS_YAML_PATH = os.environ.get("APPS_YAML", "/app/apps.yaml")
SER = URLSafeTimedSerializer(SECRET)


# ── bcrypt 安全編碼 ─────────────────────────────────────────
def pwd_bytes(pwd: str) -> bytes:
    return pwd.encode("utf-8")[:72]


def safe_verify(pwd: str, stored_hash: str) -> bool:
    if not stored_hash or not stored_hash.startswith("$2"):
        return False
    try:
        return bcrypt.verify(pwd_bytes(pwd), stored_hash)
    except (ValueError, TypeError) as e:
        log.warning("bcrypt verify failed: %s", e)
        return False


# ── 配置載入（mtime 快取）────────────────────────────────────
_cfg_cache = {"mtime": 0.0, "data": None}


def load_cfg() -> dict:
    try:
        mt = os.path.getmtime(YAML_PATH)
    except OSError as e:
        if _cfg_cache["data"] is not None:
            log.warning("stat users.yaml failed: %s", e)
            return _cfg_cache["data"]
        raise

    if mt != _cfg_cache["mtime"]:
        try:
            with open(YAML_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            log.warning("users.yaml parse error, keep cache: %s", e)
            if _cfg_cache["data"] is not None:
                return _cfg_cache["data"]
            return {"roles": {}, "users": []}

        data.setdefault("roles", {})
        data.setdefault("users", [])
        _cfg_cache["data"] = data
        _cfg_cache["mtime"] = mt
        log.info("users.yaml reloaded: %d users, %d roles",
                 len(data.get("users", [])), len(data.get("roles", {})))
    return _cfg_cache["data"]


# ── apps.yaml 載入（mtime 快取，結構與 users.yaml 類似）────────
_apps_cache = {"mtime": 0.0, "data": None}


def load_apps() -> list:
    """讀取 apps.yaml，回傳 apps 陣列。缺文件時回傳空陣列並警告。"""
    try:
        mt = os.path.getmtime(APPS_YAML_PATH)
    except OSError:
        if _apps_cache["data"] is None:
            log.warning("apps.yaml 不存在於 %s，/auth/apps 將回空清單", APPS_YAML_PATH)
            _apps_cache["data"] = []
        return _apps_cache["data"]

    if mt != _apps_cache["mtime"]:
        try:
            with open(APPS_YAML_PATH, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            apps = raw.get("apps") or []
            if not isinstance(apps, list):
                apps = []
            _apps_cache["data"] = apps
            _apps_cache["mtime"] = mt
            log.info("apps.yaml reloaded: %d apps", len(apps))
        except yaml.YAMLError as e:
            log.warning("apps.yaml parse error, keep cache: %s", e)
            if _apps_cache["data"] is None:
                _apps_cache["data"] = []
    return _apps_cache["data"]


# ── 權限判定（嚴格邊界）──────────────────────────────────────
def path_allowed(uri: str, allowed: list) -> bool:
    path = uri.split("?", 1)[0]
    for p in allowed:
        p = p.rstrip("/")
        if not p:
            continue
        if path == p or path.startswith(p + "/"):
            return True
    return False


# ── 核心：推導用戶的 finance 子節 ─────────────────────────────
def resolve_finance(user: dict) -> Optional[dict]:
    """
    第一性原理：數據層權限必須明確，否則寧可 None（下游 401）不要誤放。

    規則:
      1. 顯式配 finance.role → 使用該配置
         - SCOPED 必須帶非空 scope dict（否則降級為 None）
      2. Gateway role ∈ {admin, manager} 且未配 → 預設 ADMIN（看全部）
      3. advisor 未顯式配 → None（配置錯誤，下游擋住）
      4. 其他 role → None（不該訪問 /finance）
    """
    fin = user.get("finance")
    if isinstance(fin, dict) and fin.get("role"):
        role = str(fin.get("role", "")).upper()
        if role == "SCOPED":
            scope = fin.get("scope") or {}
            # scope 必須是 dict 且至少有一個非空維度
            if not isinstance(scope, dict):
                return None
            has_any = any(
                isinstance(v, (list, tuple)) and any(str(x).strip() for x in v)
                for v in scope.values()
            )
            if not has_any:
                return None
        return fin
    gw_role = user.get("role", "")
    if gw_role in ("admin", "manager"):
        return {"role": "ADMIN"}
    return None


# ── 會話管理 ────────────────────────────────────────────────
def get_session(req: Request) -> Optional[dict]:
    token = req.cookies.get(COOKIE)
    if not token:
        return None
    try:
        return SER.loads(token, max_age=MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None


def get_client_ip(req: Request) -> str:
    return req.headers.get("X-Real-IP") or (req.client.host if req.client else "unknown")


# ── 失敗限流 ────────────────────────────────────────────────
_fail_log: dict = {}
FAIL_WINDOW = 300
FAIL_LIMIT = 5
_last_gc = 0.0


def _gc_fail_log(now: float):
    global _last_gc
    if now - _last_gc < 60:
        return
    _last_gc = now
    expired = []
    for ip, ts_list in _fail_log.items():
        kept = [t for t in ts_list if now - t < FAIL_WINDOW]
        if kept:
            _fail_log[ip] = kept
        else:
            expired.append(ip)
    for ip in expired:
        _fail_log.pop(ip, None)


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    _gc_fail_log(now)
    attempts = [t for t in _fail_log.get(ip, []) if now - t < FAIL_WINDOW]
    _fail_log[ip] = attempts
    return len(attempts) >= FAIL_LIMIT


def record_fail(ip: str):
    _fail_log.setdefault(ip, []).append(time.time())


# ══════════════════════════════════════════════════════════
#   訪問日誌 Middleware（中央集中記錄）
# ══════════════════════════════════════════════════════════
@app.middleware("http")
async def access_log_middleware(request: Request, call_next):
    """
    每個業務請求記一行 access 日誌；健康檢查完全靜音。

    記錄欄位（key=value，方便 grep）:
      ts      - 時間戳（由 logging format 提供）
      level   - INFO / WARNING
      event   - access
      method  - GET / POST
      path    - /auth/check, /finance/xxx, ...
      uri     - /auth/check 才有意義（X-Original-URI，下游真實 URI）
      user    - 從 cookie session 解出來的登入用戶
      role    - gateway role
      dn      - display_name
      ip      - 真實客戶端 IP
      status  - HTTP 狀態碼
      dur_ms  - 處理耗時毫秒

    搜索範例:
      grep 'user=zhang' app.log               # 某用戶所有操作
      grep 'event=access.*status=403' app.log # 所有被擋的請求
      grep 'uri=/finance' app.log             # finance 相關所有訪問
    """
    path = request.url.path

    # 健康檢查完全靜音
    if path in SILENT_PATHS:
        return await call_next(request)

    t0 = time.perf_counter()
    response: Response = await call_next(request)
    dur_ms = int((time.perf_counter() - t0) * 1000)

    # 解 session（解失敗不影響主流程）
    sess = get_session(request)
    user = sess.get("u") if sess else None
    role = sess.get("r") if sess else None
    dn = sess.get("n") if sess else None

    # /auth/check 的真實業務 URI 在 header 裡，比 path 更有審計價值
    original_uri = request.headers.get("X-Original-URI") if path == "/auth/check" else None

    level = logging.WARNING if response.status_code >= 400 else logging.INFO
    audit.log(
        level,
        _kv(
            event="access",
            method=request.method,
            path=path,
            uri=original_uri,
            user=user,
            role=role,
            dn=dn,
            ip=get_client_ip(request),
            status=response.status_code,
            dur_ms=dur_ms,
        ),
    )
    return response


# ══════════════════════════════════════════════════════════
#   路由
# ══════════════════════════════════════════════════════════

@app.get("/auth/login", response_class=HTMLResponse)
def login_page(req: Request, error: str = ""):
    if get_session(req):
        return RedirectResponse("/portal", 302)
    msg = {"rate": "尝试过多，请稍后再试"}.get(error, "帐号或密码错误" if error else "")
    err_html = f'<p class="err">{msg}</p>' if msg else ""
    return LOGIN_HTML.replace("{{ERROR}}", err_html)


@app.post("/auth/login")
def login(req: Request, username: str = Form(), password: str = Form()):
    ip = get_client_ip(req)
    if is_rate_limited(ip):
        audit.warning(_kv(event="rate_limited", user=username, ip=ip))
        return RedirectResponse("/auth/login?error=rate", 302)

    try:
        cfg = load_cfg()
    except Exception as e:
        log.exception("load_cfg failed: %s", e)
        return RedirectResponse("/auth/login?error=1", 302)

    user = next((u for u in cfg.get("users", []) if u.get("username") == username), None)

    if user and safe_verify(password, user.get("password_hash", "")):
        role = user.get("role", "viewer")
        if role not in cfg.get("roles", {}):
            audit.error(_kv(event="login_fail", reason="unknown_role",
                            user=username, role=role, ip=ip))
            record_fail(ip)
            return RedirectResponse("/auth/login?error=1", 302)

        display = user.get("display_name", username)
        token = SER.dumps({"u": username, "r": role, "n": display})
        resp = RedirectResponse("/portal", 302)
        resp.set_cookie(
            COOKIE, token,
            max_age=MAX_AGE, httponly=True, samesite="lax", path="/",
        )
        audit.info(_kv(event="login_ok", user=username, role=role, dn=display, ip=ip))
        return resp

    record_fail(ip)
    audit.warning(_kv(event="login_fail", reason="bad_credentials",
                      user=username, ip=ip))
    return RedirectResponse("/auth/login?error=1", 302)


@app.get("/auth/logout")
def logout(req: Request):
    sess = get_session(req)
    if sess:
        audit.info(_kv(event="logout", user=sess.get("u"),
                       role=sess.get("r"), ip=get_client_ip(req)))
    resp = RedirectResponse("/auth/login", 302)
    resp.delete_cookie(COOKIE, path="/")
    return resp


@app.get("/auth/check")
def check(req: Request):
    """
    Nginx auth_request 子請求：放行時回傳 X-Auth-* headers。
    nginx 用 auth_request_set 抓取後再 proxy_set_header 給下游。

    詳細審計：no_session / forbidden 在這裡顯式記原因，
    access middleware 會再記一行整體狀態（status / dur_ms）。
    兩條互補：這條告訴你「為什麼擋」，那條告訴你「整個請求耗時與結果」。
    """
    sess = get_session(req)
    ip = get_client_ip(req)
    uri = req.headers.get("X-Original-URI", "/")

    if not sess:
        audit.warning(_kv(event="auth_no_session", uri=uri, ip=ip))
        return Response(status_code=401)

    try:
        cfg = load_cfg()
    except Exception as e:
        log.exception("check: load_cfg failed: %s", e)
        return Response(status_code=401)

    role = sess.get("r", "")
    allowed = cfg.get("roles", {}).get(role, [])

    if not path_allowed(uri, allowed):
        audit.warning(_kv(event="forbidden", user=sess.get("u"), role=role,
                          dn=sess.get("n"), uri=uri, ip=ip))
        return Response(status_code=403)

    # ── 身份注入 ──
    username = sess.get("u", "")
    user = next((u for u in cfg.get("users", []) if u.get("username") == username), {}) or {}
    display = user.get("display_name") or sess.get("n") or username

    resp = Response(status_code=200)
    resp.headers["X-Auth-User"] = username
    resp.headers["X-Auth-Gw-Role"] = role           # Gateway 層角色（除錯 / 通用）
    resp.headers["X-Auth-Display-Name"] = quote(display, safe="")

    # ── finance 專用 header（保留完全兼容 kiki_DAta_Analysis）──
    fin = resolve_finance(user)
    if fin:
        resp.headers["X-Auth-Role"] = (fin.get("role") or "").upper()
        resp.headers["X-Auth-Dept-Scope"] = quote(fin.get("dept_scope") or "", safe="")
        resp.headers["X-Auth-Advisor-Name"] = quote(fin.get("advisor_name") or "", safe="")
        scope = fin.get("scope")
        if scope and isinstance(scope, dict):
            resp.headers["X-Auth-Scope"] = quote(
                json.dumps(scope, ensure_ascii=False, separators=(",", ":")),
                safe="",
            )
        else:
            resp.headers["X-Auth-Scope"] = ""
    else:
        resp.headers["X-Auth-Role"] = ""
        resp.headers["X-Auth-Dept-Scope"] = ""
        resp.headers["X-Auth-Advisor-Name"] = ""
        resp.headers["X-Auth-Scope"] = ""

    # ── 通用 extras（新看板可自由使用，users.yaml 的 user.extras dict）──
    extras = user.get("extras")
    if isinstance(extras, dict) and extras:
        resp.headers["X-Auth-Extras"] = quote(
            json.dumps(extras, ensure_ascii=False, separators=(",", ":")),
            safe="",
        )
    else:
        resp.headers["X-Auth-Extras"] = ""

    return resp


@app.get("/auth/me")
def me(req: Request):
    """前端取當前用戶 — 含 Gateway 路徑權限 + Finance 細粒度權限。"""
    sess = get_session(req)
    if not sess:
        return Response(status_code=401)
    try:
        cfg = load_cfg()
    except Exception as e:
        log.exception("me: load_cfg failed: %s", e)
        return Response(status_code=500)

    username = sess.get("u", "")
    user = next((u for u in cfg.get("users", []) if u.get("username") == username), {}) or {}
    fin = resolve_finance(user)

    return {
        "username": username,
        "role": sess.get("r"),                                            # Gateway role
        "display_name": user.get("display_name") or sess.get("n") or username,
        "allowed": cfg.get("roles", {}).get(sess.get("r", ""), []),
        "finance": {
            "role": (fin.get("role") if fin else None),
            "dept_scope": (fin.get("dept_scope") if fin else None),
            "advisor_name": (fin.get("advisor_name") if fin else None),
            "scope": (fin.get("scope") if fin else None),
        } if fin else None,
    }


@app.get("/auth/apps")
def apps_endpoint(req: Request):
    """
    回傳當前登入用戶可見的看板清單（portal.html 動態渲染用）。
    過濾邏輯：用戶 gw_role.paths 裡有哪些 app.path 前綴，就看到哪些。
    與 /auth/check 的 path_allowed 使用相同邊界判定，保證一致性。
    """
    sess = get_session(req)
    if not sess:
        return Response(status_code=401)
    try:
        cfg = load_cfg()
    except Exception as e:
        log.exception("apps: load_cfg failed: %s", e)
        return Response(status_code=500)

    role = sess.get("r", "")
    allowed = cfg.get("roles", {}).get(role, [])
    apps_list = load_apps()

    visible = []
    for a in apps_list:
        path = a.get("path")
        if not path:
            continue
        if path_allowed(path, allowed):
            visible.append({
                "id":   a.get("id"),
                "name": a.get("name", a.get("id")),
                "desc": a.get("desc", ""),
                "icon": a.get("icon", "📂"),
                "tag":  a.get("tag", ""),
                "path": path,
            })
    return visible


@app.get("/auth/health")
def health():
    return {"ok": True}


# ══════════════════════════════════════════════════════════
#   登入頁 HTML
# ══════════════════════════════════════════════════════════

LOGIN_HTML = """<!DOCTYPE html>
<html lang="zh-Hant">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>广州前途数据平台 · 登入</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  background:#f5f5f0;color:#2c2c2a;padding:20px}
.card{width:100%;max-width:360px;padding:40px;background:#fff;border-radius:16px;
  box-shadow:0 2px 24px rgba(0,0,0,.08)}
h1{font-size:20px;font-weight:600;margin-bottom:4px}
.sub{font-size:13px;color:#888;margin-bottom:28px}
label{display:block;font-size:13px;font-weight:500;margin-bottom:6px;color:#555}
input[type=text],input[type=password]{width:100%;padding:10px 14px;border:1px solid #ddd;
  border-radius:8px;font-size:15px;margin-bottom:16px;transition:border .2s;
  font-family:inherit}
input:focus{outline:none;border-color:#1d9e75}
button{width:100%;padding:12px;background:#1d9e75;color:#fff;border:none;
  border-radius:8px;font-size:15px;font-weight:500;cursor:pointer;transition:background .2s}
button:hover{background:#0f6e56}
.err{color:#e24b4a;margin:0 0 12px;font-size:13px}
</style></head>
<body><div class="card">
<h1>广州前途数据平台</h1><p class="sub">Data Analytics Portal</p>
{{ERROR}}
<form method="POST" action="/auth/login" autocomplete="on">
<label>帐号</label><input name="username" type="text" required autofocus autocomplete="username">
<label>密码</label><input name="password" type="password" required autocomplete="current-password">
<button type="submit">登 入</button>
</form></div></body></html>"""
