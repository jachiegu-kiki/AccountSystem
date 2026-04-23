#!/usr/bin/env python3
"""
render_nginx.py  —  從 apps.yaml 生成 nginx.conf
────────────────────────────────────────────────────────────────
用法:
  python render_nginx.py [apps.yaml路徑] [輸出路徑]
  預設: apps.yaml 在 /app/apps.yaml（容器內），輸出到 stdout

設計原則:
  • 一個 app 產生一個 location block + 可選的 absolute_api 入口
  • 所有 X-Auth-* header 都從 auth-api 子請求回傳並統一注入
    （apps 不需要知道有哪些 header，自取所需）
  • 產出的 nginx.conf 與手動維護的版本**逐行等效**
────────────────────────────────────────────────────────────────
"""
import os
import sys
from pathlib import Path

import yaml


# ── 共用的 auth_request_set / proxy_set_header 區塊 ─────────────────
# 所有 X-Auth-* header 對所有 app 一律注入，下游按需消費
AUTH_HEADERS = [
    "X-Auth-User",
    "X-Auth-Gw-Role",
    "X-Auth-Role",           # finance 細粒度角色 ADMIN/MANAGER/ADVISOR/SCOPED
    "X-Auth-Dept-Scope",
    "X-Auth-Advisor-Name",
    "X-Auth-Scope",          # SCOPED 用的 JSON
    "X-Auth-Display-Name",
    "X-Auth-Extras",         # 通用 extras（為新看板預留）
]


def _nginx_var(h: str) -> str:
    """X-Auth-Dept-Scope → $auth_dept_scope"""
    return "$auth_" + h.lower().replace("x-auth-", "").replace("-", "_")


def _upstream_header(h: str) -> str:
    """X-Auth-Dept-Scope → $upstream_http_x_auth_dept_scope"""
    return "$upstream_http_" + h.lower().replace("-", "_")


def _auth_request_set_block(indent: str = "        ") -> str:
    """每個 location 都需要這段 auth_request_set，從 subrequest 回傳 header"""
    lines = []
    for h in AUTH_HEADERS:
        lines.append(f"{indent}auth_request_set {_nginx_var(h):<25} {_upstream_header(h)};")
    return "\n".join(lines)


def _proxy_set_auth_header_block(indent: str = "        ") -> str:
    """把 $auth_* 變數注入到 proxy_set_header（下游取得）"""
    lines = []
    for h in AUTH_HEADERS:
        lines.append(f"{indent}proxy_set_header {h:<22} {_nginx_var(h)};")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# 檔頭與共用基礎設施
# ─────────────────────────────────────────────────────────────────

PREAMBLE = """\
# ═══════════════════════════════════════════════════════════════
#  新東方數據平台 · Gateway Nginx（由 apps.yaml 自動生成）
# ═══════════════════════════════════════════════════════════════
#  ⚠  此文件由 auth-api/render_nginx.py 從 apps.yaml 生成
#     請勿手動編輯 — 改動路由請改 apps.yaml，再跑 deploy.sh
# ═══════════════════════════════════════════════════════════════

upstream auth_api {
    server auth-api:8000;
    keepalive 16;
}

map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name _;

    absolute_redirect    off;
    server_tokens        off;
    client_max_body_size 50m;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options        SAMEORIGIN always;
    add_header Referrer-Policy        strict-origin-when-cross-origin always;

    gzip on;
    gzip_types text/css application/javascript application/json text/xml image/svg+xml;
    gzip_min_length 1000;
    gzip_comp_level 6;
    gzip_vary on;

    # ══════════════════════════════════════════════════════════
    #  認證子請求（通用 /auth/check）
    # ══════════════════════════════════════════════════════════

    location = /auth/check {
        internal;
        proxy_pass                  http://auth_api/auth/check;
        proxy_pass_request_body     off;
        proxy_set_header            Content-Length "";
        proxy_set_header            X-Original-URI $request_uri;
        proxy_set_header            X-Real-IP      $remote_addr;
        proxy_set_header            Cookie         $http_cookie;
    }
"""


AUTH_LOCATION = """\

    # ══════════════════════════════════════════════════════════
    #  Auth 對外端點
    # ══════════════════════════════════════════════════════════

    location /auth/ {
        proxy_pass                  http://auth_api;
        proxy_set_header            Host              $http_host;
        proxy_set_header            X-Real-IP         $remote_addr;
        proxy_set_header            X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header            X-Forwarded-Proto $scheme;
        proxy_set_header            X-Forwarded-Host  $http_host;
        proxy_http_version          1.1;
    }
"""


def render_portal() -> str:
    """Portal 首頁（固定）"""
    a_set = _auth_request_set_block()
    return f"""\

    # ══════════════════════════════════════════════════════════
    #  Portal 首頁
    # ══════════════════════════════════════════════════════════

    location = /portal {{
        auth_request                /auth/check;
        error_page 401 = @login_redirect;
        error_page 403 = @forbidden;

        default_type                text/html;
        alias                       /usr/share/nginx/html/portal.html;
        add_header Cache-Control    "no-cache, no-store, must-revalidate" always;
    }}
"""


def render_absolute_api_check(app: dict) -> str:
    """為帶 absolute_api_path 的 app 生成專屬 check 子請求。
    把 X-Original-URI 改寫為 <app.path><原始 URI>，以便 path_allowed
    能命中 users.yaml roles 裡配置的 app.path。
    """
    app_id = app["id"]
    prefix = app["path"].rstrip("/")
    return f"""\

    # /{app_id} 絕對 API 的 check：把 URI 前綴補上 {prefix} 再驗
    location = /auth/check_{app_id} {{
        internal;
        proxy_pass                  http://auth_api/auth/check;
        proxy_pass_request_body     off;
        proxy_set_header            Content-Length "";
        proxy_set_header            X-Original-URI {prefix}$request_uri;
        proxy_set_header            X-Real-IP      $remote_addr;
        proxy_set_header            Cookie         $http_cookie;
    }}
"""


def render_app_location(app: dict) -> str:
    """每個 app 的主 location block"""
    app_id = app["id"]
    path = app["path"]                       # /finance/
    prefix = path.rstrip("/")                # /finance
    upstream = app["upstream"]
    a_set = _auth_request_set_block()
    a_inject = _proxy_set_auth_header_block()

    return f"""\

    # ══════════════════════════════════════════════════════════
    #  項目：{app.get('name', app_id)}  ({app_id})
    #  下游: {upstream}
    # ══════════════════════════════════════════════════════════

    location {path} {{
        auth_request                /auth/check;
        error_page 401 = @login_redirect;
        error_page 403 = @forbidden;

        # ── 從 /auth/check 子請求回傳中抓取身份 header ──
{a_set}

        rewrite ^{path}(.*)$     /$1 break;
        proxy_pass                  http://{upstream};

        # ── 統一注入全部 X-Auth-* 給下游（下游按需消費）──
{a_inject}

        # ── 標準 proxy header ──
        proxy_set_header Host              $http_host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $http_host;
        proxy_set_header X-Forwarded-Prefix {prefix};

        proxy_http_version  1.1;
        proxy_set_header    Upgrade    $http_upgrade;
        proxy_set_header    Connection $connection_upgrade;

        proxy_redirect      ~^http://[^/]+(/.*)$  {prefix}$1;
        proxy_buffering     off;
        proxy_read_timeout  300s;
    }}
    location = {prefix} {{ return 302 {path}; }}
"""


def render_absolute_api_location(app: dict) -> str:
    """app 的 absolute_api_path（如 finance 的 /api/）"""
    if not app.get("absolute_api_path"):
        return ""
    app_id = app["id"]
    api_path = app["absolute_api_path"]
    upstream = app["upstream"]
    a_set = _auth_request_set_block()
    a_inject = _proxy_set_auth_header_block()

    return f"""\

    # ── {app.get('name', app_id)} 的絕對 API: {api_path}* ──
    location {api_path} {{
        auth_request                /auth/check_{app_id};
        error_page 401 = @login_redirect;
        error_page 403 = @forbidden;

{a_set}

        proxy_pass                  http://{upstream};

{a_inject}

        proxy_set_header Host              $http_host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $http_host;
        proxy_http_version 1.1;

        proxy_buffering     off;
        proxy_read_timeout  300s;
    }}
"""


FOOTER = """\

    # ══════════════════════════════════════════════════════════
    #  根 + 錯誤
    # ══════════════════════════════════════════════════════════

    location = / { return 302 /portal; }

    location @login_redirect { return 302 /auth/login; }

    location @forbidden {
        default_type text/html;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        return 403 '<!DOCTYPE html><html lang="zh-Hant"><head><meta charset="utf-8"><title>403</title>
<style>body{display:flex;align-items:center;justify-content:center;min-height:100vh;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f5f5f0;color:#555;margin:0}
.c{text-align:center;padding:20px}h1{font-size:64px;color:#ddd;margin:0 0 8px}p{margin:8px 0}
a{color:#1d9e75;text-decoration:none}a:hover{text-decoration:underline}</style></head><body><div class="c">
<h1>403</h1><p>你沒有權限查看此頁面</p>
<p><a href="/portal">返回首頁</a> · <a href="/auth/logout">換個帳號</a></p>
</div></body></html>';
    }

    location = /favicon.ico {
        return 204;
        access_log off;
        log_not_found off;
    }
}
"""


def render(apps_yaml_path: str) -> str:
    with open(apps_yaml_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    apps = cfg.get("apps") or []
    if not apps:
        raise RuntimeError(f"{apps_yaml_path}: apps 清單為空")

    # 基本欄位校驗
    for i, a in enumerate(apps):
        for required in ("id", "path", "upstream"):
            if not a.get(required):
                raise RuntimeError(f"apps[{i}]: 缺少必填欄位 '{required}'")
        if not a["path"].startswith("/") or not a["path"].endswith("/"):
            raise RuntimeError(
                f"apps[{i}] id={a['id']}: path 必須以 / 開頭和結尾（如 /finance/）"
            )

    parts = [PREAMBLE]

    # 為每個有 absolute_api_path 的 app 先輸出 check_xxx 子請求
    for a in apps:
        if a.get("absolute_api_path"):
            parts.append(render_absolute_api_check(a))

    parts.append(AUTH_LOCATION)
    parts.append(render_portal())

    # 每個 app 的 location
    for a in apps:
        parts.append(render_app_location(a))
        if a.get("absolute_api_path"):
            parts.append(render_absolute_api_location(a))

    parts.append(FOOTER)
    return "".join(parts)


def main():
    default_yaml = "/app/apps.yaml" if os.path.exists("/app/apps.yaml") else "apps.yaml"
    apps_yaml = sys.argv[1] if len(sys.argv) > 1 else default_yaml
    output = sys.argv[2] if len(sys.argv) > 2 else None

    content = render(apps_yaml)
    if output:
        Path(output).write_text(content, encoding="utf-8")
        print(f"✓ 已寫入 {output}", file=sys.stderr)
    else:
        sys.stdout.write(content)


if __name__ == "__main__":
    main()
