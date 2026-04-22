#!/usr/bin/env python3
"""
用戶管理 CLI（整合版 v2）
────────────────────────────────────────────────────────────
容器內執行:

  # 基本用戶
  add <username> <password|-> <gw_role> [display_name]
  passwd <username> [new_pwd|-]
  chrole <username> <new_gw_role>
  remove <username>

  # Finance 細粒度權限（數據層）
  set-finance <username> <ADMIN|MANAGER|ADVISOR> [--dept <d>] [--advisor <a>]
  set-finance-scope <username> [--line a,b,..] [--sub-line ...]
                               [--biz-block a,b,..] [--group-l1 ...]
                               [--group-advisor ...] [--biz-type 留学,多语]
  unset-finance <username>

  # 查看
  list

Gateway role (gw_role):  admin / manager / consultant / advisor / viewer
Finance role:            ADMIN / MANAGER / ADVISOR / SCOPED

範例:
  # 部門經理：只看留學二部
  add zhang_mgr - manager 張經理
  set-finance zhang_mgr MANAGER --dept 留學二部

  # 顧問老師：只看自己那行
  add wang - advisor 王老師
  set-finance wang ADVISOR --advisor 王曉明

  # 多維範圍（SCOPED）：吳嘉恒看歐亞板塊
  add wujiaheng ouya2026 manager 吳嘉恒
  set-finance-scope wujiaheng --line 欧洲,亚洲 --biz-block 欧亚,外包

  # 老闆：gateway manager + 看全公司數據（預設推導，不用 set-finance）
  add boss - manager 老闆
"""
import os
import sys
import getpass
import re

import yaml
from passlib.hash import bcrypt

YAML_PATH = os.environ.get(
    "USERS_YAML",
    "/app/users.yaml" if os.path.exists("/app/users.yaml") else "users.yaml"
)
VALID_GW_ROLES = {"admin", "manager", "consultant", "advisor", "viewer"}
VALID_FIN_ROLES = {"ADMIN", "MANAGER", "ADVISOR", "SCOPED"}
VALID_SCOPE_DIMS = {"line", "sub_line", "biz_block", "group_l1", "group_advisor", "biz_type"}
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{2,32}$")


# ── 公用 ────────────────────────────────────────────────────
def pwd_bytes(pwd: str) -> bytes:
    return pwd.encode("utf-8")[:72]


def load() -> dict:
    with open(YAML_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("roles", {})
    data.setdefault("users", [])
    return data


def save(cfg: dict):
    content = yaml.dump(cfg, allow_unicode=True,
                        default_flow_style=False, sort_keys=False)
    with open(YAML_PATH, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())


def find_user(cfg: dict, username: str):
    for u in cfg["users"]:
        if u["username"] == username:
            return u
    return None


def require_user(cfg: dict, username: str):
    u = find_user(cfg, username)
    if not u:
        print(f"✗ 找不到用戶: {username}")
        sys.exit(1)
    return u


def validate_username(user: str):
    if not USERNAME_RE.match(user):
        print(f"✗ 無效用戶名 '{user}'（限英數/底線/連字號，2-32 字元）")
        sys.exit(1)


def warn_weak_password(pwd: str):
    if len(pwd) < 8:
        print(f"⚠ 密碼過短 ({len(pwd)} 字元)，建議 ≥ 8")
    if len(pwd.encode("utf-8")) > 72:
        print(f"⚠ 密碼 utf-8 長度 > 72 字節，將被截斷")


def prompt_password() -> str:
    p1 = getpass.getpass("新密碼: ")
    p2 = getpass.getpass("再輸入一次: ")
    if p1 != p2:
        print("✗ 兩次密碼不一致"); sys.exit(1)
    if not p1:
        print("✗ 密碼不能為空"); sys.exit(1)
    return p1


def parse_flags(args, flags: dict):
    """
    簡單解析 --key value 形式的 flag。
    flags = {"--dept": "dept_scope", "--advisor": "advisor_name"}
    返回 (positional, parsed_dict)
    """
    positional, parsed = [], {}
    i = 0
    while i < len(args):
        a = args[i]
        if a in flags:
            if i + 1 >= len(args):
                print(f"✗ {a} 需要值"); sys.exit(1)
            parsed[flags[a]] = args[i + 1]
            i += 2
        else:
            positional.append(a)
            i += 1
    return positional, parsed


# ── 指令 ────────────────────────────────────────────────────

def cmd_add(args):
    if len(args) < 3:
        print("用法: add <username> <password|-> <gw_role> [display_name]")
        print(f"gw_role: {', '.join(sorted(VALID_GW_ROLES))}")
        sys.exit(1)
    user, pwd_arg, role = args[0], args[1], args[2]
    name = args[3] if len(args) > 3 else user
    validate_username(user)
    if role not in VALID_GW_ROLES:
        print(f"✗ 無效 gw_role: {role}（{', '.join(sorted(VALID_GW_ROLES))}）")
        sys.exit(1)
    pwd = prompt_password() if pwd_arg == "-" else pwd_arg
    warn_weak_password(pwd)

    cfg = load()
    if find_user(cfg, user):
        print(f"✗ 用戶 {user} 已存在，用 passwd 改密"); sys.exit(1)

    cfg["users"].append({
        "username": user,
        "password_hash": bcrypt.hash(pwd_bytes(pwd)),
        "role": role,
        "display_name": name,
    })
    save(cfg)
    print(f"✓ 新增 {user} (gw_role={role}, display={name})")
    if role == "advisor":
        print(f"  ⚠ advisor 需要配 finance 才能看到財務數據:")
        print(f"    set-finance {user} ADVISOR --advisor <姓名>")
    elif role in ("admin", "manager"):
        print(f"  ℹ finance 未配 → 自動映射為 ADMIN（看全部）。"
              f"如需限部門:")
        print(f"    set-finance {user} MANAGER --dept <部門>")


def cmd_passwd(args):
    if len(args) < 1:
        print("用法: passwd <username> [new_pwd|-]"); sys.exit(1)
    user = args[0]
    pwd = args[1] if len(args) > 1 and args[1] != "-" else prompt_password()
    warn_weak_password(pwd)
    cfg = load()
    u = require_user(cfg, user)
    u["password_hash"] = bcrypt.hash(pwd_bytes(pwd))
    save(cfg)
    print(f"✓ 已更新 {user} 密碼")


def cmd_remove(args):
    if len(args) < 1:
        print("用法: remove <username>"); sys.exit(1)
    user = args[0]
    cfg = load()
    before = len(cfg["users"])
    cfg["users"] = [u for u in cfg["users"] if u["username"] != user]
    if len(cfg["users"]) == before:
        print(f"✗ 找不到用戶: {user}"); sys.exit(1)
    save(cfg)
    print(f"✓ 已刪除 {user}")


def cmd_chrole(args):
    if len(args) < 2:
        print("用法: chrole <username> <new_gw_role>"); sys.exit(1)
    user, role = args[0], args[1]
    if role not in VALID_GW_ROLES:
        print(f"✗ 無效 gw_role: {role}"); sys.exit(1)
    cfg = load()
    u = require_user(cfg, user)
    old = u["role"]
    u["role"] = role
    save(cfg)
    print(f"✓ {user} 的 gw_role: {old} → {role}")


def cmd_set_finance(args):
    positional, flags = parse_flags(args, {
        "--dept": "dept_scope",
        "--advisor": "advisor_name",
    })
    if len(positional) < 2:
        print("用法: set-finance <username> <ADMIN|MANAGER|ADVISOR> "
              "[--dept <d>] [--advisor <a>]")
        sys.exit(1)
    user, fin_role = positional[0], positional[1].upper()
    if fin_role not in VALID_FIN_ROLES:
        print(f"✗ 無效 finance role: {fin_role}（{', '.join(sorted(VALID_FIN_ROLES))}）")
        sys.exit(1)

    cfg = load()
    u = require_user(cfg, user)
    fin = {"role": fin_role}
    if fin_role == "MANAGER":
        if not flags.get("dept_scope"):
            print("✗ MANAGER 必須帶 --dept <部門名>"); sys.exit(1)
        fin["dept_scope"] = flags["dept_scope"]
    elif fin_role == "ADVISOR":
        if not flags.get("advisor_name"):
            print("✗ ADVISOR 必須帶 --advisor <顧問姓名>"); sys.exit(1)
        fin["advisor_name"] = flags["advisor_name"]

    u["finance"] = fin
    save(cfg)
    desc = f"role={fin_role}"
    if "dept_scope" in fin: desc += f", dept={fin['dept_scope']}"
    if "advisor_name" in fin: desc += f", advisor={fin['advisor_name']}"
    print(f"✓ {user} 的 finance: {desc}")


def cmd_unset_finance(args):
    if len(args) < 1:
        print("用法: unset-finance <username>"); sys.exit(1)
    user = args[0]
    cfg = load()
    u = require_user(cfg, user)
    if "finance" in u:
        u.pop("finance")
        save(cfg)
        print(f"✓ 已清除 {user} 的 finance 設定"
              f"（若 gw_role ∈ admin/manager 將自動預設為 ADMIN）")
    else:
        print(f"ℹ {user} 原本就沒有 finance 設定")


def cmd_set_finance_scope(args):
    """設定多維度白名單（SCOPED 角色）
    用法: set-finance-scope <username> [--line a,b,..] [--sub-line ...]
                                        [--biz-block a,b,..] [--group-l1 ...]
                                        [--group-advisor ...] [--biz-type 留学,多语]
    第一性原理: scope 即「能看哪些 row」的多維謂詞，YAML 存的是白名單清單。
    """
    flag_map = {
        "--line":           "line",
        "--sub-line":       "sub_line",
        "--biz-block":      "biz_block",
        "--group-l1":       "group_l1",
        "--group-advisor":  "group_advisor",
        "--biz-type":       "biz_type",
    }
    positional, parsed = parse_flags(args, flag_map)
    if len(positional) < 1:
        print("用法: set-finance-scope <username> [--line a,b] [--biz-block a,b] ...")
        print(f"支援維度: {', '.join(sorted(VALID_SCOPE_DIMS))}")
        sys.exit(1)
    user = positional[0]

    scope = {}
    for dim, raw in parsed.items():
        vals = [v.strip() for v in raw.split(",") if v.strip()]
        if vals:
            scope[dim] = vals

    if not scope:
        print("✗ 至少要指定一個維度（例如 --line 欧洲,亚洲）"); sys.exit(1)

    # biz_type 值合法性檢查（只允許 留学 / 多语）
    if "biz_type" in scope:
        bad = [v for v in scope["biz_type"] if v not in ("留学", "多语")]
        if bad:
            print(f"✗ biz_type 只允許 '留学' 或 '多语'，非法值: {bad}"); sys.exit(1)

    cfg = load()
    u = require_user(cfg, user)
    u["finance"] = {"role": "SCOPED", "scope": scope}
    save(cfg)
    desc = ", ".join(f"{k}={v}" for k, v in scope.items())
    print(f"✓ {user} 的 finance: role=SCOPED, {desc}")


def cmd_list(_):
    cfg = load()
    print()
    print(f"{'用戶名':<18} {'gw_role':<12} {'finance':<50} {'顯示名稱'}")
    print("-" * 100)
    for u in cfg["users"]:
        fin = u.get("finance")
        if fin:
            role = fin.get("role", "")
            parts = [f"role={role}"]
            if fin.get("dept_scope"):    parts.append(f"dept={fin['dept_scope']}")
            if fin.get("advisor_name"):  parts.append(f"adv={fin['advisor_name']}")
            if role == "SCOPED":
                sc = fin.get("scope") or {}
                for k, v in sc.items():
                    parts.append(f"{k}={','.join(v)}" if isinstance(v, list) else f"{k}={v}")
            fin_str = ", ".join(parts)
        else:
            gw = u.get("role", "")
            if gw in ("admin", "manager"):
                fin_str = "(default: ADMIN)"
            elif gw == "advisor":
                fin_str = "⚠ advisor 缺 finance"
            else:
                fin_str = "-"
        print(f"{u['username']:<18} {u['role']:<12} {fin_str:<50} "
              f"{u.get('display_name', '-')}")
    print(f"\n共 {len(cfg['users'])} 位用戶\n")


# ── 入口 ────────────────────────────────────────────────────

COMMANDS = {
    "add":                 cmd_add,
    "passwd":              cmd_passwd,
    "remove":              cmd_remove,
    "chrole":              cmd_chrole,
    "set-finance":         cmd_set_finance,
    "set-finance-scope":   cmd_set_finance_scope,
    "unset-finance":       cmd_unset_finance,
    "list":                cmd_list,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        sys.exit(1)
    try:
        COMMANDS[sys.argv[1]](sys.argv[2:])
    except FileNotFoundError:
        print(f"✗ 找不到配置檔: {YAML_PATH}"); sys.exit(1)
    except PermissionError as e:
        print(f"✗ 無權限寫入: {e}")
        print("   → 寫入類指令請加 -u root:")
        print("     docker compose exec -u root auth-api python /app/manage.py ...")
        sys.exit(1)
