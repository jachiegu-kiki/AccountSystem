#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  新東方數據平台 · Auth Gateway 部署腳本 v3
# ═══════════════════════════════════════════════════════════════
#  用法:  bash deploy.sh
#  前提:  服務器已裝 Docker + Docker Compose v2
#
#  v3 變更:
#    ✅ 部署前從 apps.yaml 自動渲染 nginx.conf（無需 python3 在宿主機）
#       渲染透過容器執行，宿主機零依賴
#    ✅ 修改 apps.yaml 後 bash deploy.sh 即重新生效
#
#  v2 保留:
#    ✅ 不在宿主機 pip install（避免 --break-system-packages 污染）
#    ✅ 所有用戶管理都透過 docker compose exec 走容器
#    ✅ 檢測 admin 的無效 hash 佔位符並強制設密碼
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

C_CYAN='\033[36m'; C_GRN='\033[32m'; C_YEL='\033[33m'; C_RED='\033[31m'; C_OFF='\033[0m'

echo "═══════════════════════════════════════════════════════════"
echo "  新東方數據平台 · Auth Gateway 部署 v3"
echo "═══════════════════════════════════════════════════════════"

# ── 1. 檢查 Docker ──────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo -e "${C_RED}✗ 未安裝 Docker${C_OFF}"
    echo "  Ubuntu/Debian:  curl -fsSL https://get.docker.com | sh"
    exit 1
fi
if ! docker compose version &>/dev/null; then
    echo -e "${C_RED}✗ Docker Compose v2 未就緒${C_OFF}"
    exit 1
fi
echo -e "${C_GRN}✓ Docker 環境就緒${C_OFF}"

# ── 2. 生成 SECRET_KEY（若 .env 不存在）────────────────────
ENV_FILE="$SCRIPT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    SK=$(openssl rand -hex 32)
    cat > "$ENV_FILE" <<EOF
# 自動生成 — 洩漏會導致所有 cookie 失效，請妥善保管
SECRET_KEY=$SK
# Gateway 對外端口（可改）
GW_PORT=8770
EOF
    chmod 600 "$ENV_FILE"
    echo -e "${C_GRN}✓ 已生成 .env${C_OFF}"
else
    echo -e "${C_GRN}✓ .env 已存在，保留原值${C_OFF}"
fi

# ── 3. 確認 apps.yaml 存在 ─────────────────────────────────
if [ ! -f "$SCRIPT_DIR/apps.yaml" ]; then
    echo -e "${C_RED}✗ apps.yaml 不存在${C_OFF}"
    echo "  看板註冊表由 apps.yaml 管理，請先建立該文件"
    exit 1
fi
APPS_COUNT=$(grep -c '^  - id:' apps.yaml || echo 0)
echo -e "${C_GRN}✓ apps.yaml 就緒（${APPS_COUNT} 個看板）${C_OFF}"

# ── 4. 提醒下游服務的網絡配置 ──────────────────────────────
cat <<'EOF'

┌──────────────────────────────────────────────────────────────┐
│  ⚠  重要：下游服務（8771、8772、…）的網絡隔離               │
│                                                              │
│  【方案 A・推薦・最簡單】雲安全組保護                         │
│    ▸ 下游綁 0.0.0.0:8771 / 0.0.0.0:8772（或 docker 預設）   │
│    ▸ 雲服務器安全組「入站規則」只開 8770                     │
│    ▸ 關閉下游公網入站                                        │
│                                                              │
│  【方案 B・進階】下游加入 gw_net docker 網絡                 │
│    ▸ 下游 docker-compose 加:                                 │
│        networks: [gw_net]                                    │
│      外層:                                                   │
│        networks:                                             │
│          gw_net:                                             │
│            external: true                                    │
│    ▸ 然後把 apps.yaml 的 upstream 改成 <container_name>:80   │
└──────────────────────────────────────────────────────────────┘

EOF

# ── 5. 構建映像 ─────────────────────────────────────────────
echo "→ 構建 auth-api 映像..."
docker compose build

# ── 6. 從 apps.yaml 渲染 nginx.conf ──────────────────────────
# 透過 auth-api 容器執行（宿主機不需要 python3 + pyyaml）
echo "→ 從 apps.yaml 渲染 nginx.conf..."
docker compose run --rm --no-deps --entrypoint python \
    -v "$SCRIPT_DIR/apps.yaml:/work/apps.yaml:ro" \
    -v "$SCRIPT_DIR:/out" \
    auth-api /app/render_nginx.py /work/apps.yaml /out/nginx.conf
echo -e "${C_GRN}✓ nginx.conf 已更新（$(wc -l < nginx.conf) 行）${C_OFF}"

# ── 7. 啟動服務 ──────────────────────────────────────────────
echo "→ 啟動 Gateway..."
docker compose up -d
# 對已跑中的 nginx 強制 reload（volumes 是 ro 掛載，docker 不會自動重啟）
if docker ps --format '{{.Names}}' | grep -q '^gw_nginx$'; then
    if docker compose exec -T gateway nginx -t >/dev/null 2>&1; then
        docker compose exec -T gateway nginx -s reload >/dev/null 2>&1 && \
            echo -e "${C_GRN}✓ nginx 已 reload${C_OFF}" || \
            echo -e "${C_YEL}⚠ nginx reload 失敗${C_OFF}"
    else
        echo -e "${C_YEL}⚠ nginx -t 校驗失敗，請檢查 nginx.conf${C_OFF}"
    fi
fi

# 等 auth-api 就緒（healthcheck 通過）
echo -n "→ 等待 auth-api 就緒"
for i in $(seq 1 30); do
    STATUS=$(docker inspect -f '{{.State.Health.Status}}' gw_auth 2>/dev/null || echo "starting")
    if [ "$STATUS" = "healthy" ]; then
        echo -e " ${C_GRN}✓${C_OFF}"
        break
    fi
    echo -n "."
    sleep 1
    if [ "$i" = "30" ]; then
        echo -e " ${C_RED}✗ 超時${C_OFF}"
        echo "  請執行 'docker compose logs auth-api' 查看錯誤"
        exit 1
    fi
done

# ── 8. 設定 admin 密碼 ─────────────────────────────────────
if [ -f users.yaml ] && grep -q 'PLACEHOLDER_PLEASE_RUN_DEPLOY_SH' users.yaml; then
    echo ""
    echo -e "${C_YEL}⚠  檢測到 admin 密碼尚未設定${C_OFF}"
    while true; do
        read -srp "  設定 admin 密碼 (不少於 8 位): " ADMIN_PWD; echo
        if [ "${#ADMIN_PWD}" -lt 8 ]; then
            echo -e "  ${C_RED}密碼太短${C_OFF}"
            continue
        fi
        read -srp "  再輸入一次: " ADMIN_PWD2; echo
        if [ "$ADMIN_PWD" != "$ADMIN_PWD2" ]; then
            echo -e "  ${C_RED}兩次不一致${C_OFF}"
            continue
        fi
        break
    done
    docker compose exec -u root -T auth-api python /app/manage.py passwd admin "$ADMIN_PWD"
    unset ADMIN_PWD ADMIN_PWD2
fi

# ── 9. 顯示服務狀態與訪問方式 ──────────────────────────────
GW_PORT="$(grep -E '^GW_PORT=' "$ENV_FILE" 2>/dev/null | cut -d= -f2)"
GW_PORT="${GW_PORT:-8770}"
SERVER_IP="$(curl -s --max-time 3 ifconfig.me 2>/dev/null || echo 'YOUR_SERVER_IP')"

echo ""
echo -e "${C_GRN}═══════════════════════════════════════════════════════════${C_OFF}"
echo -e "${C_GRN}  ✅ 部署完成${C_OFF}"
echo -e "${C_GRN}═══════════════════════════════════════════════════════════${C_OFF}"
echo ""
echo -e "  ${C_CYAN}入口:${C_OFF}  http://${SERVER_IP}:${GW_PORT}/"
echo -e "  ${C_CYAN}登入:${C_OFF}  http://${SERVER_IP}:${GW_PORT}/auth/login"
echo ""
echo "  ── 新增看板 ──"
echo "    1. 編輯 apps.yaml 加一個區塊"
echo "    2. 編輯 users.yaml 把新 path 加入對應 roles"
echo "    3. bash deploy.sh    # 自動重渲染 + reload"
echo ""
echo "  ── 日常管理（全部在容器內執行，宿主機無需裝 Python 依賴）──"
echo ""
echo "  ℹ  讀取類操作不加 -u：list"
echo "  ℹ  寫入類操作要加 -u root：add / passwd / remove / chrole"
echo ""
echo "    docker compose exec          auth-api python /app/manage.py list"
echo "    docker compose exec -u root  auth-api python /app/manage.py add boss P@ssw0rd manager 老闆"
echo "    docker compose exec -u root  auth-api python /app/manage.py passwd admin -"
echo "    docker compose exec -u root  auth-api python /app/manage.py remove teacher_wang"
echo ""
echo "  ── 查看日誌 ──"
echo ""
echo "    docker compose logs -f auth-api    # 認證日誌"
echo "    docker compose logs -f gateway     # nginx 訪問日誌"
echo ""
