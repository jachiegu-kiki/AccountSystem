FROM python:3.12-slim

# 安全：非 root 運行
RUN useradd --create-home --shell /usr/sbin/nologin app

WORKDIR /app

# 先裝依賴，利用 docker layer cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 應用代碼
COPY main.py .
COPY manage.py .

# 預設 healthcheck 端點（簡單 HTTP GET，不跑 I/O）
HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=10s \
    CMD python -c "import urllib.request, sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/auth/health', timeout=3).status == 200 else 1)"

USER app

# workers=1：記憶體限流字典需要單 worker；用戶量大再換 Redis
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]
