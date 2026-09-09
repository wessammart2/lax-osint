FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# تثبيت PhoneInfoga (Binary رسمي — غير متوفر على PyPI)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL "https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_x86_64.tar.gz" -o /tmp/phoneinfoga.tar.gz \
    && tar -xzf /tmp/phoneinfoga.tar.gz -C /usr/local/bin phoneinfoga \
    && chmod +x /usr/local/bin/phoneinfoga \
    && rm -f /tmp/phoneinfoga.tar.gz \
    && rm -rf /var/lib/apt/lists/*

# التحقق من وجود الأدوات (غير قاتل للبناء)
RUN maigret --version || true
RUN phoneinfoga version || true

COPY . .

EXPOSE 8000

# Railway يمرر PORT عبر البيئة؛ نستخدمه إن وُجد وإلا 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]