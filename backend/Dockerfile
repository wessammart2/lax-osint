FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# أدوات البحث الاختيارية — أزل التعليق لتفعيلها في الإنتاج (تُضخّم الصورة)
# RUN pip install --no-cache-dir maigret holehe duckduckgo-search beautifulsoup4

COPY . .

EXPOSE 8000

# Railway يمرر PORT عبر البيئة؛ نستخدمه إن وُجد وإلا 8000
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]