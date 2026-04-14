FROM python:3.12-slim

WORKDIR /app

# Dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Dépendances Python
COPY requirements.txt web/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r web/requirements.txt

# Code source
COPY src/ ./src/
COPY web/ ./web/

# .env optionnel (clés API)
COPY .env* ./

ENV PYTHONUNBUFFERED=1

EXPOSE 8888

CMD ["python", "web/app.py"]
