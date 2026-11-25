FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Docker CLI is needed only in guarded apply mode to start tenant compose
# projects. The daemon itself is NOT installed/started in this image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends docker.io ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/state /app/provisioned \
 && chmod 700 /app/state /app/provisioned

EXPOSE 8788
CMD ["python", "-B", "web/app.py", "--port", "8788"]
