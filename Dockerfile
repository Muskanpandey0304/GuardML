FROM python:3.11-slim

# The repo root IS the `guardml` package, so it is copied to /app/guardml and
# /app is put on PYTHONPATH. That makes `guardml.api.main` importable.
WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git \
    && rm -rf /var/lib/apt/lists/*

# Non-root user (fixed UID/GID so bind-mounted dirs can be chowned on the host)
RUN groupadd --system --gid 1000 guardml \
    && useradd --system --uid 1000 --gid guardml --home-dir /app --shell /usr/sbin/nologin guardml

# Python deps (installed as root, system-wide)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code (.dockerignore keeps .env, *.db and venvs out of the image)
COPY . /app/guardml
ENV PYTHONPATH=/app
WORKDIR /app/guardml

# Writable directories; /app/data holds the SQLite DB (mounted as a volume)
RUN mkdir -p demo/data reports /app/data \
    && chown -R guardml:guardml /app

USER guardml

EXPOSE 8000 8501

CMD ["uvicorn", "guardml.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
