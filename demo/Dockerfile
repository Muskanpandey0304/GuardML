FROM python:3.11-slim

WORKDIR /app

# curl is used by the compose healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY demo/ ./demo/
COPY . .

ENV MLFLOW_TRACKING_URI=sqlite:///./demo/mlruns.db
ENV MODEL_NAME=fraud_classifier
ENV MODEL_ALIAS=production

EXPOSE 8001

CMD ["uvicorn", "demo.model_api:app", "--host", "0.0.0.0", "--port", "8001"]
