FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY demo/ ./demo/
COPY . .

ENV MLFLOW_TRACKING_URI=sqlite:///./demo/mlruns.db
ENV MODEL_NAME=fraud_classifier
ENV MODEL_ALIAS=production

EXPOSE 8001

CMD ["uvicorn", "demo.model_api:app", "--host", "0.0.0.0", "--port", "8001"]
