"""
Phase 1 - Demo model serving API.
A small FastAPI app that serves the production model alias from MLflow.
"""
import os
import json
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import mlflow
import mlflow.pyfunc

MLFLOW_TRACKING_URI = os.getenv('MLFLOW_TRACKING_URI', 'sqlite:///./demo/mlruns.db')
MODEL_NAME = os.getenv('MODEL_NAME', 'fraud_classifier')
MODEL_ALIAS = os.getenv('MODEL_ALIAS', 'production')

mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)

app = FastAPI(title='GuardML Demo Model API', version='1.0.0')

_model = None


def load_model():
    global _model
    model_uri = f'models:/{MODEL_NAME}@{MODEL_ALIAS}'
    _model = mlflow.pyfunc.load_model(model_uri)
    print(f'Loaded model: {model_uri}')


@app.on_event('startup')
async def startup_event():
    load_model()


class PredictRequest(BaseModel):
    data: List[Dict[str, Any]] = Field(..., description='List of feature dicts')


class PredictResponse(BaseModel):
    predictions: List[int]
    probabilities: List[float]
    model_name: str
    model_alias: str


@app.post('/predict', response_model=PredictResponse)
async def predict(request: PredictRequest):
    if _model is None:
        raise HTTPException(status_code=503, detail='Model not loaded')
    try:
        df = pd.DataFrame(request.data)
        preds = _model.predict(df)
        # Try to get probabilities if available
        try:
            proba = _model.predict(df)  # pyfunc returns array
            probabilities = [float(p) for p in preds]
        except Exception:
            probabilities = [float(p) for p in preds]
        return PredictResponse(
            predictions=[int(p) for p in preds],
            probabilities=probabilities,
            model_name=MODEL_NAME,
            model_alias=MODEL_ALIAS,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get('/health')
async def health():
    model_loaded = _model is not None
    return {
        'status': 'healthy' if model_loaded else 'degraded',
        'model_loaded': model_loaded,
        'model_name': MODEL_NAME,
        'model_alias': MODEL_ALIAS,
    }


@app.get('/reload')
async def reload_model():
    """Reload the production model (used after alias changes)."""
    try:
        load_model()
        return {'status': 'reloaded', 'model_name': MODEL_NAME, 'model_alias': MODEL_ALIAS}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8001)
