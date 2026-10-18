"""
Phase 1 - Demo Environment: Train model, log to MLflow, register.
Trains fraud detection models (v1 good, v2 bad) and registers them.
Run this first to set up the demo environment.
"""
import os
import sys
import json
import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score, f1_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings('ignore')

DEMO_DIR = Path(__file__).parent
DATA_DIR = DEMO_DIR / 'data'
DATA_DIR.mkdir(exist_ok=True)

MLFLOW_TRACKING_URI = os.getenv('MLFLOW_TRACKING_URI', 'sqlite:///./demo/mlruns.db')
EXPERIMENT_NAME = 'fraud_detection'
MODEL_NAME = 'fraud_classifier'


def generate_dataset(n_samples: int = 5000, seed: int = 42, drift: bool = False) -> pd.DataFrame:
    """Generate synthetic fraud detection dataset."""
    rng = np.random.RandomState(seed)

    # Base features
    amount = rng.exponential(scale=100, size=n_samples)
    n_transactions_day = rng.poisson(lam=5, size=n_samples)
    account_age_days = rng.randint(1, 3650, size=n_samples)
    hour_of_day = rng.randint(0, 24, size=n_samples)
    distance_from_home = rng.exponential(scale=20, size=n_samples)
    credit_score = rng.normal(loc=650, scale=100, size=n_samples).clip(300, 850)

    if drift:
        # Inject drift: shift amount distribution, add nulls
        amount = rng.exponential(scale=350, size=n_samples)  # mean shifted
        credit_score = rng.normal(loc=550, scale=150, size=n_samples).clip(300, 850)  # lower scores
        # Add ~10% nulls to distance_from_home
        null_mask = rng.random(n_samples) < 0.10
        distance_from_home = distance_from_home.astype(float)
        distance_from_home[null_mask] = np.nan

    # Fraud label (more fraud at high amounts, odd hours)
    fraud_prob = (
        0.02 +
        0.15 * (amount > 400).astype(float) +
        0.10 * ((hour_of_day < 5) | (hour_of_day > 22)).astype(float) +
        0.08 * (distance_from_home > 50).astype(float) +
        0.05 * (n_transactions_day > 10).astype(float)
    ).clip(0, 0.95)
    is_fraud = rng.random(n_samples) < fraud_prob

    df = pd.DataFrame({
        'amount': amount,
        'n_transactions_day': n_transactions_day,
        'account_age_days': account_age_days,
        'hour_of_day': hour_of_day,
        'distance_from_home': distance_from_home,
        'credit_score': credit_score,
        'is_fraud': is_fraud.astype(int),
    })
    return df


def train_v1(df: pd.DataFrame, mlflow_client):
    """Train good v1 model on clean data."""
    df_clean = df.dropna()
    X = df_clean.drop('is_fraud', axis=1)
    y = df_clean['is_fraud']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    mlflow.set_experiment(EXPERIMENT_NAME)
    with mlflow.start_run(run_name='v1_good_model') as run:
        pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', GradientBoostingClassifier(n_estimators=100, max_depth=4, random_state=42))
        ])
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)
        y_prob = pipeline.predict_proba(X_test)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_prob)
        f1 = f1_score(y_test, y_pred)

        mlflow.log_param('model_type', 'GradientBoosting')
        mlflow.log_param('n_estimators', 100)
        mlflow.log_param('data_version', 'v1_clean')
        mlflow.log_metric('accuracy', acc)
        mlflow.log_metric('auc', auc)
        mlflow.log_metric('f1', f1)
        mlflow.log_metric('training_samples', len(X_train))
        mlflow.sklearn.log_model(
            pipeline, 'model', serialization_format='cloudpickle', registered_model_name=MODEL_NAME
        )

        print(f'v1: acc={acc:.4f} auc={auc:.4f} f1={f1:.4f} run_id={run.info.run_id}')
        return run.info.run_id


def train_v2(df_drift: pd.DataFrame):
    """Train bad v2 model on drifted data."""
    # Fill nulls with 0 (bad practice, intentional regression)
    df_bad = df_drift.fillna(0)
    X = df_bad.drop('is_fraud', axis=1)
    y = df_bad['is_fraud']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    mlflow.set_experiment(EXPERIMENT_NAME)
    with mlflow.start_run(run_name='v2_bad_model') as run:
        pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', LogisticRegression(C=0.01, random_state=42, max_iter=200))
        ])
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)
        y_prob = pipeline.predict_proba(X_test)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_prob)
        f1 = f1_score(y_test, y_pred)

        mlflow.log_param('model_type', 'LogisticRegression')
        mlflow.log_param('C', 0.01)
        mlflow.log_param('data_version', 'v2_drifted')
        mlflow.log_metric('accuracy', acc)
        mlflow.log_metric('auc', auc)
        mlflow.log_metric('f1', f1)
        mlflow.log_metric('training_samples', len(X_train))
        mlflow.sklearn.log_model(
            pipeline, 'model', serialization_format='cloudpickle', registered_model_name=MODEL_NAME
        )


        print(f'v2: acc={acc:.4f} auc={auc:.4f} f1={f1:.4f} run_id={run.info.run_id}')
        return run.info.run_id


def set_aliases(client):
    """Promote v2 to production (the bad model) for demo scenario."""
    versions = client.search_model_versions(f"name='{MODEL_NAME}'")
    versions_sorted = sorted(versions, key=lambda v: int(v.version))
    if len(versions_sorted) >= 2:
        v1_ver = versions_sorted[0].version
        v2_ver = versions_sorted[1].version
        # v1 gets 'champion' alias
        client.set_registered_model_alias(MODEL_NAME, 'champion', v1_ver)
        # v2 gets 'production' alias - this is the bad one that needs rollback
        client.set_registered_model_alias(MODEL_NAME, 'production', v2_ver)
        print(f'Aliases set: champion=v{v1_ver}, production=v{v2_ver}')
    elif len(versions_sorted) == 1:
        client.set_registered_model_alias(MODEL_NAME, 'production', versions_sorted[0].version)
        print(f'Single version set as production: v{versions_sorted[0].version}')


def main():
    mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
    client = mlflow.MlflowClient(tracking_uri=MLFLOW_TRACKING_URI)

    print('=== GuardML Demo: Training Models ===')
    print('Generating clean dataset (v1)...')
    df_clean = generate_dataset(n_samples=5000, seed=42, drift=False)
    df_clean.to_csv(DATA_DIR / 'train_clean.csv', index=False)
    print(f'Clean dataset: {len(df_clean)} rows, fraud rate={df_clean.is_fraud.mean():.3f}')

    print('\nGenerating drifted dataset (v2)...')
    df_drift = generate_dataset(n_samples=5000, seed=99, drift=True)
    df_drift.to_csv(DATA_DIR / 'train_drifted.csv', index=False)
    null_pct = df_drift.distance_from_home.isna().mean()
    print(f'Drifted dataset: {len(df_drift)} rows, nulls={null_pct:.1%}')

    print('\nTraining v1 (good model)...')
    train_v1(df_clean, client)

    print('\nTraining v2 (bad model on drifted data)...')
    train_v2(df_drift)

    print('\nSetting model aliases...')
    set_aliases(client)

    # Save reference data for drift comparison
    ref_data = df_clean.drop('is_fraud', axis=1).dropna()
    ref_data.to_csv(DATA_DIR / 'reference.csv', index=False)
    print(f'\nReference data saved: {len(ref_data)} rows')

    # Save current production data (drifted)
    curr_data = df_drift.drop('is_fraud', axis=1)
    curr_data.to_csv(DATA_DIR / 'current.csv', index=False)
    print(f'Current (drifted) data saved: {len(curr_data)} rows')

    print('\n=== Setup complete! ===')
    print(f'MLflow tracking: {MLFLOW_TRACKING_URI}')
    print('Run: mlflow ui --backend-store-uri sqlite:///./demo/mlruns.db')


if __name__ == '__main__':
    main()
