"""
Drift detection tool: per-feature Kolmogorov-Smirnov test (SciPy).
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from .base import BaseTool, RiskLevel

DATA_DIR = Path(os.getenv('GUARDML_DATA_DIR', './demo/data'))


class DriftReport(BaseTool):
    name = 'drift_report'
    description = (
        'Run a data drift report (per-feature Kolmogorov-Smirnov test) comparing reference data to current data. '
        'Returns per-feature drift scores and a summary.'
    )
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'reference_path': {
                'type': 'string',
                'x-guard': 'path',
                'default': '',
                'description': 'Path to reference CSV. Defaults to demo/data/reference.csv',
            },
            'current_path': {
                'type': 'string',
                'x-guard': 'path',
                'default': '',
                'description': 'Path to current CSV. Defaults to demo/data/current.csv',
            },
            'columns': {
                'type': 'array',
                'items': {'type': 'string', 'x-guard': 'identifier'},
                'description': 'Specific columns to check. Empty = all numeric columns.',
                'default': [],
            },
        },
        'required': [],
    }

    def _execute(
        self,
        reference_path: str = '',
        current_path: str = '',
        columns: Optional[List[str]] = None,
        **_,
    ) -> Dict:
        ref_path = Path(reference_path) if reference_path else DATA_DIR / 'reference.csv'
        cur_path = Path(current_path) if current_path else DATA_DIR / 'current.csv'

        if not ref_path.exists():
            return {'error': f'Reference data not found: {ref_path}', 'ok': False}
        if not cur_path.exists():
            return {'error': f'Current data not found: {cur_path}', 'ok': False}

        ref_df = pd.read_csv(ref_path)
        cur_df = pd.read_csv(cur_path)

        # Select columns
        num_cols = ref_df.select_dtypes(include='number').columns.tolist()
        if columns:
            num_cols = [c for c in columns if c in num_cols]

        # Remove label column if present
        for label_col in ['is_fraud', 'label', 'target']:
            if label_col in num_cols:
                num_cols.remove(label_col)

        ref_sub = ref_df[num_cols].copy()
        cur_sub = cur_df[[c for c in num_cols if c in cur_df.columns]].copy()

        per_feature = {}
        try:
            from scipy.stats import ks_2samp
            for col in num_cols:
                if col in cur_sub.columns:
                    s1 = ref_sub[col].dropna()
                    s2 = cur_sub[col].dropna()
                    if len(s1) > 0 and len(s2) > 0:
                        _, pval = ks_2samp(s1, s2)
                        drifted = bool(pval < 0.05)
                        per_feature[col] = {
                            'drifted': drifted,
                            'score': round(float(pval), 4),
                            'method': 'Kolmogorov-Smirnov',
                            'threshold': 0.05,
                        }
        except Exception as e:
            # Fallback simple mean difference
            for col in num_cols:
                if col in cur_sub.columns:
                    m1 = ref_sub[col].mean()
                    m2 = cur_sub[col].mean()
                    diff = abs(m2 - m1) / (abs(m1) + 1e-6)
                    per_feature[col] = {
                        'drifted': bool(diff > 0.2),
                        'score': round(float(diff), 4),
                        'method': 'Mean Shift',
                        'threshold': 0.2,
                    }

        drifted_features = [k for k, v in per_feature.items() if v['drifted']]
        share_drifted = len(drifted_features) / len(per_feature) if per_feature else 0.0
        dataset_drift = share_drifted > 0.3

        return {
            'ok': True,
            'dataset_drift_detected': dataset_drift,
            'share_of_drifted_columns': round(share_drifted, 4),
            'drifted_features': drifted_features,
            'feature_details': per_feature,
            'reference_rows': len(ref_sub),
            'current_rows': len(cur_sub),
        }

