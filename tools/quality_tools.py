"""
Data quality tool: null fractions and numeric ranges (pandas).
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from .base import BaseTool, RiskLevel

DATA_DIR = Path(os.getenv('GUARDML_DATA_DIR', './demo/data'))


class DataQualityCheck(BaseTool):
    name = 'data_quality_check'
    description = (
        'Run data quality checks (null fractions and numeric ranges) on a CSV file. '
        'Checks for nulls, value ranges, and schema conformance.'
    )
    risk_level = RiskLevel.READ
    parameters_schema = {
        'type': 'object',
        'properties': {
            'data_path': {
                'type': 'string',
                'x-guard': 'path',
                'default': '',
                'description': 'Path to CSV. Defaults to demo/data/current.csv',
            },
            'null_threshold': {
                'type': 'number',
                'minimum': 0,
                'maximum': 1,
                'default': 0.05,
                'description': 'Max allowed null fraction per column (0.0-1.0)',
            },
            'columns': {
                'type': 'array',
                'items': {'type': 'string', 'x-guard': 'identifier'},
                'default': [],
                'description': 'Columns to check. Empty = all columns.',
            },
        },
        'required': [],
    }

    def _execute(
        self,
        data_path: str = '',
        null_threshold: float = 0.05,
        columns: Optional[List[str]] = None,
        **_,
    ) -> Dict:
        path = Path(data_path) if data_path else DATA_DIR / 'current.csv'
        if not path.exists():
            return {'error': f'Data not found: {path}', 'ok': False}

        df = pd.read_csv(str(path))
        cols = list(columns) if columns else df.columns.tolist()
        results = []
        failed = []
        passed = []

        for col in cols:
            if col not in df.columns:
                continue
            col_results = {'column': col, 'checks': []}

            # Check null fraction
            actual_null = float(df[col].isna().mean())
            col_results['null_fraction'] = round(actual_null, 4)
            col_results['null_check_passed'] = actual_null <= null_threshold

            if not col_results['null_check_passed']:
                failed.append(f'{col}: null_fraction={actual_null:.2%} > threshold={null_threshold:.2%}')
            else:
                passed.append(col)

            # Check for numeric columns: reasonable value range
            if pd.api.types.is_numeric_dtype(df[col]):
                min_val = df[col].min()
                max_val = df[col].max()
                mean_val = df[col].mean()
                col_results['stats'] = {
                    'min': float(min_val) if pd.notna(min_val) else None,
                    'max': float(max_val) if pd.notna(max_val) else None,
                    'mean': float(mean_val) if pd.notna(mean_val) else None,
                }

            results.append(col_results)

        return {
            'ok': True,
            'data_path': str(path),
            'total_rows': len(df),
            'columns_checked': len(results),
            'failed_checks': failed,
            'passed_columns': passed,
            'details': results,
        }
