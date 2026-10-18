"""
Phase 1 - Drift injection: Produces drifted 'this week's data' that the drift report flags.
"""
import argparse
import numpy as np
import pandas as pd
from pathlib import Path

DATA_DIR = Path(__file__).parent / 'data'


def inject_drift(
    n_samples: int = 1000,
    seed: int = 123,
    amount_scale: float = 350.0,
    null_frac: float = 0.10,
    credit_shift: float = -100.0,
) -> pd.DataFrame:
    """
    Generate a drifted dataset:
    - amount mean shifts from ~100 to ~350
    - distance_from_home gets null_frac nulls
    - credit_score mean drops by credit_shift
    """
    rng = np.random.RandomState(seed)
    amount = rng.exponential(scale=amount_scale, size=n_samples)
    n_transactions_day = rng.poisson(lam=7, size=n_samples)  # also shifted up
    account_age_days = rng.randint(1, 3650, size=n_samples)
    hour_of_day = rng.randint(0, 24, size=n_samples)
    distance_from_home = rng.exponential(scale=20, size=n_samples).astype(float)
    credit_score = rng.normal(loc=650 + credit_shift, scale=150, size=n_samples).clip(300, 850)

    null_mask = rng.random(n_samples) < null_frac
    distance_from_home[null_mask] = np.nan

    return pd.DataFrame({
        'amount': amount,
        'n_transactions_day': n_transactions_day,
        'account_age_days': account_age_days,
        'hour_of_day': hour_of_day,
        'distance_from_home': distance_from_home,
        'credit_score': credit_score,
    })


def main():
    parser = argparse.ArgumentParser(description='Inject drift into demo data')
    parser.add_argument('--n', type=int, default=1000, help='Number of samples')
    parser.add_argument('--seed', type=int, default=123)
    parser.add_argument('--amount-scale', type=float, default=350.0)
    parser.add_argument('--null-frac', type=float, default=0.10)
    parser.add_argument('--credit-shift', type=float, default=-100.0)
    parser.add_argument('--output', type=str, default=None)
    args = parser.parse_args()

    DATA_DIR.mkdir(exist_ok=True)
    df = inject_drift(
        n_samples=args.n,
        seed=args.seed,
        amount_scale=args.amount_scale,
        null_frac=args.null_frac,
        credit_shift=args.credit_shift,
    )
    out = args.output or str(DATA_DIR / 'current.csv')
    df.to_csv(out, index=False)
    null_pct = df.distance_from_home.isna().mean()
    print(f'Drifted dataset written to {out}')
    print(f'  Rows: {len(df)}')
    print(f'  amount mean: {df.amount.mean():.1f} (expected ~{args.amount_scale})')
    print(f'  credit_score mean: {df.credit_score.mean():.1f}')
    print(f'  distance_from_home nulls: {null_pct:.1%}')
    print('  -> Run drift_report tool to see the drift test flag these features.')


if __name__ == '__main__':
    main()
