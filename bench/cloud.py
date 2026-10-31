"""
One command for the live benchmark on a machine with a GPU (Kaggle, Colab, a cloud VM, or your own PC).

    python -m guardml.bench.cloud                       # qwen2.5:14b, the `live` split, ToolGuard + intent check
    python -m guardml.bench.cloud --smoke               # 3 scenarios first: a quick check that everything works
    python -m guardml.bench.cloud --model qwen2.5:7b

Run it from the directory that CONTAINS the repo folder (the folder must be named `guardml`).
It installs what is missing (Python packages, Ollama on Linux), starts Ollama, pulls the model, runs the benchmark
and zips the results. If the session dies, run the SAME command again: a checkpoint in the output folder is
picked up automatically and finished runs are skipped.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import List, Optional

OLLAMA_URL = 'http://localhost:11434'
REPO_ROOT = Path(__file__).resolve().parent.parent
PY_MODULES = ['mlflow', 'yaml', 'requests', 'dotenv', 'pandas', 'numpy', 'sklearn', 'scipy', 'psutil', 'pydantic']


def default_out() -> Path:
    kaggle = Path('/kaggle/working')
    return kaggle / 'results' if kaggle.is_dir() else Path(__file__).parent / 'results'


def default_tag(model: str, smoke: bool = False) -> str:
    tag = 'live-ollama-' + re.sub(r'[^A-Za-z0-9.]+', '-', model).strip('-')
    return tag + '-smoke' if smoke else tag


def build_args(ns: argparse.Namespace, out: Path, tag: str, resume: bool) -> List[str]:
    args = ['--mode', 'live', '--split', ns.split, '--configs', ns.configs, '--yes',
            '--out', str(out), '--tag', tag, '--repeat', str(ns.repeat)]
    limit = 3 if ns.smoke else ns.limit
    if limit:
        args += ['--limit', str(limit)]
    if resume:
        args.append('--resume')
    return args


def ensure_python_deps() -> None:
    missing = [m for m in PY_MODULES if importlib.util.find_spec(m) is None]
    if missing:
        print(f'[setup] installing Python packages (missing: {", ".join(missing)}) ...', flush=True)
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-q', '-r', str(REPO_ROOT / 'requirements.txt')],
                       check=True)


def _tags() -> Optional[List[str]]:
    try:
        with urllib.request.urlopen(f'{OLLAMA_URL}/api/tags', timeout=2) as r:
            return [m['name'] for m in json.loads(r.read()).get('models', [])]
    except Exception:
        return None


def ensure_ollama(model: str) -> None:
    if _tags() is None:
        if not shutil.which('ollama'):
            if not sys.platform.startswith('linux'):
                raise SystemExit('Ollama is not installed. Install it from https://ollama.com and run this again.')
            print('[setup] installing Ollama ...', flush=True)
            subprocess.run('apt-get install -y zstd > /dev/null 2>&1 || true', shell=True)
            subprocess.run('curl -fsSL https://ollama.com/install.sh | sh', shell=True, check=True)
        print('[setup] starting Ollama ...', flush=True)
        subprocess.Popen(['ollama', 'serve'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            if _tags() is not None:
                break
            time.sleep(1)
        else:
            raise SystemExit('Ollama did not start within 60 s.')
    have = _tags() or []
    if model not in have and f'{model}:latest' not in have:
        print(f'[setup] pulling {model} (a few GB, first time only) ...', flush=True)
        subprocess.run(['ollama', 'pull', model], check=True)


def zip_results(out: Path, tag: str) -> Optional[Path]:
    files = [out / f'{tag}.md', out / f'{tag}.json']
    files = [f for f in files if f.exists()]
    if not files:
        return None
    path = out / f'{tag}-results.zip'
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for f in files:
            z.write(f, f.name)
    return path


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description='One-command live GuardBench on a GPU machine',
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument('--model', default='qwen2.5:14b', help='Ollama model (default qwen2.5:14b)')
    ap.add_argument('--split', default='live', choices=['dev', 'holdout', 'live', 'adversarial', 'all'])
    ap.add_argument('--configs', default='c_toolguard,e_full')
    ap.add_argument('--repeat', type=int, default=1)
    ap.add_argument('--limit', type=int, default=0, help='first N scenarios only')
    ap.add_argument('--smoke', action='store_true', help='3 scenarios only, under its own tag')
    ap.add_argument('--out', default=None, help='output folder (default /kaggle/working/results on Kaggle)')
    ap.add_argument('--tag', default=None)
    ns = ap.parse_args(argv)

    out = Path(ns.out) if ns.out else default_out()
    out.mkdir(parents=True, exist_ok=True)
    tag = ns.tag or default_tag(ns.model, ns.smoke)

    ensure_python_deps()
    ensure_ollama(ns.model)

    os.environ['GUARDML_LLM_PROVIDER'] = 'ollama'
    os.environ['OLLAMA_MODEL'] = ns.model
    resume = (out / f'{tag}.partial.jsonl').exists()
    print(f'[run] {ns.model}  split={ns.split}  configs={ns.configs}  out={out}'
          + ('  (continuing from the checkpoint)' if resume else ''), flush=True)

    from .run import main as bench_main  # imported late: needs the packages installed above
    rc = bench_main(build_args(ns, out, tag, resume))

    zipped = zip_results(out, tag)
    if zipped:
        print(f'\n[done] results: {zipped}')
    if rc != 0:
        print('[note] the run did not finish cleanly. Run the same command again to continue.')
    return rc


if __name__ == '__main__':
    sys.exit(main())
