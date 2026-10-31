# Running the live benchmark on a free cloud GPU (Kaggle)

A bigger model than a 4 GB laptop GPU can hold, e.g. `qwen2.5:14b` (about 9 GB), runs on a Kaggle T4 (16 GB).
The benchmark runs **inside** the notebook, so nothing is exposed and no tunnel is needed.
`bench/cloud.py` does the setup (Python packages, Ollama, model download), the run, the resume and the zip.

> The Kaggle steps follow Kaggle's and Ollama's documented behaviour but were not run on Kaggle. The runner itself
> was run on a laptop with a local model. Check each cell the first time.

## Steps

1. New notebook. Settings: **Accelerator = GPU T4**, **Internet = On** (Kaggle may ask you to verify a phone number).
2. Cell 1, get the code (the folder must be called `guardml`):
   ```
   !git clone https://github.com/Muskanpandey0304/GuardML.git /kaggle/working/guardml
   ```
   No GitHub? Upload a zip of the repo as a Kaggle dataset, add it to the notebook, and
   `!cp -r /kaggle/input/<dataset>/* /kaggle/working/guardml/` instead.
3. Cell 2, a quick check first (3 scenarios):
   ```
   !cd /kaggle/working && python -m guardml.bench.cloud --smoke
   ```
4. Cell 3, the full run:
   ```
   !cd /kaggle/working && python -m guardml.bench.cloud
   ```
5. Download `/kaggle/working/results/live-ollama-qwen2.5-14b-results.zip` (file browser on the right, three dots,
   Download) and unzip it into `bench/results/` in the repo.

Options: `--model qwen2.5:7b`, `--split holdout`, `--configs c_toolguard`, `--repeat 3`, `--limit 5`.

## If the session dies

Run the **same command again**. If the checkpoint `results/<tag>.partial.jsonl` is still there, it continues and
skips finished runs. Kaggle wipes `/kaggle/working` when an interactive session ends, so **download the
`.partial.jsonl` every so often** and put it back in `/kaggle/working/results/` in the new session. Alternatives
that keep it for you: "Save Version" (commit) runs, Google Colab with Drive mounted (use `--out` on a Drive folder),
or a Google Cloud VM, whose disk survives a restart.

## Rough expectations

Guess: a 14B model on a T4 is several times faster than the laptop (about 30 to 60 minutes for the 44-run `live`
split, against about 2.5 hours for the 7B on the laptop). The `--smoke` run tells you the real speed.
