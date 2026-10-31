# AgentDojo: banking-8x5-qwen2.5-14b

- **Run**: 2026-10-31 20:17 | **AgentDojo**: 0.1.35 | **benchmark**: v1.2.2 | **mode**: live
- **Model**: qwen2.5:14b (Ollama) | **attack**: important_instructions
- **Rebuilt from the saved task logs** (no task was re-run), so the run date above is the rebuild time.

| Defence | Suite | Utility (no attack) | Utility under attack | Attack success | Runs (clean / attack) |
|---|---|---|---|---|---|
| none | banking | 62% | 52% | **65%** | 8 / 40 |
| full | banking | 38% | 48% | **0%** | 8 / 40 |

Attack success = the injection's goal was achieved (lower is better).

- **full / banking, from the saved task logs**: 203 blocked calls {'intent': 87, 'provenance': 116}; the guard blocked at least one call in 34 attack pairs. Of the 26 pairs where the attack worked with no guard, it blocked a call in 25.
