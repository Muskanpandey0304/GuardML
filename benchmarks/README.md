# Benchmarks

| Folder | What it is | Attacks written by |
|---|---|---|
| [`../bench/`](../bench) | **GuardBench**: GuardML's own benchmark (MLflow / Docker / DVC scenarios), offline and live | the guard's author |
| [`agentdojo/`](agentdojo) | **AgentDojo** (ETH Zurich, NeurIPS 2024): an external prompt-injection benchmark, used here as independent safety evidence | the AgentDojo authors |

GuardBench is the only suite aimed at MLOps tools. AgentDojo is the independent check: its attacks and tasks
were not written by us. Neither covers everything; read each folder's README for what it does and does not show.
