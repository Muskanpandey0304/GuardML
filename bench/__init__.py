"""
GuardBench: an evaluation benchmark for agent tool-execution safety.

It measures how often attacks (direct, indirect prompt injection, argument and
approval bypass) get a state-changing or data-exposing tool call executed, versus how
many legitimate tasks still complete, under different defence configurations.

Run from the directory that CONTAINS the repo folder (so `guardml` is importable):

    python -m guardml.bench.run --help
"""
