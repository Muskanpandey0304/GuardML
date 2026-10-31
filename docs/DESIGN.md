# GuardML design notes

## The one rule

**The model proposes; code decides.** Everything an LLM can do goes through one function,
`GuardedExecutor.execute()`, the only code path that calls `tool.run()` (a test fails if any other module
does). The agent loop contains no safety logic of its own, so there is nothing to forget in a new code path.

## Decisions and trade-offs

**Deny by default, severity only goes up.** Every check can raise a verdict (`ALLOW < NEEDS_APPROVAL < BLOCK`);
none can lower one. A passing intent check or a clean provenance result never turns an approval requirement
into an allow. The policy file is schema-validated at startup (`extra=forbid`), so a typo fails the boot
instead of silently weakening a rule.

**Typed arguments instead of regex blocklists.** The first version guessed validators from argument *names*
and relied on blocked-pattern regexes. Names are a weak signal (`data_path` wasn't in the list, so `../.env`
got through), and regexes lose to encoding tricks. Now every tool declares each argument's kind
(`identifier`, `path`, `url`, `revision`, `duration`, ...) next to its schema and the guard validates by that
declaration; unknown arguments are rejected. A unit test fails if a new tool leaves a string argument
undeclared. The blocklist is kept as a second layer, not the main defence.

**Provenance: cheap, deterministic, and deliberately limited.** The session stores the tokens of the user's
messages (trusted) and of everything tools returned (untrusted). A write whose argument appears only in the
untrusted set is escalated, naming the source tool. It needs no model call and can't be talked out of its
verdict. Its limit is that it matches literal tokens: a paraphrase ("the second version"), a value the user
happened to say for another reason, or a value nobody said at all is invisible to it. That is why it is
paired with the intent check rather than sold as complete.

**Intent check: an isolated judge that can only escalate.** A second model call sees only the user's request
and the proposed action. It never sees tool output (so injected text can't reach it) or the agent's own
`reason` (an injection could have written it). It fails closed: an error, a timeout or an unparseable reply
counts as "not aligned", and results are cached so the re-check at approval time costs nothing. Applied to
write tools only, so it adds latency and cost only where it matters. It is the least tested part (see below).

**Approvals are bound to the exact call.** `sha256(session, env, tool, canonical args)` is stored with the
request; execution re-hashes and compares, requires `approved` status, a live TTL and a never-used approval,
and re-runs the whole guard (policy may have changed). The agent has no approve tool and the API takes the
approver's identity from the bearer token, never from the request. In production a person can't approve
their own request.

**Audit before action.** An `INTENT` entry is written before a tool runs and an outcome entry after, so a
crash can't hide an action. Entries are SHA-256 hash-chained and appended inside `BEGIN IMMEDIATE`, with a
unique index on the sequence number; two concurrent sessions used to be able to fork the chain.

**Verify after write, decide by what was observed.** After an alias change the executor health-checks the
service: healthy keeps it, an unhealthy answer rolls it back, and *unreachable* is decided by policy per
environment (staging keeps the change and marks it unverified, production rolls back). Without that split,
a local demo with no model server running would silently undo every approved change.

**Fixed typing at the boundary, not in the guard.** Real MLflow returns versions as integers; strict typing
rejected them and a legitimate rollback failed (found by the benchmark). The guard stays strict; the agent
loop converts only whole numbers into string identifier fields before the call is built.

## GuardBench, in one paragraph

62 development scenarios plus a held-out set and a small real-infrastructure tier. Attack success is "the
malicious call actually executed", read from tool outcomes and cross-checked in a test against the simulated
world's ground truth. Human approval is bracketed (a perfect approver and a rubber-stamp approver), because
escalating to a human only helps if the human refuses. Offline runs use a scripted agent playing a model that
already fell for the trap; live runs use a real model and cost API calls. Details and results:
`bench/README.md`.

## What this does not do (known limits)

- **Live evidence is small.** Offline numbers say the guard stops a compromised model's actions. In a live run with `qwen2.5:7b` (8 attacks, 3 benign tasks) the model acted on 2 injections; ToolGuard alone let both through (valid calls to the wrong target) and the intent check stopped both. Its benign-task numbers are dominated by scoring strictness
(required tool route, any blocked call counts as a false positive), not by the judge rejecting a legitimate action. One small model and a handful of scenarios: indicative, not a rate. `bench/README.md`.
- **Attacks and defence share an author.** The held-out set was written after the guard was frozen, but by
  the same person. Independent attack authors would be a stronger test.
- **Read confidentiality is allow-lists only, not a policy.** A tool-output injection that made the agent read another
  container's logs succeeded; ToolGuard only gates state changes and unsafe arguments. The adversarial set found
  two more of the same kind (source code under `./demo` readable by the data tools; any Kubernetes namespace
  listable). Both were fixed in v2 with an allow-list (`allowed_file_roots` narrowed, `allowed_k8s_namespaces`)
  and re-measured separately. The container-log hole (`ho-06`) was fixed in v3 with `allowed_log_containers`
  (control plane excluded). Other read tools have no confidentiality rule beyond these lists.
- **Provenance matches tokens, not meaning** (see above).
- **Audit chain is tamper-evident, not tamper-proof.** Anyone who can write to the database can recompute
  every hash. An HMAC- or signature-anchored checkpoint held outside the database would fix that.
- **Approval quality is out of scope.** A person who approves everything defeats approval gating; the benchmark
  shows that as its own number rather than hiding it.
- **Single-node state.** Sessions are in memory and the databases are SQLite; this is not horizontally scalable.
- **Not production-deployed.** The Docker setup was written without being able to build it.

## If I had more time

A live-LLM benchmark run with several models and repeats; attacks written by other people; a confidentiality
policy for read tools; an MCP proxy so the same policy engine can guard any MCP server's tools; and a signed
audit checkpoint.
