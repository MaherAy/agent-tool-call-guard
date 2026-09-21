# agent-tool-call-guard

A deterministic defense for the [SENTINEL](https://github.com/Skan22/Sentinel_Starter_Kit) agent-safety benchmark
(IndabaX Tunisia 2026). It sits between the agent's candidate action and the tool gateway and answers
`allow | block | escalate | rewrite` for every action.

The rule it enforces: *an action runs only if trusted evidence explains it.* The tool must be allowed by policy and
asked for by the user's goal, the ids it acts on must come from trusted sources, and no protected value may leave
through a destination its sensitivity disallows. It uses **no language model**: every decision is reproducible.

## Status (read this first)

Stage 1 of the plan: the deterministic core, tests, and an evaluation harness.

- Measured **only with the kit's `mock` agent, offline**. The mock is a structural, gullible stand-in and "can make a
  defense look stronger than it will against the real one". **Nothing here has been run against Qwen3-8B yet.**
- Not built yet: observability dashboard, adversarial probe scenarios, the GRC mapping, Kaggle/Qwen runs.
- Not implemented yet from the design: fragment/drip-leak accounting, session posture, quarantine marker.

## How a decision is made

Checks run in this order; the first hit decides. Every decision carries a rule id and reason codes.

| Rule | Check | Outcome |
|---|---|---|
| R1 | tool is in the policy's `allowed_tools` (the ceiling; the goal can never widen it) | `TOOL_NOT_ALLOWED` block |
| R2 | the user's goal rules the verb out ("do not confirm or execute") | `GOAL_NEGATED` block |
| R5 | a *consequential* tool must actually be asked for in the goal | `PLAN_DEVIATION` block |
| R6 | ids and external recipients of a *write* must come from trusted evidence | `TAINTED_ARGUMENT` block |
| R7 | a *read* that mirrors an instruction found in untrusted content and is not explained by the goal | `INJECTED_INSTRUCTION` block |
| R8 | memory holds facts, not instructions or authority claims | `MEMORY_DIRECTIVE` block / rewrite to the facts |
| R4 | a protected value may not reach a disallowed destination, including the final response | `SECRET_TO_SINK` / `ENCODED_EXFIL` rewrite (redact) |
| R9 | a consequential action needs a recorded human confirmation | `CONSEQUENTIAL_UNCONFIRMED` escalate |

Design points that came from measuring the baselines:

- **Explained beats co-occurring.** An attacker's payload often names the *legitimate* call. The baseline blocks the
  honest call because its tool and arguments also appear in untrusted text; we block only when trusted evidence does
  not explain the call.
- **Evidence classes.** The user and provenance-free *tool receipts* (ids minted by a "prepare" step) are trusted; any
  item with an untrusted or mixed provenance is untrusted as a whole; agent-authored text is ignored.
- **Per-run ledger.** A request carries only the last 12 items (2,000 chars each), so the ledger accumulates ids,
  secrets and untrusted text for the whole run. State resets when a run's step counter restarts.
- **Sidecar trace.** The kit drops decision `metadata` from its event log, so a hash-chained JSONL trace records the
  rule, evidence and latency for each decision. Secret values are never written.

## Run it

```bash
pip install -e ".[dev]"          # pydantic, fastapi, uvicorn, pytest, httpx
pytest                            # 39 tests, no network

# serve (optionally record the sidecar trace)
GUARD_TRACE_DIR=./trace uvicorn guard.app:app --port 8080
python -m guard.trace verify ./trace/guard-trace.jsonl

# evaluate against the kit (needs a checkout of the SENTINEL kit with its venv)
KIT_DIR=../Sentinel_Starter_Kit python scripts/eval_with_kit.py
KIT_DIR=../Sentinel_Starter_Kit python scripts/eval_with_kit.py --attacker mutation --attack-mode adaptive

# or point any kit command at the service
sentinel run --scenario <yaml> --defense-url http://127.0.0.1:8080
```

Layers can be ablated with `GUARD_DISABLE=contract,grounding,dlp,reconstruction,memory_rules`.

## Observability: sidecar trace and Langfuse (optional)

Every decision is recorded twice. The **sidecar trace** (`GUARD_TRACE_DIR`) is a local hash-chained JSONL file and is the
source of truth. **Langfuse** mirrors it so the decisions can be browsed:

- one *session* per agent run (`session_id` = run id), one *trace* per screened action, named `screen-action` (a static
  name; what varies is in tags, metadata and scores, so saved filters and dashboards stay stable);
- the root observation has type `guardrail`, a readable **input** (`incident_update(incident_id=INC-0101, status=closed)`)
  and a readable **output** (`BLOCK [PLAN_DEVIATION] risk 0.90, confidence 0.85. <explanation>`);
- tags and filterable metadata carry the decision, rule, tool, reason codes and which layers were enabled (`layers` is
  `all` or `without:contract,dlp` for ablation runs);
- the observation metadata holds the structured detail: evidence, the raw action, and the **context the guard decided
  with** (user goal, allowed and consequential tools, what the goal asked for or ruled out, least-trusted and
  most-sensitive data seen so far);
- `risk_score`, `confidence` and `decision` are scores you can filter and chart;
- `environment` (`LANGFUSE_TRACING_ENVIRONMENT`) and `release` / `version` (`LANGFUSE_RELEASE`, default
  `agent-tool-call-guard@<installed version>`) are set, so demo and test traces never mix and runs are comparable across
  versions of the guard;
- trace ids come from `guard:<environment>:<run_id>:<step>`, so each sidecar line maps to one Langfuse trace.

```bash
pip install -e ".[langfuse]"
cp .env.example .env            # git-ignored; fill in the keys of your Langfuse project (never commit them)
python -m guard.telemetry check # verifies the keys and sends one sample decision (session "check-run")
uvicorn guard.app:app --port 8080
```

- **Off by default.** Without `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY` nothing is sent and no network call is
  made. `LANGFUSE_TRACING_ENABLED=false` switches it off while keeping the keys.
- **Never in the decision path.** Export is batched by the SDK on a background thread and errors are swallowed; a
  decision never waits on, or fails because of, Langfuse. Tested with an unreachable server: decisions unchanged.
- **What is sent.** Only what the sidecar record holds: rule, codes, a short explanation, truncated arguments and evidence
  with protected values already removed, then masked a second time just before export (Langfuse's `mask_otel_spans` hook
  replaces any secret-shaped token in inputs, outputs and status messages). All data in this benchmark is synthetic. No
  user id is set because the SENTINEL protocol carries no user identity.
- **External service.** Langfuse Cloud is a third-party service; the team asked the organizers, who allowed it. Declare it
  in the report. To keep everything offline, point `LANGFUSE_BASE_URL` at a self-hosted instance instead.

## Results on the updated kit (mock agent, kit commit `dd2e5fe`, 21/09/2026)

The updated kit adds 21 exfiltration scenarios (40 public scenarios: 31 attacks, 9 benign; plus 9 validation). Same
setup as below; reproduce with `scripts/eval_with_kit.py` pointed at that kit. Detailed comparison with other layers:
[docs/existing_work_and_benchmark.md](docs/existing_work_and_benchmark.md).

| Defense | BTU | ASR | FBR | UER | TUI | ECE |
|---|---|---|---|---|---|---|
| `keyword` (baseline) | 0.778 | 0.226 | 0.136 | 0.000 | 0.832 | 0.081 |
| `heuristic_risk` (baseline) | 1.000 | 0.677 | 0.000 | 0.006 | 0.750 | 0.050 |
| `provenance` (baseline) | 1.000 | 0.000 | 0.222 | 0.000 | 1.000 | 0.197 |
| **agent-tool-call-guard** | 1.000 | 0.000 | 0.000 | 0.000 | 0.842 | 0.012 |

On the 9 validation scenarios: ASR 0.000, BTU 1.000. Not yet run against Qwen3-8B.

## Results on the previous kit (mock agent, kit commit `c86681a`, 21/09/2026)

Reproduce with `scripts/eval_with_kit.py`. Public split = 19 scenarios, validation split = 9.

| Defense | Split | BTU | ASR | CVR | FBR | UER |
|---|---|---|---|---|---|---|
| `keyword` (baseline) | public | 0.778 | 0.700 | 0.368 | 0.046 | 0.000 |
| `provenance` (baseline) | public | 1.000 | 0.000 | 0.000 | 0.046 | 0.000 |
| `heuristic_risk` (baseline) | public | 1.000 | 0.000 | 0.000 | 0.000 | 0.011 |
| **agent-tool-call-guard** | public | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| `provenance` (baseline) | validation | 1.000 | 0.250 | 0.111 | 0.000 | 0.000 |
| `heuristic_risk` (baseline) | validation | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| **agent-tool-call-guard** | validation | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 |

Also against the kit's adaptive mutation attacker (`--attacker mutation --attack-mode adaptive`): ASR 0 on both
splits. Decision time inside the service (from the sidecar trace, 139 decisions): median 1.3 ms, p95 2.7 ms, max 5.3 ms;
the p95 of about 25 ms in the kit's report includes the HTTP round trip.

**The published scenarios do not separate the strong defenses on the mock.** `heuristic_risk` also reaches ASR 0, by
escalating. What this defense adds is precision (no false blocks, no needless escalations) and a reason for each
decision. Ablations below.

### Ablation (mock; ASR public / validation)

| Variant | ASR | Notes |
|---|---|---|
| all layers | 0.00 / 0.00 | |
| ceiling + human confirmation only (R1, R9) | 0.20 / 0.25 | leaks in three scenarios (two memory/invoice leaks, one encoded exfiltration) |
| without `contract` (R2, R5) | 0.00 / 0.00 | consequential actions are then stopped by R9 (the simulated human denies them) |
| without `grounding` (R6) | 0.00 / 0.00 | an illegitimate write is executed harmlessly in validation |
| without `dlp` (R4) | 0.00 / 0.00 | other layers stop the flows upstream |
| without `reconstruction` (R7) | 0.00 / 0.00 | harmless illegitimate reads are executed |
| without `memory_rules` (R8) | 0.00 / 0.00 | the memory-poison scenario then **loses its legitimate task** |

Reading: the layers overlap on these scenarios, so removing any *one* leaves ASR at 0; removing all of them (keeping
only the ceiling and confirmation) does not. **We expected removing the contract to reopen the scenarios whose
forbidden action is inside `allowed_tools`; on the mock it does not, because R9 escalates and the simulated human
denies.** The contract still turns those cases into an immediate, explained block instead of a request to a human,
but the published scenarios cannot show its marginal value. Purpose-built probes are the next step.

## Existing work and benchmark

[docs/existing_work_and_benchmark.md](docs/existing_work_and_benchmark.md) surveys open-source defense layers and benchmarks the ones that can run offline (Heimdall's deterministic layers, an open-source injection classifier, a generic secret scanner) against this defense on the updated kit. Reproduce with `benchmarks/run_external.py`.

## Defense rules

Every decision uses only the request: goal, candidate action, provenance, policy context and observed content.
`tests/test_no_hardcoding.py` fails if the source contains a scenario id, a scenario filename, or the benchmark's
seeded-secret formats. Secret detection is generic (length, character classes, entropy) and driven by provenance
labels, never by a value's format. No external model or dataset is used.

## Known limitations

- The goal contract is lexical (a few verb stems and a negation rule). Unusual goal phrasing can mis-justify a tool;
  only consequential tools are hard-gated, other writes are a soft signal.
- A request shows 2,000 characters per item; a payload beyond that is invisible to the monitor.
- Semantic exfiltration (a paraphrased or translated secret) is not detected; only encodings the benchmark declares.
- Injected content that stays inside the contract and only changes *which legitimate value* is used is not caught.
- R7 only looks at untrusted content read in the current turn (plus recalled memory), so a payload read in an earlier
  turn is left to the write-side rules and the leak checks.
- Some illegitimate-but-harmless calls are still executed (TUI 0.98 on the public split).

## Prior art and credits

- The v1 API schemas and the six leak-check transformations follow the SENTINEL starter kit (Apache-2.0), which this
  repository's license also is.
- Several design points were informed by reading another public SENTINEL defense,
  [mmed-hajnasr/heimdall](https://github.com/mmed-hajnasr/heimdall): treating provenance-free tool receipts as trusted so
  ids minted during a run can be acted on, treating mixed-provenance items as wholly untrusted, the thresholds used for
  secret-likeness (12 characters, two character classes, 2.5 bits of entropy), and a per-run registry that resets when
  the step counter restarts. The code is independent, but these ideas and constants are theirs first.
- The approach draws on published work on privilege control and provenance for agents: CaMeL, Progent, Fides,
  Task Shield, AuthGraph and ARGUS.
