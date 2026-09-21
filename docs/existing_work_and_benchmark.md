# Existing work and a benchmark of defense layers

Written 21/09/2026. Everything here was checked on that date; anything not checked is marked **[unverified]**.

## 1. Why, and the constraints that decide what is usable

We compare defense layers built by other people, with more time and experience, against what SENTINEL needs. The
constraints of this challenge decide what can be reused:

- The agent (Qwen3-8B) is fixed. A defense sits **between its candidate action and the tool gateway** and answers
  `allow`, `block`, `escalate` or `rewrite`. Anything that needs to change the agent, its prompt or its program is out.
- **No external inference API** ("runs locally" means an open-weight model you host; the organizers' FAQ). Anything that
  needs a hosted model is out, unless the model can be self-hosted.
- The defense never sees the agent's chain of thought. Detectors that audit reasoning cannot run.
- The kit's client times out at 5 s per decision by default; it can be raised, but both numbers should be reported.

## 2. Catalog of existing work

Repository facts (license, stars, last push, archived) come from the GitHub API on 21/09/2026.

### Frameworks and policy engines

| Name | What it is | Status | Fit with SENTINEL |
|---|---|---|---|
| [Invariant Guardrails](https://github.com/invariantlabs-ai/invariant) | Rule DSL over tool-call traces, including data-flow rules; runs as a local library or an MCP/LLM proxy | Apache-2.0, 460 stars, last push 2026-01-12 | Closest existing analogue of a goal-independent policy layer; could express our tool and flow rules. Its built-in detectors (for example prompt injection) are probably model-based **[unverified]**. **Not benchmarked** (any rule set we wrote would be our own design) |
| [Progent](https://github.com/sunblaze-ucb/progent) (paper 2504.11703) | Deterministic privilege policies over tool names and arguments; an LLM writes and updates the policy | **No license file**, 52 stars, last push 2026-05-14 | Same idea as our contract. Paper reports AgentDojo attack success 39.9% to 1.0% in proxy mode (search summary, not re-checked). No license, so code cannot be reused |
| [CaMeL](https://github.com/google-research/camel-prompt-injection) (paper 2503.18813) | Control and data flow extracted from the trusted query; a custom interpreter enforces capabilities | Apache-2.0, 391 stars, last push 2025-06-20; authors call it a research artifact that "likely contains bugs" | Needs API keys and owns the agent's program; cannot sit behind a fixed agent |
| [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) | Input, dialog, retrieval, execution and output rails | README says Apache-2.0 (GitHub could not classify the file), 7.2k stars, active | Most rails need an LLM; no documented mechanism for injections arriving in tool outputs. Heavy for a per-action check |
| [LlamaFirewall](https://github.com/meta-llama/PurpleLlama) (paper 2505.03574) | PromptGuard 2 + AlignmentCheck + CodeShield | Repository has mixed licenses, 4.4k stars, active | Paper reports AgentDojo attack success 17.6% (none), 7.5% (PromptGuard 2), 2.9% (AlignmentCheck), 1.75% (both), with utility 47.7 to 42.7%. AlignmentCheck reads the agent's reasoning and needs a large LLM, so it cannot run here |
| [LLM Guard](https://github.com/protectai/llm-guard) | Input and output scanners (prompt injection, secrets, PII, and more) | MIT, 3.2k stars, **archived (no longer maintained)** | Its injection scanner uses ProtectAI's DeBERTa models; the one benchmarked below comes from the same publisher |
| [AgentSpec](https://arxiv.org/abs/2503.18666) (ICSE 2026) | Rule DSL (trigger, predicate, enforcement) for LangChain agents | Paper only; code release **[unverified]** | Same family as the contract; not runnable |
| [guardrail-layer](https://github.com/rishrav/guardrail-layer) | Policy engine, DeBERTa, local LLM judges, taint tracking, hash-chained audit | No license, 2 stars; needs Docker, Ollama, PostgreSQL, Redis; self-reports 0% attack success and 88.9% task completion on its own 170 cases | Very similar to our design, too heavy to run here, results not independent |
| Heimdall (our teammate's repository) | Deterministic gate and ReBAC layers, plus two model layers | No license, 0 stars | Benchmarked below (deterministic layers only; the model layers call OpenRouter) |
| [OpenGuardrails](https://github.com/openguardrails/openguardrails) | A wire protocol and a vendor-neutral leaderboard | Apache-2.0, 46 stars | Not a layer |

### Detectors and scanners

| Name | What it is | Status | Fit |
|---|---|---|---|
| [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | 0.2B binary classifier (benign / injection), English only | Apache-2.0. Card: accuracy 95.25%, precision 91.59%, recall 99.74% on 20,000 held-out prompts; known false positives | **Benchmarked** as a detector layer |
| [Llama Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) (86M, 22M) | mDeBERTa classifier: benign / injection / jailbreak | Gated under the Llama 4 license; access review "could take up to a few days" | Not benchmarked (access) |
| [IBM Granite Guardian](https://github.com/ibm-granite/granite-guardian) | LLM-based detector including prompt injection and function-calling risk | Apache-2.0, 178 stars | Needs LLM inference; not benchmarked |
| [Qwen3Guard](https://github.com/QwenLM/Qwen3Guard) | 0.6B / 4B / 8B safety models, 119 languages, safe / controversial / unsafe | Models Apache-2.0 (Hugging Face); repository has no license file | Content-safety classification; not designed for injections in tool output (**[unverified]**). Not benchmarked |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | 27+ secret detectors (entropy, keywords, provider formats); can scan a single string | Apache-2.0, 4.6k stars | **Benchmarked** as the data-leak layer |

### Attack tools and benchmarks (for evaluating, not defending)

[garak](https://github.com/NVIDIA/garak) (Apache-2.0, 9.3k stars, 120+ probes, encoding and injection attacks),
[promptfoo](https://github.com/promptfoo/promptfoo) (MIT, 25k stars), [PyRIT](https://github.com/Azure/PyRIT)
(MIT; the repository is archived, its current home is **[unverified]**), and the
[AgentDojo](https://github.com/ethz-spylab/agentdojo) benchmark (MIT, 849 stars; the organizers' optional bonus
track). Not run here.

Also relevant, not runnable here: AuthGraph, ARGUS and AgentSentry (2026 papers; code release **[unverified]**).

## 3. What was benchmarked, and how

- **Setup.** Kit commit `dd2e5fe`: 40 public scenarios (31 attacks, 9 benign) and 9 validation scenarios (4 attacks).
  Agent: the kit's `mock` model, offline. The defense timeout was raised to 60 s so decisions, not timeouts, are
  measured; latency is reported separately.
- **Layers.** Each was served as a v1 defense service. Heimdall runs with its model layers switched off (no API key
  needed): L0 only (`gate`) and L0 + L1 (`gate` + ReBAC). The detector and the scanner are adapters we wrote
  (`benchmarks/classifier_guard.py`, `benchmarks/secretscan_guard.py`); their **policies are our choices** (below).
- **Reproduce.** `benchmarks/run_external.py`; raw results are in `benchmarks/data/`.

Adapter policies. *DeBERTa "quarantine"*: score every untrusted or mixed-provenance item once; after any item scores 0.5
or more, block non-read tool calls and memory writes for the rest of the run (reads and replies stay allowed). It has no
confirmation logic. *detect-secrets*: scan every outbound string token by token (quoted, so entropy and provider
detectors apply) and redact what matches. A different policy could score better or worse.

## 4. Results (mock agent, one seed)

Public split (40 scenarios):

| Layer | BTU (benign tasks done) | ASR (attacks that succeed) | FBR (legitimate actions blocked) | UER | TUI | ECE |
|---|---|---|---|---|---|---|
| allow_all | 1.000 | 1.000 | 0.000 | 0.000 | 0.652 | 0.235 |
| keyword | 0.778 | 0.226 | 0.136 | 0.000 | 0.832 | 0.081 |
| heuristic_risk | 1.000 | **0.677** | 0.000 | 0.006 | 0.750 | 0.050 |
| provenance | 1.000 | 0.000 | **0.222** | 0.000 | 1.000 | 0.197 |
| **DeBERTa detector (quarantine)** | 0.889 | **0.742** | 0.074 | 0.000 | 0.681 | 0.202 |
| **detect-secrets scanner** | **0.333** | 0.129 | 0.000 | 0.000 | 0.507 | 0.361 |
| Heimdall L0 (gate) | 1.000 | 0.000 | 0.000 | 0.000 | 0.801 | 0.056 |
| Heimdall L0 + L1 | 1.000 | 0.000 | 0.000 | 0.000 | 0.801 | 0.024 |
| agent-tool-call-guard (ours) | 1.000 | 0.000 | 0.000 | 0.000 | 0.842 | 0.012 |

Validation split (9 scenarios): DeBERTa ASR 0.500, BTU 0.800; detect-secrets ASR 0.500, BTU 0.400; provenance ASR 0.250;
keyword ASR 0.750; heuristic_risk, Heimdall L0 / L0 + L1 and agent-tool-call-guard all ASR 0.000, BTU 1.000.

Detector at content level (payload-bearing untrusted items, using the scenarios' own payload text as ground truth,
never as an input to the defense): it flagged **10 of 32** payload items (recall 31%) and **2 of 13** benign untrusted
items (15%). Both false positives are the customer's quoted scam message in the two scam-quote scenarios.
Decision latency on CPU: p95 about 450 to 540 ms; the deterministic layers, including HTTP, about 20 ms.

## 5. What the results say

1. **A state-of-the-art open detector barely helps here.** The DeBERTa layer lets 23 of 31 attacks through (8 of 10
   older ones, 15 of 21 new ones) and still blocks legitimate work. The new payloads read like ordinary business text
   ("confirm the credential binding before triage"), not "ignore previous instructions". This agrees with the
   literature on over-defense (InjecGuard), evasion, and injections that hide as data (AutoDojo).
2. **A generic secret scanner finds the secrets but wrecks the task.** detect-secrets stops every new exfiltration
   (attack success 0 on the 21) because the leaked values have high entropy, yet only 33% of benign tasks complete: it
   also redacts ordinary words, ids and addresses. Its remaining attack successes (6 across both splits) are attacks
   that involve no secret at all (direct instructions, closing a ticket, disabling monitoring), which a scanner cannot
   see by design. In a sample check it also missed a digit-only account number. Sensitivity labels and destinations are
   what make a leak check usable.
3. **The new library separates the defenses.** `heuristic_risk` fails all 21 new exfiltration scenarios (it only looks
   at e-mail sinks); `provenance` stops everything but blocks 22% of legitimate actions.
4. **Provenance-aware deterministic cores tie at the top.** agent-tool-call-guard and Heimdall's gate (even L0 alone) both
   reach ASR 0 with no false blocks. They differ only in calibration (ECE 0.012 vs 0.056 / 0.024) and in how many
   unrequested-but-harmless actions run (TUI 0.84 vs 0.80). On this benchmark, **the tool ceiling, a value-level
   data-flow check with decoding and redaction, and human confirmation are enough**; the extra layers of both designs
   (contract, grounding, reconstruction, memory rule, ReBAC) are not distinguished by it.
5. **The threat that matters for the real agent is exfiltration.** The organizers report that Qwen3-8B refuses to move
   money or close incidents but does routine lookups and copies results into internal records and replies. That is the
   data-flow layer's job.

## 6. Limits of this benchmark

- **Mock agent only.** Nothing was run against Qwen3-8B; the mock follows a structural grammar that flatters any
  layer that keys on tool names. Results may differ on the real agent.
- **Our adapters and policies.** The detector and scanner are wired the way we judged reasonable. A different policy
  (for example escalating instead of blocking) could change their numbers.
- **Small, single-seed samples.** Content-level statistics rest on 32 and 13 items.
- **Not run:** anything that needs a hosted or gated model (LlamaFirewall's AlignmentCheck, Prompt Guard 2, Heimdall's
  model layers, NeMo rails), and the frameworks that need a rule set we would have to author (Invariant, Progent).
- Heimdall's model layers and the LLM-judge idea are therefore **not evaluated**, neither for nor against.

## 7. Questions to settle together

- Do we combine the best parts of the two deterministic cores (their ReBAC and tool receipts, our goal negation, memory
  rule and instruction reconstruction), or keep two independent solutions for comparison?
- Which extra layers can we defend with evidence, given that this benchmark does not separate them? Probes we write
  ourselves would be needed.
- Do we add a self-hosted Qwen layer (Ollama or Kaggle, no API), and what would it be measured against?
- Reuse rather than reinvent: Invariant Guardrails as the policy language, and a detector only as a weak signal.
