"""Benchmark existing defense layers on the SENTINEL scenarios (mock agent, offline).

Each layer is served as a v1 defense service (or is one of the kit's built-in baselines) and evaluated with
`sentinel eval` on the public and validation splits. Run it with the kit's Python:

    KIT_DIR=<kit checkout> KIT_PY=<kit venv python> BENCH_PY=<benchmark venv python> HEIMDALL_DIR=<heimdall checkout> \
        python benchmarks/run_external.py [--only guard,heimdall_L0_L1] [--out DIR]

Layers: guard (this repository), heimdall_L0, heimdall_L0_L1 (deterministic layers only, no API key),
deberta_quarantine (open-source injection classifier), detect_secrets (generic secret scanner), and the kit baselines.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
METRICS = ["btu", "asr", "cvr", "fbr", "uer", "tui", "dfi", "brier", "ece", "latency_p95_ms"]
BASELINES = ["allow_all", "keyword", "heuristic_risk", "provenance"]
SPLITS = ("public", "validation")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_healthy(url: str, seconds: float) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/healthz", timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.5)
    raise RuntimeError(f"service at {url} did not become healthy in {seconds:.0f}s")


def services(out: Path, kit_py: str, bench_py: str, heimdall: Path) -> dict[str, tuple[str, Path, str, dict[str, str]]]:
    heimdall_off = {"HEIMDALL_ENABLE_JUDGE": "false", "HEIMDALL_ENABLE_READER": "false", "HEIMDALL_LLM_REQUIRED": "false"}
    return {
        "guard": (kit_py, REPO, "guard.app:app", {"PYTHONPATH": str(REPO)}),
        "heimdall_L0": (bench_py, heimdall, "app.main:app", {**heimdall_off, "HEIMDALL_ENABLE_AUTHZ": "false"}),
        "heimdall_L0_L1": (bench_py, heimdall, "app.main:app", heimdall_off),
        "deberta_quarantine": (bench_py, REPO, "benchmarks.classifier_guard:app",
                               {"PYTHONPATH": str(REPO), "CG_LOG_DIR": str(out / "deberta")}),
        "detect_secrets": (bench_py, REPO, "benchmarks.secretscan_guard:app", {"PYTHONPATH": str(REPO)}),
    }


def kit_eval(kit: Path, kit_py: str, target: list[str], split: str, out: Path, name: str, timeout_cfg: Path) -> dict:
    report = out / f"{name}-{split}.json"
    cmd = [kit_py, "-m", "sentinel.cli", "eval", split, *target, "--model", "mock", "--config", str(timeout_cfg),
           "--artifacts", str(out / f"art-{name}-{split}"), "--output", str(report), "--json"]
    env = {**os.environ, "PYTHONPATH": str(kit / "src"), "PYTHONUTF8": "1"}
    subprocess.run(cmd, cwd=kit, env=env, stdout=subprocess.DEVNULL, check=True)
    result = json.loads(report.read_text(encoding="utf-8"))
    outcomes = []
    for summary in sorted(glob.glob(str(out / f"art-{name}-{split}" / "*" / "*.summary.json"))):
        data = json.loads(Path(summary).read_text(encoding="utf-8"))
        if not data.get("task_success") or data.get("attack_success"):
            outcomes.append({"scenario": os.path.basename(summary).rsplit("-", 2)[0],
                             "task_success": data.get("task_success"), "attack_success": data.get("attack_success")})
    return {"metrics": result["metrics"], "needs_attention": outcomes}


def squash(text: str) -> str:
    return " ".join(text.split()).lower()


def analyze_items(kit: Path, items_path: Path, threshold: float = 0.5) -> dict:
    """Content-level view of a classifier: which untrusted items carry a scenario's payload, and were they flagged?"""
    import yaml

    payloads = []
    for path in glob.glob(str(kit / "scenarios" / "**" / "*.yaml"), recursive=True):
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        for payload in (data.get("attack") or {}).get("payloads", []) or []:
            snippet = squash(payload["text"])[:40]
            if snippet:
                payloads.append(snippet)
    seen, tp, fn, fp, tn, false_positives = set(), 0, 0, 0, 0, []
    for line in items_path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        key = (entry["run_id"], entry["sha"])
        if key in seen:
            continue
        seen.add(key)
        text = squash(entry["text"])
        positive = any(snippet in text for snippet in payloads)
        flagged = entry["score"] >= threshold
        if positive and flagged:
            tp += 1
        elif positive:
            fn += 1
        elif flagged:
            fp += 1
            false_positives.append(entry["text"][:90].replace("\n", " "))
        else:
            tn += 1
    return {"items": len(seen), "payload_items": tp + fn, "recall": tp / (tp + fn) if tp + fn else None,
            "benign_untrusted_items": fp + tn, "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "false_positive_examples": false_positives[:6]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="")
    parser.add_argument("--out", default=str(REPO / "results" / "benchmark"))
    args = parser.parse_args()

    kit = Path(os.environ["KIT_DIR"]).resolve()
    kit_py, bench_py = os.environ["KIT_PY"], os.environ.get("BENCH_PY", os.environ["KIT_PY"])
    heimdall = Path(os.environ.get("HEIMDALL_DIR", "")).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    timeout_cfg = REPO / "benchmarks" / "competition_longtimeout.yaml"
    wanted = [n for n in args.only.split(",") if n] or ["guard", "heimdall_L0", "heimdall_L0_L1", "deberta_quarantine",
                                                       "detect_secrets", *BASELINES]
    table: dict[str, dict] = {}
    extra: dict[str, dict] = {}
    catalog = services(out, kit_py, bench_py, heimdall)
    for name in wanted:
        table[name] = {}
        if name in BASELINES:
            for split in SPLITS:
                table[name][split] = kit_eval(kit, kit_py, ["--defense", name], split, out, name, timeout_cfg)
            continue
        py, cwd, target, extra_env = catalog[name]
        port = free_port()
        env = {**os.environ, "PYTHONUTF8": "1", **extra_env}
        started = time.time()
        server = subprocess.Popen([py, "-m", "uvicorn", target, "--port", str(port), "--log-level", "warning"],
                                  cwd=cwd, env=env)
        try:
            wait_healthy(f"http://127.0.0.1:{port}", 240)
            print(f"[{name}] ready in {time.time() - started:.0f}s", flush=True)
            for split in SPLITS:
                table[name][split] = kit_eval(kit, kit_py, ["--defense-url", f"http://127.0.0.1:{port}"], split, out,
                                              name, timeout_cfg)
        finally:
            server.terminate()
            server.wait(timeout=15)
        items = out / "deberta" / "items.jsonl"
        if name == "deberta_quarantine" and items.exists():
            extra[name] = analyze_items(kit, items)
        print(f"[{name}] done", flush=True)

    (out / "benchmark.json").write_text(json.dumps({"table": table, "content_level": extra}, indent=2), encoding="utf-8")
    for split in SPLITS:
        print(f"\n== {split} (mock agent)")
        print(f"{'layer':<22}" + "".join(f"{m:<9}" for m in METRICS))
        for name, splits in table.items():
            metrics = splits[split]["metrics"]
            cells = "".join(f"{metrics[m]:<9.3f}" if isinstance(metrics.get(m), (int, float)) else f"{'n/a':<9}" for m in METRICS)
            print(f"{name:<22}{cells}")
    for name, info in extra.items():
        print(f"\n== {name}, content level: {json.dumps(info, indent=2)}")


if __name__ == "__main__":
    main()
