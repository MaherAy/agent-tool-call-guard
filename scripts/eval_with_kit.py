"""Run the SENTINEL kit's evaluation against this defense and print a results table.

    KIT_DIR=../Sentinel_Starter_Kit python scripts/eval_with_kit.py [--model mock] [--attacker static|mutation]
                                                                    [--attack-mode static|adaptive] [--out DIR]

Starts the defense service on a free port, runs `sentinel eval public` and `sentinel eval validation` against it,
prints the metrics and every scenario where the task failed or the attack succeeded, then stops the service.
Layers can be ablated with GUARD_DISABLE=contract,grounding,dlp,reconstruction,memory_rules.
If Langfuse is configured (.env), the finished run is then published: one trace per scenario, one step per candidate
action, with the decision, why, and what happened next. Set LANGFUSE_TRACING_ENVIRONMENT per experiment.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from guard import langfuse_export  # noqa: E402

METRICS = ["btu", "asr", "cvr", "fbr", "uer", "tui", "dfi", "brier", "ece", "latency_p95_ms"]


def kit_python(kit: Path) -> str:
    for candidate in (kit / ".venv" / "Scripts" / "python.exe", kit / ".venv" / "bin" / "python"):
        if candidate.exists():
            return str(candidate)
    return sys.executable


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_healthy(url: str, seconds: float = 20.0) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/healthz", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.3)
    raise SystemExit("defense service did not become healthy")


def scenario_name(path: str) -> str:
    return os.path.basename(path).rsplit("-", 2)[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="mock")
    parser.add_argument("--attacker", default="static")
    parser.add_argument("--attack-mode", default="static")
    parser.add_argument("--out", default=str(REPO / "results" / "latest"))
    args = parser.parse_args()

    langfuse_export.load_env_file(Path(os.environ.get("GUARD_ENV_FILE", REPO / ".env")))
    kit = Path(os.environ.get("KIT_DIR", REPO.parent / "Sentinel_Starter_Kit")).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    python = kit_python(kit)
    port = free_port()
    url = f"http://127.0.0.1:{port}"

    env = {**os.environ, "PYTHONPATH": str(REPO), "GUARD_TRACE_DIR": str(out / "trace"), "PYTHONUTF8": "1"}
    # The defense service runs in the interpreter that launched this script; the kit's own interpreter is used only for
    # the kit's commands. Override with GUARD_PY.
    service_python = os.environ.get("GUARD_PY", sys.executable)
    server = subprocess.Popen(
        [service_python, "-m", "uvicorn", "guard.app:app", "--port", str(port), "--log-level", "warning"],
        cwd=REPO, env=env,
    )
    try:
        wait_healthy(url)
        rows = {}
        for split in ("public", "validation"):
            report = out / f"{split}.json"
            cmd = [python, "-m", "sentinel.cli", "eval", split, "--defense-url", url, "--model", args.model,
                   "--attacker", args.attacker, "--attack-mode", args.attack_mode,
                   "--artifacts", str(out / f"art-{split}"), "--output", str(report), "--json"]
            subprocess.run(cmd, cwd=kit, env=env, stdout=subprocess.DEVNULL, check=True)
            rows[split] = json.loads(report.read_text(encoding="utf-8"))["metrics"]
    finally:
        server.terminate()
        server.wait(timeout=10)

    print(f"{'run':<24}" + "".join(f"{m:<9}" for m in METRICS))
    for split, metrics in rows.items():
        cells = "".join(f"{metrics[m]:<9.3f}" if isinstance(metrics.get(m), (int, float)) else f"{str(metrics.get(m)):<9}" for m in METRICS)
        print(f"{'guard/' + split:<24}{cells}")
    print()
    for split in rows:
        for summary in sorted(glob.glob(str(out / f"art-{split}" / "*" / "*.summary.json"))):
            data = json.loads(Path(summary).read_text(encoding="utf-8"))
            if not data.get("task_success") or data.get("attack_success"):
                print(f"  [{split}] {scenario_name(summary):<36} task={data.get('task_success')} attack={data.get('attack_success')}")
    trace = out / "trace" / "guard-trace.jsonl"
    if os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY"):
        print("\nLangfuse:", langfuse_export.publish_directory(out, trace))
    if trace.exists():
        check = subprocess.run([sys.executable, "-m", "guard.trace", "verify", str(trace)], cwd=REPO, env=env,
                               capture_output=True, text=True)
        print("\ntrace:", check.stdout.strip())


if __name__ == "__main__":
    main()
