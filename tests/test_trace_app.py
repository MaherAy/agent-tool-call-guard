import json

from fastapi.testclient import TestClient

from guard.app import app
from guard.trace import Trace, verify


def test_chain_verifies_and_detects_tampering(tmp_path):
    path = tmp_path / "trace.jsonl"
    trace = Trace(path)
    for step in range(3):
        trace.append({"run_id": "r", "step": step, "decision": "allow"})
    assert verify(path) == (True, 3, None)

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["decision"] = "block"
    lines[1] = json.dumps(tampered, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, _, message = verify(path)
    assert not ok and "line 2" in message


def test_chain_continues_across_restarts(tmp_path):
    path = tmp_path / "trace.jsonl"
    Trace(path).append({"step": 1})
    Trace(path).append({"step": 2})
    assert verify(path)[:2] == (True, 2)


def test_service_speaks_the_v1_contract_and_fails_closed():
    client = TestClient(app)
    assert client.get("/healthz").json() == {"status": "ok"}
    body = {
        "run_id": "svc-1", "step_id": 2, "user_goal": "Read the note",
        "candidate_action": {"type": "tool_call", "tool": "unlisted_tool", "arguments": {}},
        "policy_context": {"allowed_tools": ["note_read"]},
    }
    reply = client.post("/v1/decision", json=body).json()
    assert reply["decision"] == "block" and reply["reason_codes"] == ["TOOL_NOT_ALLOWED"]
    assert set(reply) == {"decision", "risk_score", "confidence", "reason_codes", "explanation",
                          "rewritten_action", "metadata"}
    assert client.post("/v1/decision", json={"nonsense": True}).status_code == 422  # kit treats this as fail-closed
