import asyncio
import hashlib
import inspect
import json
import subprocess

import pytest

import server


def _ids(obligations):
    return sorted(o["id"] for o in obligations)


def test_scope_obligations_filters_by_flags():
    assert _ids(server.scope_obligations(True, True, False)) == [
        "EUAIA-ART50", "GDPR-ART30", "GDPR-ART32"]
    assert server.scope_obligations(False, False, False) == []
    assert "EUAIA-ART50" not in _ids(server.scope_obligations(True, False, False))


def test_unknown_recipe_raises_value_error(tmp_path):
    with pytest.raises(ValueError, match="nope"):
        server.get_recipe("nope")
    with pytest.raises(ValueError, match="nope"):
        server.run_check("nope", str(tmp_path))


def test_run_check_not_checked_when_binary_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(server.shutil, "which", lambda name: None)
    result = server.run_check("secret-in-repo", str(tmp_path))
    assert result["status"] == "not_checked"
    assert result["status"] != "pass"


def test_record_evidence_writes_hashed_line(monkeypatch, tmp_path):
    evidence = tmp_path / "evidence.jsonl"
    monkeypatch.setattr(server, "EVIDENCE", evidence)
    result = server.record_evidence("secret-in-repo", "fail", "some output")
    assert result["sha256"] == hashlib.sha256(b"some output").hexdigest()
    lines = evidence.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    for key in ("output_sha256", "timestamp", "recipe_id", "status"):
        assert key in entry
    assert entry["output_sha256"] == result["sha256"]
    assert entry["recipe_id"] == "secret-in-repo"
    assert entry["status"] == "fail"


def test_no_tool_can_run_an_arbitrary_command(monkeypatch, tmp_path):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setattr(server.shutil, "which", lambda name: "/x")
    path = str(tmp_path)

    result = server.run_check("secret-in-repo", path)
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv[0] == "gitleaks"
    expected = [tok.replace("{path}", path)
                for tok in server.get_recipe("secret-in-repo")["detect"]]
    assert argv == expected
    assert kwargs.get("shell", False) is False
    assert result["status"] == "pass"

    with pytest.raises(ValueError):
        server.run_check("rm -rf /", path)
    assert len(calls) == 1

    with pytest.raises(ValueError):
        server.run_check("secret-in-repo", "--config=/etc/x")
    assert len(calls) == 1

    tools = asyncio.run(server.mcp.list_tools())
    assert tools
    forbidden = {"command", "cmd", "argv", "args"}
    for tool in tools:
        params = set(inspect.signature(getattr(server, tool.name)).parameters)
        assert not params & forbidden, tool.name
