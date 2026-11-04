"""compliance-knowledge: first slice of the Claude for Compliance knowledge server.

Read-only knowledge tools plus run_check, which stands in for the separate
scanner server's scanner.run. It never applies a fix and only runs the detect
command defined in a recipe file.
"""
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml
from mcp.server.fastmcp import FastMCP

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
EVIDENCE = Path(os.environ.get("COMPLIANCE_EVIDENCE_FILE", HERE / "evidence.jsonl"))
TIMEOUT_S = 60
STATUSES = {"pass", "fail", "not_checked"}

mcp = FastMCP("compliance-knowledge")


def _load(name: str) -> dict:
    with open(DATA / f"{name}.yaml", encoding="utf-8") as f:
        return {item["id"]: item for item in yaml.safe_load(f)}


@mcp.tool()
def scope_obligations(processes_eu_personal_data: bool, people_talk_to_ai: bool,
                      high_risk_ai: bool) -> list[dict]:
    """Return the obligations that apply to a system with these characteristics."""
    flags = {"processes_eu_personal_data": processes_eu_personal_data,
             "people_talk_to_ai": people_talk_to_ai,
             "high_risk_ai": high_risk_ai}
    return [o for o in _load("obligations").values()
            if any(flags.get(key) for key in o["applies_if"])]


@mcp.tool()
def get_control(control_id: str) -> dict:
    """Return a control with its mapped obligations expanded."""
    controls = _load("controls")
    if control_id not in controls:
        raise ValueError(f"Unknown control: {control_id}. Known: {sorted(controls)}")
    obligations = _load("obligations")
    control = dict(controls[control_id])
    control["obligations"] = [obligations[o] for o in control["obligations"]]
    return control


@mcp.tool()
def get_recipe(recipe_id: str) -> dict:
    """Return a remediation recipe (detect / fix / verify / evidence / gate)."""
    recipes = _load("recipes")
    if recipe_id not in recipes:
        raise ValueError(f"Unknown recipe: {recipe_id}. Known: {sorted(recipes)}")
    return recipes[recipe_id]


@mcp.tool()
def run_check(recipe_id: str, path: str) -> dict:
    """Run ONLY the recipe's detect command against path. Never applies a fix.

    Stand-in for the scanner server's scanner.run.
    Returns status pass | fail | not_checked and the raw output.
    """
    recipe = get_recipe(recipe_id)
    if not path or path.startswith("-") or not Path(path).exists():
        raise ValueError(f"path must be an existing file or folder: {path}")
    argv =[tok.replace("{path}", path) for tok in recipe["detect"]]
    if shutil.which(argv[0]) is None:
        return {"recipe_id": recipe_id, "status": "not_checked",
                "output": f"{argv[0]} not installed", "command": argv}
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=TIMEOUT_S, shell=False)
    except subprocess.TimeoutExpired:
        return {"recipe_id": recipe_id, "status": "not_checked",
                "output": f"timed out after {TIMEOUT_S}s", "command": argv}
    except OSError as e:
        return {"recipe_id": recipe_id, "status": "not_checked",
                "output": str(e), "command": argv}
    status = {0: "pass", 1: "fail"}.get(proc.returncode, "not_checked")
    return {"recipe_id": recipe_id, "status": status, "exit_code": proc.returncode,
            "output": proc.stdout + proc.stderr, "command": argv}


@mcp.tool()
def record_evidence(recipe_id: str, status: str, output: str) -> dict:
    """Append a hashed evidence line to evidence.jsonl and return the hash."""
    get_recipe(recipe_id)
    if status not in STATUSES:
        raise ValueError(f"status must be one of {sorted(STATUSES)}")
    digest = hashlib.sha256(output.encode("utf-8")).hexdigest()
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(),
             "recipe_id": recipe_id, "status": status, "output_sha256": digest}
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    with open(EVIDENCE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return {"sha256": digest, "evidence_file": str(EVIDENCE)}


if __name__ == "__main__":
    mcp.run()
