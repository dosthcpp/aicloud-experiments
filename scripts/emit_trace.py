#!/usr/bin/env python3
"""Emit a metadata-only Gate A trace after validating contract and run scope."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from validate_contract import load_contract, trusted_context_from_env, validate_contract


SECRET_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"\b(?:sk[-_][A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9_-]{8,}|github_pat_[A-Za-z0-9_-]{8,})\b"),
)
APPROVED_TOOLS = {"manifest-collector", "gate-a-shadow-runner"}


def evidence_root() -> Path:
    """Resolve the evidence directory from the current Paperclip workspace."""
    workspace = os.environ.get("PAPERCLIP_WORKSPACE_CWD", "").strip()
    root = Path(workspace) if workspace else Path(__file__).resolve().parents[1]
    return root.resolve() / "evidence"


def redact_secret_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _redact_trace_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secret_text(value)
    if isinstance(value, list):
        return [_redact_trace_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_trace_value(item) for key, item in value.items()}
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_trace(
    contract: dict,
    artifact_path: Path,
    tool: str,
    model_provider: str,
    model: str,
    result: str,
    duration_ms: int,
    *,
    trusted_context: Mapping[str, str],
) -> dict:
    errors = validate_contract(contract, trusted_context)
    if errors:
        raise ValueError("invalid contract: " + "; ".join(errors))
    if result not in {"succeeded", "failed", "cancelled", "timed_out", "rejected"}:
        raise ValueError("result must be a terminal state")
    if duration_ms < 0:
        raise ValueError("duration_ms must be non-negative")

    if tool not in APPROVED_TOOLS:
        raise ValueError("tool is not an approved Gate A metadata identifier")
    approved_routes = {
        tuple(route.split("/", 1))
        for route in (contract["model"]["localRoute"], contract["model"]["externalReferenceRoute"])
        if isinstance(route, str) and "/" in route
    }
    if (model_provider, model) not in approved_routes:
        raise ValueError("model provider/revision is not declared by the run contract")

    output_root = Path(contract["data"]["outputRoot"]).resolve()
    artifact_resolved = artifact_path.resolve(strict=True)
    if output_root not in artifact_resolved.parents:
        raise ValueError("artifact is outside the contract's run-owned outputRoot")

    run_id = contract["identity"]["runId"]
    artifact_sha = sha256_file(artifact_resolved)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    common = {
        "company_id": contract["identity"]["companyId"],
        "issue_id": contract["identity"]["issueId"],
        "run_id": run_id,
        "agent_id": contract["identity"]["agentId"],
        "workload_class": contract["placement"]["workloadClass"],
        "source_revision": contract["provenance"]["sourceRevision"],
        "content_capture": False,
        "tool_arguments_capture": False,
        "tool_results_capture": False,
    }
    trace = {
        "traceVersion": "gate-a-trace/v1",
        "traceId": hashlib.sha256(f"{run_id}:{artifact_sha}".encode()).hexdigest()[:32],
        "observedAt": now,
        "ownerRunId": run_id,
        "spans": [
            {"name": "paperclip.run", "attributes": {**common, "result_code": result}},
            {"name": "tool.invoke", "attributes": {**common, "tool": tool, "duration_ms": duration_ms, "result_code": result}},
            {"name": "model.route", "attributes": {**common, "route": model_provider, "model": model, "result_code": result}},
            {"name": "artifact.record", "attributes": {**common, "artifact_sha256": artifact_sha, "result_code": result}},
        ],
    }
    return _redact_trace_value(trace)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--model-provider", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--duration-ms", type=int, required=True)
    args = parser.parse_args()

    trace = build_trace(
        load_contract(args.contract),
        args.artifact,
        args.tool,
        args.model_provider,
        args.model,
        args.result,
        args.duration_ms,
        trusted_context=trusted_context_from_env(),
    )
    output_root = evidence_root()
    destination = args.output.resolve()
    if output_root not in destination.parents:
        raise ValueError(f"trace output must stay inside {output_root}")
    destination.write_text(json.dumps(trace, indent=2) + "\n", encoding="utf-8")
    print(f"WROTE metadata-only trace {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
