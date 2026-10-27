#!/usr/bin/env python3
"""Dependency-free semantic validator for the TON-3971 Gate A contract."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from artifact_policy import trusted_artifact_root


WORKLOADS = {"embedding", "recap", "classification"}
FALLBACK_REASONS = {
    "local_timeout",
    "local_unavailable",
    "local_capacity",
    "local_retryable_error",
}
ALLOWED_TRACE_ATTRIBUTES = {
    "company_id",
    "issue_id",
    "run_id",
    "agent_id",
    "workload_class",
    "route",
    "model",
    "tool",
    "source_revision",
    "artifact_sha256",
    "queue_ms",
    "duration_ms",
    "input_tokens",
    "output_tokens",
    "result_code",
    "cost_lane",
    "cost_microusd",
}
FORBIDDEN_NEW_PATH_PREFIXES = ("/tmp/", "/private/tmp/", "/Users/")
ROOT = Path(__file__).resolve().parents[1]
COMPANY_ID = "8a2155a0-7cd2-4030-8006-4ffdde53b1a2"
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
EGRESS_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
APPROVED_ROUTE_POLICY = {
    "embedding": {
        "localRoute": "llamacpp/nomic-embed-text-v1.5.Q4_K_M",
        "externalReferenceRoute": "openai/text-embedding-3-small",
        "egress": {"api.openai.com"},
    },
    "recap": {
        "localRoute": f"llamacpp/{os.environ.get('GATE_A_CHAT_MODEL', 'Qwen3.8-27B')}",
        "externalReferenceRoute": "openai/gpt-4o-mini",
        "egress": {"api.openai.com"},
    },
    "classification": {
        "localRoute": f"llamacpp/{os.environ.get('GATE_A_CHAT_MODEL', 'Qwen3.8-27B')}",
        "externalReferenceRoute": "openai/gpt-4o-mini",
        "egress": {"api.openai.com"},
    },
}
ALLOWED_OBJECT_KEYS = {
    "": {"schemaVersion", "identity", "authorization", "placement", "data", "network", "model", "quality", "fallback", "sideEffects", "telemetry", "cost", "provenance", "slo"},
    "identity": {"companyId", "issueId", "runId", "agentId", "idempotencyKey"},
    "authorization": {"source", "audience", "authorizedCompanyId", "authorizedAgentIds", "runBoundSecretBroker"},
    "placement": {"workloadClass", "localNode", "timeoutMs", "retryLimit", "maxConcurrency", "memoryLimitMiB"},
    "data": {"sensitivity", "inputs", "outputRoot", "retentionHours"},
    "network": {"denyByDefault", "egressAllowlist", "downstreamTokenPassthrough"},
    "model": {"capability", "localRoute", "externalReferenceRoute"},
    "quality": {"suiteId", "minimumPassRate", "deterministicValidator"},
    "fallback": {"enabled", "localAttempts", "externalAttempts", "onlyOn", "sameDeadline"},
    "sideEffects": {"mode", "userVisible", "externalWrite", "singleCommit"},
    "telemetry": {"contentCapture", "toolArgumentsCapture", "toolResultsCapture", "allowedAttributes"},
    "cost": {"billedMicrousdCap", "shadowMicrousdCap", "localMicrousdCap", "requireRunLink"},
    "provenance": {"sourceRevision", "policyRevision", "modelRevision"},
    "slo": {"queueToStartP95Ms", "terminalSuccessMinimum", "orphanMaximum", "controlPlaneP95RegressionMaximum"},
}


def _is_explicit_egress_destination(value: Any) -> bool:
    """Accept one explicit HTTPS host (optionally with a port), never a wildcard."""
    if not isinstance(value, str) or not value or "*" in value or any(char.isspace() for char in value):
        return False
    candidate = value if "://" in value else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
        parsed.port
    except ValueError:
        return False
    hostname = parsed.hostname or ""
    labels = hostname.split(".")
    return bool(
        parsed.scheme == "https"
        and hostname
        and all(EGRESS_HOST_LABEL.fullmatch(label) for label in labels)
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    )


def _at(doc: dict[str, Any], dotted: str, errors: list[str]) -> Any:
    value: Any = doc
    for key in dotted.split("."):
        if not isinstance(value, dict) or key not in value:
            errors.append(f"missing required field: {dotted}")
            return None
        value = value[key]
    return value


def _reject_unknown_fields(doc: dict[str, Any], errors: list[str]) -> None:
    for path, allowed in ALLOWED_OBJECT_KEYS.items():
        value: Any = doc
        if path:
            for key in path.split("."):
                if not isinstance(value, dict) or key not in value:
                    value = None
                    break
                value = value[key]
        if isinstance(value, dict):
            for key in sorted(set(value) - allowed):
                label = f"{path}.{key}" if path else key
                errors.append(f"unknown field forbidden by closed contract: {label}")
    inputs = doc.get("data", {}).get("inputs") if isinstance(doc.get("data"), dict) else None
    if isinstance(inputs, list):
        for index, artifact in enumerate(inputs):
            if isinstance(artifact, dict):
                for key in sorted(set(artifact) - {"uri", "sha256", "ownerRunId"}):
                    errors.append(f"unknown field forbidden by closed contract: data.inputs[{index}].{key}")


def trusted_context_from_env() -> dict[str, str]:
    """Read identity only from the Paperclip-injected execution context."""
    env_fields = {
        "companyId": "PAPERCLIP_COMPANY_ID",
        "runId": "PAPERCLIP_RUN_ID",
        "agentId": "PAPERCLIP_AGENT_ID",
    }
    context = {field: os.environ.get(name, "") for field, name in env_fields.items()}
    missing = [env_fields[field] for field, value in context.items() if not value]
    if missing:
        raise ValueError(f"missing trusted Paperclip context: {', '.join(missing)}")
    return context


def validate_contract(
    doc: dict[str, Any], trusted_context: Mapping[str, str] | None = None, *, artifact_root: Path | None = None
) -> list[str]:
    errors: list[str] = []
    _reject_unknown_fields(doc, errors)

    if _at(doc, "schemaVersion", errors) != "gate-a/v1":
        errors.append("schemaVersion must be gate-a/v1")

    run_id = _at(doc, "identity.runId", errors)
    issue_id = _at(doc, "identity.issueId", errors)
    company_id = _at(doc, "identity.companyId", errors)
    agent_id = _at(doc, "identity.agentId", errors)
    idem = _at(doc, "identity.idempotencyKey", errors)
    if issue_id is not None and not re.fullmatch(r"TON-[0-9]+", str(issue_id)):
        errors.append("identity.issueId must match TON-<number>")
    if not isinstance(run_id, str) or not UUID_PATTERN.fullmatch(run_id):
        errors.append("identity.runId must be a canonical lowercase UUID")
    if not isinstance(agent_id, str) or not UUID_PATTERN.fullmatch(agent_id):
        errors.append("identity.agentId must be a canonical lowercase UUID")
    if not isinstance(idem, str) or len(idem) < 16:
        errors.append("identity.idempotencyKey must be stable and at least 16 characters")

    if company_id != COMPANY_ID:
        errors.append("identity.companyId is unauthorized for Tony AI Lab Gate A")
    if trusted_context is None:
        errors.append("trusted Paperclip run context is required")
    else:
        for field, claimed in (
            ("companyId", company_id),
            ("runId", run_id),
            ("agentId", agent_id),
        ):
            trusted = trusted_context.get(field)
            if trusted != claimed:
                errors.append(f"identity.{field} does not match trusted Paperclip run context")
    if _at(doc, "authorization.source", errors) != "paperclip-run-context":
        errors.append("authorization must come from the Paperclip run context")
    if _at(doc, "authorization.audience", errors) != "gate-a-shadow":
        errors.append("authorization audience must be gate-a-shadow")
    if _at(doc, "authorization.authorizedCompanyId", errors) != company_id:
        errors.append("authorization company does not match the run identity")
    authorized_agents = _at(doc, "authorization.authorizedAgentIds", errors)
    if not isinstance(authorized_agents, list) or authorized_agents != [agent_id]:
        errors.append("identity.agentId is unauthorized for this contract")
    broker_enabled = _at(doc, "authorization.runBoundSecretBroker", errors)
    fallback_enabled = _at(doc, "fallback.enabled", errors)
    if not isinstance(fallback_enabled, bool):
        errors.append("fallback.enabled must be boolean")
    if broker_enabled is not fallback_enabled:
        errors.append("the run-bound secret broker must match external reference opt-in")

    workload = _at(doc, "placement.workloadClass", errors)
    capability = _at(doc, "model.capability", errors)
    local_route = _at(doc, "model.localRoute", errors)
    external_route = _at(doc, "model.externalReferenceRoute", errors)
    if workload not in WORKLOADS:
        errors.append("placement.workloadClass is not allowed in Gate A")
    if capability != workload:
        errors.append("model.capability must equal placement.workloadClass")
    route_policy = APPROVED_ROUTE_POLICY.get(str(workload))
    if route_policy is None:
        errors.append("placement.workloadClass has no approved full-route registry entry")
    else:
        if local_route != route_policy["localRoute"]:
            errors.append("model.localRoute does not match the approved full-route registry")
        if fallback_enabled:
            if external_route != route_policy["externalReferenceRoute"]:
                errors.append("model.externalReferenceRoute does not match the approved full-route registry")
        elif external_route is not None:
            errors.append("model.externalReferenceRoute must be null when the external lane is disabled")
    if _at(doc, "placement.localNode", errors) != "mac-m4-local":
        errors.append("Gate A local placement is restricted to mac-m4-local")

    timeout_ms = _at(doc, "placement.timeoutMs", errors)
    retry_limit = _at(doc, "placement.retryLimit", errors)
    concurrency = _at(doc, "placement.maxConcurrency", errors)
    if not isinstance(timeout_ms, int) or not 1000 <= timeout_ms <= 120000:
        errors.append("placement.timeoutMs must be between 1000 and 120000")
    if not isinstance(retry_limit, int) or not 0 <= retry_limit <= 1:
        errors.append("placement.retryLimit must be 0 or 1")
    if not isinstance(concurrency, int) or not 1 <= concurrency <= 2:
        errors.append("placement.maxConcurrency must be 1 or 2")

    sensitivity = _at(doc, "data.sensitivity", errors)
    if sensitivity not in {"public", "internal"}:
        errors.append("unencrypted Gate A storage rejects confidential/personal/secret data")
    output_root = _at(doc, "data.outputRoot", errors)
    output_base = (artifact_root or trusted_artifact_root(ROOT)).resolve()
    expected_path = (output_base / run_id).resolve() if isinstance(run_id, str) else output_base
    expected_run_root = f"{expected_path}/"
    if expected_path.parent != output_base:
        errors.append("identity.runId may not escape the canonical artifact root")
    if not isinstance(output_root, str) or output_root != expected_run_root:
        errors.append(f"data.outputRoot must be the run-scoped path {expected_run_root}")
    if isinstance(output_root, str) and output_root.startswith(FORBIDDEN_NEW_PATH_PREFIXES):
        errors.append("workload output may not use /tmp, /private/tmp or /Users")

    inputs = _at(doc, "data.inputs", errors)
    if not isinstance(inputs, list) or not inputs:
        errors.append("data.inputs must contain at least one digest-addressed artifact")
    else:
        for index, artifact in enumerate(inputs):
            if not isinstance(artifact, dict):
                errors.append(f"data.inputs[{index}] must be an object")
                continue
            if artifact.get("ownerRunId") != run_id:
                errors.append(f"data.inputs[{index}] is cross-run or lacks ownerRunId")
            digest = artifact.get("sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                errors.append(f"data.inputs[{index}].sha256 must be lowercase SHA-256")

    if _at(doc, "network.denyByDefault", errors) is not True:
        errors.append("network.denyByDefault must be true")
    if _at(doc, "network.downstreamTokenPassthrough", errors) is not False:
        errors.append("downstream token passthrough is forbidden")
    allowlist = _at(doc, "network.egressAllowlist", errors)
    if not isinstance(allowlist, list) or len(allowlist) > 2:
        errors.append("network.egressAllowlist must contain at most two explicit destinations")
    elif any(not _is_explicit_egress_destination(destination) for destination in allowlist):
        errors.append("network.egressAllowlist entries must be explicit HTTPS hosts without wildcards")

    if route_policy is not None and isinstance(allowlist, list):
        expected_egress = route_policy["egress"] if fallback_enabled else set()
        if set(allowlist) != expected_egress:
            errors.append("network.egressAllowlist does not match the approved external reference mode")

    for field, expected in (
        ("sideEffects.mode", "shadow_only"),
        ("sideEffects.userVisible", False),
        ("sideEffects.externalWrite", False),
        ("sideEffects.singleCommit", True),
        ("telemetry.contentCapture", False),
        ("telemetry.toolArgumentsCapture", False),
        ("telemetry.toolResultsCapture", False),
    ):
        if _at(doc, field, errors) != expected:
            errors.append(f"{field} must be {expected!r}")

    attributes = _at(doc, "telemetry.allowedAttributes", errors)
    if not isinstance(attributes, list):
        errors.append("telemetry.allowedAttributes must be a list")
    else:
        disallowed = sorted(set(attributes) - ALLOWED_TRACE_ATTRIBUTES)
        if disallowed:
            errors.append(f"telemetry attributes are not metadata-only: {', '.join(disallowed)}")

    if _at(doc, "quality.minimumPassRate", errors) is None or doc["quality"]["minimumPassRate"] < 0.95:
        errors.append("quality.minimumPassRate must be at least 0.95")
    if _at(doc, "fallback.localAttempts", errors) != 1:
        errors.append("fallback.localAttempts must be exactly 1")
    external_attempts = _at(doc, "fallback.externalAttempts", errors)
    if _at(doc, "fallback.sameDeadline", errors) is not True:
        errors.append("fallback must share the original deadline")
    only_on = _at(doc, "fallback.onlyOn", errors)
    if fallback_enabled:
        if external_attempts != 1:
            errors.append("fallback.externalAttempts must be exactly 1 when the external lane is enabled")
        if not isinstance(only_on, list) or not only_on or set(only_on) - FALLBACK_REASONS:
            errors.append("fallback.onlyOn contains a non-bounded reason")
    else:
        if external_attempts != 0:
            errors.append("fallback.externalAttempts must be 0 when the external lane is disabled")
        if only_on != []:
            errors.append("fallback.onlyOn must be empty when the external lane is disabled")

    if _at(doc, "cost.requireRunLink", errors) is not True:
        errors.append("all cost lanes must link to the Paperclip run")
    for lane in ("billedMicrousdCap", "shadowMicrousdCap", "localMicrousdCap"):
        value = _at(doc, f"cost.{lane}", errors)
        if not isinstance(value, int) or value < 0:
            errors.append(f"cost.{lane} must be a non-negative integer")
    if not fallback_enabled and _at(doc, "cost.billedMicrousdCap", errors) != 0:
        errors.append("cost.billedMicrousdCap must be 0 when the external lane is disabled")

    if _at(doc, "provenance.policyRevision", errors) != "ADR-0001":
        errors.append("provenance.policyRevision must be ADR-0001")
    if _at(doc, "slo.queueToStartP95Ms", errors) is None or doc["slo"]["queueToStartP95Ms"] > 30000:
        errors.append("slo.queueToStartP95Ms must be at most 30000")
    if _at(doc, "slo.terminalSuccessMinimum", errors) is None or doc["slo"]["terminalSuccessMinimum"] < 0.95:
        errors.append("slo.terminalSuccessMinimum must be at least 0.95")
    if _at(doc, "slo.orphanMaximum", errors) != 0:
        errors.append("slo.orphanMaximum must be zero")
    regression = _at(doc, "slo.controlPlaneP95RegressionMaximum", errors)
    if not isinstance(regression, (int, float)) or regression > 0.10:
        errors.append("control-plane p95 regression maximum must be at most 10%")

    return sorted(set(errors))


def load_contract(path: Path) -> dict[str, Any]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("contract root must be a JSON object")
    data = doc.get("data")
    if isinstance(data, dict) and isinstance(data.get("outputRoot"), str):
        data["outputRoot"] = data["outputRoot"].replace(
            "${GATE_A_ARTIFACT_ROOT}", str(trusted_artifact_root(ROOT))
        )
    return doc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path)
    args = parser.parse_args()
    try:
        errors = validate_contract(load_contract(args.contract), trusted_context_from_env())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"INVALID: {error}", file=sys.stderr)
        return 1
    print("VALID gate-a/v1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
