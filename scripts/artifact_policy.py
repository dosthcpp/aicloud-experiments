#!/usr/bin/env python3
"""Trusted artifact-root policy shared by Gate A contract and runtime code."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping


ARTIFACT_ROOT_ENV = "GATE_A_ARTIFACT_ROOT"
ALLOWED_STORAGE_ROOTS = (
    Path("/Volumes/Data/tony_ai_lab"),
    Path("/home/tony/aicloud"),
)
FORBIDDEN_ROOTS = (Path("/Users"), Path("/tmp"), Path("/private/tmp"))


def _approved_storage_root(workspace_root: Path) -> Path:
    workspace = workspace_root.resolve()
    for storage_root in ALLOWED_STORAGE_ROOTS:
        resolved_storage_root = storage_root.resolve()
        if workspace == resolved_storage_root or resolved_storage_root in workspace.parents:
            return resolved_storage_root
    raise ValueError("workspace root must be under an approved storage root")


def trusted_artifact_root(workspace_root: Path, environ: Mapping[str, str] | None = None) -> Path:
    """Return the single explicit artifact root or fail closed."""
    storage_root = _approved_storage_root(workspace_root)
    values = os.environ if environ is None else environ
    configured = values.get(ARTIFACT_ROOT_ENV, "").strip()
    candidate = Path(configured) if configured else workspace_root / "artifacts"
    if not candidate.is_absolute():
        raise ValueError(f"{ARTIFACT_ROOT_ENV} must be an absolute path")
    resolved = candidate.resolve()
    if resolved == storage_root or storage_root not in resolved.parents:
        raise ValueError(f"trusted artifact root must be under {storage_root}")
    if any(resolved == root or root in resolved.parents for root in FORBIDDEN_ROOTS):
        raise ValueError("trusted artifact root may not use /Users, /tmp, or /private/tmp")
    return resolved
