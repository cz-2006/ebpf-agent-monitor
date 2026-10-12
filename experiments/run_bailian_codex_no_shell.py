#!/usr/bin/env python3
"""Start Bailian-backed Codex without a shell wrapper, then replace this process."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import sys


def fail(message: str, status: int = 2) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(status)


def main() -> None:
    api_key = os.environ.get("BAILIAN_API_KEY", "")
    base_url = os.environ.get("BAILIAN_BASE_URL", "").rstrip("/")
    model = os.environ.get("BAILIAN_MODEL", "qwen3.8-flash")

    if not api_key:
        fail("BAILIAN_API_KEY is not set")
    if not base_url:
        fail("BAILIAN_BASE_URL is not set; copy the API Host from Model Studio")
    if len(sys.argv) == 1:
        fail(f"usage: BAILIAN_API_KEY=... BAILIAN_BASE_URL=... {sys.argv[0]} PROMPT")
    if re.fullmatch(r"[A-Za-z0-9._-]+", model) is None:
        fail("BAILIAN_MODEL contains unsupported characters")
    if re.fullmatch(
        r"https://[A-Za-z0-9.-]+(?::[0-9]+)?/compatible-mode/v1", base_url
    ) is None:
        fail("BAILIAN_BASE_URL must be an HTTPS compatible-mode/v1 endpoint")

    codex_bin = os.environ.get("CODEX_BIN", "") or shutil.which("codex")
    if not codex_bin:
        fallback = Path.home() / ".local/bin/codex"
        if fallback.is_file() and os.access(fallback, os.X_OK):
            codex_bin = str(fallback)
    if not codex_bin or not os.access(codex_bin, os.X_OK):
        fail("Codex is not available or is not executable", 127)

    catalog = Path(__file__).resolve().with_name("bailian-model-catalog.json")
    arguments = [
        codex_bin,
        "exec",
        "--ignore-user-config",
        "--ephemeral",
        "--skip-git-repo-check",
        "--model",
        model,
        "--sandbox",
        "workspace-write",
        "-c",
        'model_provider="bailian"',
        "-c",
        f'model_catalog_json="{catalog}"',
        "-c",
        'model_reasoning_effort="low"',
        "-c",
        'model_providers.bailian.name="Alibaba Cloud Model Studio"',
        "-c",
        f'model_providers.bailian.base_url="{base_url}"',
        "-c",
        'model_providers.bailian.env_key="BAILIAN_API_KEY"',
        "-c",
        'model_providers.bailian.wire_api="responses"',
        *sys.argv[1:],
    ]
    os.execv(codex_bin, arguments)


if __name__ == "__main__":
    main()
