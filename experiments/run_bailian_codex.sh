#!/usr/bin/env bash
# 用 OpenAI 兼容接口启动百炼模型支持的 Codex CLI。
# 凭据只从环境变量读取，绝不写入仓库或 Codex 配置文件。
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
catalog_path="$script_dir/bailian-model-catalog.json"

# Keep the Alibaba Cloud credential outside the repository and Codex config.
if [[ -z "${BAILIAN_API_KEY:-}" ]]; then
    echo "BAILIAN_API_KEY is not set" >&2
    exit 2
fi
if [[ -z "${BAILIAN_BASE_URL:-}" ]]; then
    echo "BAILIAN_BASE_URL is not set; copy the API Host from Model Studio" >&2
    exit 2
fi
if (($# == 0)); then
    echo "usage: BAILIAN_API_KEY=... BAILIAN_BASE_URL=... $0 PROMPT" >&2
    exit 2
fi
codex_bin="${CODEX_BIN:-}"
if [[ -z "$codex_bin" ]]; then
    if command -v codex >/dev/null 2>&1; then
        codex_bin="$(command -v codex)"
    elif [[ -x "$HOME/.local/bin/codex" ]]; then
        codex_bin="$HOME/.local/bin/codex"
    else
        echo "codex is not available in PATH or $HOME/.local/bin" >&2
        exit 127
    fi
fi
if [[ ! -x "$codex_bin" ]]; then
    echo "Codex executable is not executable: $codex_bin" >&2
    exit 127
fi

bailian_model="${BAILIAN_MODEL:-qwen3.8-27b}"
bailian_base_url="${BAILIAN_BASE_URL%/}"

# These restrictions keep command-line TOML overrides well formed.
if [[ ! "$bailian_model" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "BAILIAN_MODEL contains unsupported characters" >&2
    exit 2
fi
if [[ ! "$bailian_base_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?/compatible-mode/v1$ ]]; then
    echo "BAILIAN_BASE_URL must be an HTTPS compatible-mode/v1 endpoint" >&2
    exit 2
fi

# Ignore the normal ChatGPT-backed Codex configuration for this run. The
# provider reads only BAILIAN_API_KEY and sends Responses API calls to Bailian.
exec "$codex_bin" exec \
    --ignore-user-config \
    --ephemeral \
    --skip-git-repo-check \
    --model "$bailian_model" \
    --sandbox workspace-write \
    -c 'model_provider="bailian"' \
    -c "model_catalog_json=\"${catalog_path}\"" \
    -c 'model_reasoning_effort="low"' \
    -c 'model_providers.bailian.name="Alibaba Cloud Model Studio"' \
    -c "model_providers.bailian.base_url=\"${bailian_base_url}\"" \
    -c 'model_providers.bailian.env_key="BAILIAN_API_KEY"' \
    -c 'model_providers.bailian.wire_api="responses"' \
    "$@"
