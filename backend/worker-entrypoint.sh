#!/usr/bin/env sh
set -eu

templates_dir="${NUCLEI_TEMPLATES_DIR:-/root/nuclei-templates}"
nuclei_config_dir="${NUCLEI_CONFIG_DIR:-/root/.config/nuclei}"

if command -v nuclei >/dev/null 2>&1; then
  mkdir -p "$nuclei_config_dir"
  touch "$nuclei_config_dir/.nuclei-ignore"
  if [ ! -d "$templates_dir" ] || [ -z "$(find "$templates_dir" -mindepth 1 -maxdepth 1 2>/dev/null | head -n 1)" ]; then
    echo "Initializing Nuclei templates in $templates_dir"
    mkdir -p "$templates_dir"
    nuclei -ut -ud "$templates_dir" || {
      echo "Nuclei template initialization failed; scans can retry after network/templates are available." >&2
    }
  else
    echo "Using existing Nuclei templates in $templates_dir"
  fi
fi

exec "$@"
