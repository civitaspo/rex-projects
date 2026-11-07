#!/usr/bin/env bash
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
	printf '%s\n' 'Lua CI dependencies currently require an Ubuntu runner with apt-get.' >&2
	exit 1
fi

sudo apt-get update
sudo apt-get install --no-install-recommends --yes libreadline-dev
