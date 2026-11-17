#!/usr/bin/env bash
# Toolchain for eBPF (clang/llvm, libbpf headers, bpftool) and the Python stack.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  clang llvm libbpf-dev bpftool jq make linux-libc-dev

GO_VERSION=1.26.11
if [ "$(/opt/go/bin/go env GOVERSION 2>/dev/null)" != "go${GO_VERSION}" ]; then
  sudo rm -rf /opt/go
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | sudo tar -C /opt -xz
fi
export PATH=/opt/go/bin:$PATH

# Python deps for labgen/labctl/bench.
python3 -m pip install --user -e '.[dev]'

# bpf2go comes from the pinned cilium/ebpf version in go.mod.
(cd go && go mod download)
