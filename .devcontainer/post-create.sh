#!/usr/bin/env bash
# Toolchain for eBPF (clang/llvm, libbpf headers, bpftool) and the Python stack.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  clang llvm libbpf-dev bpftool jq make linux-libc-dev

# Python deps for labgen/labctl/bench.
python3 -m pip install --user -e '.[dev]'

# bpf2go comes from the pinned cilium/ebpf version in go.mod.
(cd go && go mod download)
