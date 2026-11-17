# Build entry points. eBPF objects are generated with bpf2go (needs clang and
# bpftool); the generated *_bpfel.{go,o} files are committed so plain `go build`
# works without clang.
SHELL := /bin/bash
GO ?= go
FRR_IMAGE := $(shell cat images/frr-image.txt)

.PHONY: all vmlinux generate ebpfcheck build test test-go test-py lint host-image preflight

all: build

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux: bpf/vmlinux.h

generate: bpf/vmlinux.h
	cd go && $(GO) generate ./...

ebpfcheck: generate
	mkdir -p build
	cd go && $(GO) build -o ../build/ebpfcheck ./cmd/ebpfcheck

build:
	mkdir -p build
	cd go && $(GO) build -o ../build/ ./cmd/...

test: test-go test-py

test-go:
	cd go && $(GO) vet ./... && $(GO) test ./...

test-py:
	python3 -m pytest -q

lint:
	ruff check . && ruff format --check .
	test -z "$$(gofmt -l go)"

host-image:
	docker build -f images/host/Dockerfile -t cm-host:latest .

preflight:
	bash scripts/preflight.sh
