# Build entry points. eBPF objects are generated with bpf2go (needs clang and
# bpftool); the generated *_bpfel.{go,o} files are committed so plain `go build`
# works without clang.
SHELL := /bin/bash
# The base image exports GOROOT=/usr/local/go (Go 1.22); always use /opt/go.
export GOROOT := /opt/go
export PATH := /opt/go/bin:$(PATH)
GO ?= go
FRR_IMAGE := $(shell cat images/frr-image.txt)

.PHONY: all vmlinux generate ebpfcheck build test test-go test-py lint host-image preflight calibrate

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
	cd go && for c in prober recorder ebpfcheck; do $(GO) build -o ../build/$$c ./cmd/$$c || exit 1; done

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

calibrate: build
	bash scripts/calibrate.sh
