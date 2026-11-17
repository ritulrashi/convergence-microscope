# Architecture decision records

Each ADR: context, decision, alternatives, consequence.

## ADR-001: Pinned versions

- **Context:** Ground rule 7 (determinism) and rule 1 (every result names its environment) need fixed versions.
- **Decision:** devcontainer image `ghcr.io/srl-labs/containerlab/devcontainer-dind:0.83.0` (containerlab 0.83.0), router image `quay.io/frrouting/frr:10.7.1` (latest stable 10.x on 2026-11-17, stored in `images/frr-image.txt` so scripts and the machine record read one source), Go 1.26, `github.com/cilium/ebpf` v0.22.0, host image on `alpine:3.24.4` built with `golang:1.26.11-alpine`.
- **Alternatives:** floating tags (`latest`, `10`); rejected because results would not be reproducible.
- **Consequence:** Go 1.26 instead of the spec's minimum 1.22, because cilium/ebpf v0.22 requires Go 1.25+ and `golang.org/x/sys` v0.50 requires 1.26.

## ADR-002: Commit bpf2go output

- **Context:** eBPF C is compiled with clang via `bpf2go`. CI runners and the host image build should not need clang or a `vmlinux.h`.
- **Decision:** `bpf/vmlinux.h` is generated from the running kernel's BTF and not committed. The bpf2go outputs (`*_bpfel.go`, `*_bpfel.o`) are committed. CO-RE relocations make the objects portable across kernels with BTF.
- **Alternatives:** commit `vmlinux.h` (several MB, kernel-specific noise in diffs); compile in CI (adds clang to every job).
- **Consequence:** after editing any `.bpf.c` file, run `make generate` and commit the regenerated objects.

## ADR-003: Drop-reason names come from kernel BTF

- **Context:** Ground rule 4 and SPEC 5.5 forbid hard-coding drop-reason codes from documentation. The numeric values of `enum skb_drop_reason` change between kernel versions.
- **Decision:** userspace reads `enum skb_drop_reason` from `/sys/kernel/btf/vmlinux` at runtime to name codes, and calibration records which codes this kernel emits for constructed blackholes and loops.
- **Alternatives:** a static table copied from kernel headers.
- **Consequence:** names always match the running kernel; the classifier mapping is a calibration output, not source code.
