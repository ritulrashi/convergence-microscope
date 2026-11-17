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

## ADR-004: Go installed into /opt/go, not via the devcontainer Go feature

- **Context:** The containerlab devcontainer image ships Go 1.22 in `/usr/local/go` and exports `GOROOT=/usr/local/go`. The devcontainer Go feature unpacked 1.26 over it, leaving 1.22 runtime files behind, and every build failed with "redeclared in this block" errors in `runtime`.
- **Decision:** `post-create.sh` installs the pinned Go release into an empty `/opt/go`. `devcontainer.json` sets `GOROOT=/opt/go` and puts `/opt/go/bin` first on `PATH`; the Makefile exports the same, so non-login shells (for example `gh codespace ssh -- cmd`) also get the right toolchain.
- **Alternatives:** delete `/usr/local/go` first (modifies the base image's layout); build a custom image (slower Codespace creation).
- **Consequence:** one toolchain, one version, independent of the base image's Go.

## ADR-005: Preflight mounts tracefs when missing

- **Context:** Codespaces do not mount tracefs inside the devcontainer. `link.Tracepoint` needs it to look up tracepoint IDs, and fails with "neither debugfs nor tracefs are mounted".
- **Decision:** `scripts/preflight.sh` (and later the tracer startup) mounts tracefs at `/sys/kernel/tracing` if neither tracing path is mounted, and records that as its own check.
- **Alternatives:** a bind mount in `devcontainer.json` (only takes effect after a full rebuild, and depends on the host path existing); `tp_btf` raw tracepoints (no tracefs needed, but a different program type than the spec names).
- **Consequence:** the privileged devcontainer gains one extra mount, done visibly and recorded in `results/preflight.json`.

## ADR-006: Spines do not expect each other's loopbacks in leaf-spine eBGP

- **Context:** In T1 eBGP, spines share ASN 65000 and leaves export only their own prefixes (SPEC 4.2). The first `verify` failed because `spine1` had no route to `spine2`'s loopback.
- **Decision:** That is the intended RFC 7938 behavior, so `verify` excludes other spines' loopbacks from a spine's expected RIB in leaf-spine eBGP. All other prefixes are still required everywhere.
- **Alternatives:** let leaves re-export spine loopbacks (makes leaves transit for spine-to-spine traffic, which the spec forbids); give spines distinct ASNs (not RFC 7938 style).
- **Consequence:** spine-to-spine reachability is not part of the fabric's contract and is not probed.

## ADR-007: Lab plumbing choices

- **Context:** Containers keep Docker's management interface (eth0, 172.20.20.0/24) with a default route.
- **Decision:** Hosts get `10.0.0.0/8 via <gateway>` instead of replacing the default route, so the management path keeps working and all lab traffic uses the fabric. Router sysctls (`ip_forward`, `fib_multipath_hash_policy=1`, `rp_filter=0`, IPv6 off) are set through containerlab's `sysctls` so they apply before FRR starts. Interface addresses are configured by FRR (`zebra`), so the generated `frr.conf` is the single source of addressing.
- **Alternatives:** `exec` sysctls after start (race with FRR); addresses via `ip addr` in `exec` (two sources of truth for drift checks).
- **Consequence:** `labctl diff` compares one config per router.

## ADR-008: Generated configs use FRR's canonical running-config form

- **Context:** `labctl diff` compares running and generated configs (SPEC 4.4). FRR rewrites its input: it reorders blocks (prefix-lists and route-maps first, interfaces sorted, `lo` after `eth*`), reorders lines inside blocks, turns `passive-interface X` into `ip ospf passive` under the interface, and hides defaults (`isis metric 10`, `maximum-paths 64`, `metric-style wide`, `bgp log-neighbor-changes` under `frr defaults datacenter`). It also shows `use-underlays-nexthop-weight`, which FRR 10.7 adds on its own.
- **Decision:** the templates emit exactly FRR 10.7.1's canonical form. Normalisation in `labctl/drift.py` only strips FRR's banner, version line, `!` separators and `end`. A clean deploy diffing empty is a tested property (`tests/test_drift.py`, running configs captured from clean deploys of every mode).
- **Alternatives:** a semantic normaliser that parses both configs into (block, line) sets with a table of FRR rewrites. More code, and every new FRR rewrite is silently "normalised away" instead of showing up as a failing test.
- **Consequence:** a new FRR version may change the canonical form; the drift fixtures will then fail and must be recaptured with the new image. Relying on FRR's default `maximum-paths` (64) is covered by `verify`'s ECMP-width check.
