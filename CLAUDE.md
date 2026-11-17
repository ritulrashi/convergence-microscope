# Convergence Microscope: working rules

The full spec is `docs/spec.md`. Non-negotiables from it:

- No unmeasured numbers. Every number in README, FINDINGS, BENCHMARKS, TESTING comes from a committed script; raw output in `results/<experiment>/`, starting with a `machine` record (`python3 -m labctl.machine`).
- Never fake a feature. README lists only what is implemented and tested.
- Report problems; invalid runs are kept and marked, never dropped.
- Calibrate classifiers against constructed cases before use.
- Deterministic: same intent gives byte-identical configs; experiments take a seed.
- Fit in 4-core / 16 GB, still run on 2-core / 8 GB, at most ~14 containers.
- No em dashes in any docs.
- Non-obvious design choices get an ADR in `docs/decisions.md`.
- Each phase ends with green tests, `reports/phaseN.md`, a commit.

Everything Linux-specific (containerlab, eBPF, netlink) runs inside the devcontainer (GitHub Codespace).
