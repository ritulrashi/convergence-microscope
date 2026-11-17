#!/usr/bin/env bash
# Calibration (SPEC 5.5). Every classifier and recorder is checked against
# constructed cases with known answers before it is used in an experiment.
# Results: results/calibration/.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m bench.calib_recorder
# Tier A only (reports/phase0.md): the eBPF tracer.
python3 -m bench.calib_tracer
