#!/usr/bin/env bash
# Phase 0 gate. Runs every check in SPEC section 3 and writes
# results/preflight.json (machine record, then one record per check with
# pass/fail and evidence). Raw evidence files go to results/preflight/.
#
# Usage: scripts/preflight.sh            (from the repo root, inside the devcontainer)
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
OUT_DIR=results/preflight
OUT=results/preflight.json
CHECKS="$(mktemp)"
mkdir -p "$OUT_DIR"
FRR_IMAGE="$(cat images/frr-image.txt)"
export FRR_IMAGE
LAB=scripts/preflight-lab/preflight.clab.yml
EBPFCHECK=build/ebpfcheck

# check NAME PASS(true|false) EVIDENCE
check() {
  python3 - "$1" "$2" "$3" >>"$CHECKS" <<'PY'
import json, sys
name, ok, ev = sys.argv[1], sys.argv[2] == "true", sys.argv[3]
print(json.dumps({"record": "check", "name": name, "pass": ok, "evidence": ev}))
PY
  if [ "$2" = true ]; then echo "PASS $1"; else echo "FAIL $1: $3"; fi
}

python3 -m labctl.machine >"$OUT_DIR/machine.json"

# 1. Kernel >= 5.17 (kfree_skb drop reasons).
KREL="$(uname -r)"
if python3 -c "import sys; v=tuple(int(x) for x in '$KREL'.split('-')[0].split('.')[:2]); sys.exit(0 if v>=(5,17) else 1)"; then
  check kernel_ge_5_17 true "uname -r = $KREL"
else
  check kernel_ge_5_17 false "uname -r = $KREL"
fi

# 2. BTF for CO-RE.
if [ -r /sys/kernel/btf/vmlinux ]; then
  check btf_vmlinux true "/sys/kernel/btf/vmlinux size $(stat -c %s /sys/kernel/btf/vmlinux) bytes"
else
  check btf_vmlinux false "/sys/kernel/btf/vmlinux missing or unreadable"
fi

# 3. Build the eBPF check program (bpf2go -> Go binary).
if make -s ebpfcheck >"$OUT_DIR/build.log" 2>&1; then
  check ebpf_build true "make ebpfcheck ok (clang $(clang --version | head -1 | awk '{print $NF}'))"
else
  check ebpf_build false "make ebpfcheck failed; see $OUT_DIR/build.log: $(tail -3 "$OUT_DIR/build.log" | tr '\n' ' ')"
fi

# Tracepoint attach needs tracefs. Codespaces do not mount it inside the
# devcontainer, so mount it if missing and record that we did.
if ! mountpoint -q /sys/kernel/tracing && ! mountpoint -q /sys/kernel/debug/tracing; then
  if sudo mount -t tracefs nodev /sys/kernel/tracing 2>"$OUT_DIR/tracefs.err"; then
    check tracefs_mounted true "was not mounted; mounted tracefs at /sys/kernel/tracing"
  else
    check tracefs_mounted false "mount -t tracefs failed: $(cat "$OUT_DIR/tracefs.err")"
  fi
else
  check tracefs_mounted true "already mounted"
fi

# 4. Attach from inside the devcontainer, no netns filter.
if [ -x "$EBPFCHECK" ] && sudo "$EBPFCHECK" -duration 3s -out "$OUT_DIR/ebpf_attach.json" >/dev/null 2>"$OUT_DIR/ebpf_attach.err"; then
  ev="$(python3 -c "import json;r=json.load(open('$OUT_DIR/ebpf_attach.json'));print('attached', r['attached'], 'netns seen', len({c['netns'] for c in r['counts'] or []}), 'events', sum(c['count'] for c in r['counts'] or []))")"
  check ebpf_attach_tracepoints true "$ev"
else
  check ebpf_attach_tracepoints false "$(cat "$OUT_DIR/ebpf_attach.err" 2>/dev/null; cat "$OUT_DIR/ebpf_attach.json" 2>/dev/null | tr '\n' ' ')"
fi

# Bring up the two-router preflight lab.
sudo -E containerlab deploy -t "$LAB" --reconfigure >"$OUT_DIR/clab_deploy.log" 2>&1
DEPLOY_RC=$?
R1=clab-cm-preflight-r1
R2=clab-cm-preflight-r2
if [ $DEPLOY_RC -ne 0 ]; then
  check lab_deploy false "containerlab deploy rc=$DEPLOY_RC; see $OUT_DIR/clab_deploy.log"
else
  check lab_deploy true "deployed $LAB with $FRR_IMAGE"
  sleep 3
  PID1="$(docker inspect -f '{{.State.Pid}}' $R1)"
  NS1="$(sudo stat -L -c %i /proc/$PID1/ns/net)"

  # 5. Cross-namespace visibility: ping r1 <-> r2 and send UDP to a closed
  # port on r1 while the tracer filters on r1's netns inode.
  if [ -x "$EBPFCHECK" ]; then
    rm -f "$OUT_DIR/.ready"
    sudo "$EBPFCHECK" -netns "$NS1" -duration 6s -ready "$OUT_DIR/.ready" -out "$OUT_DIR/ebpf_netns.json" 2>"$OUT_DIR/ebpf_netns.err" &
    EPID=$!
    for _ in $(seq 50); do [ -f "$OUT_DIR/.ready" ] && break; sleep 0.1; done
    docker exec $R2 ping -c 20 -i 0.05 10.1.0.0 >"$OUT_DIR/ping.log" 2>&1
    docker exec $R2 sh -c 'for i in 1 2 3 4 5; do echo x | nc -u -w1 10.1.0.0 9 ; done' >/dev/null 2>&1
    wait $EPID
    ev="$(python3 -c "import json;r=json.load(open('$OUT_DIR/ebpf_netns.json'));print(f\"r1 netns inode {r['target_netns']}: netif_receive_skb {r['target_recv']}, kfree_skb {r['target_drop']}, drop reasons {[(d['code'],d['name'],d['count']) for d in r['drop_reasons'] or []]}, ringbuf lost {r['ringbuf_lost']}\")" 2>&1)"
    if python3 -c "import json,sys;r=json.load(open('$OUT_DIR/ebpf_netns.json'));sys.exit(0 if r['target_recv']>0 else 1)" 2>/dev/null; then
      check ebpf_sees_node_netns true "$ev"
    else
      check ebpf_sees_node_netns false "$ev $(cat "$OUT_DIR/ebpf_netns.err")"
    fi
  else
    check ebpf_sees_node_netns false "ebpfcheck binary not built"
  fi

  # 6. Netlink route + nexthop monitoring inside r1's netns while FRR
  # installs and removes an ECMP-capable static route.
  sudo timeout 8 nsenter -t "$PID1" -n ip -ts monitor route nexthop >"$OUT_DIR/netlink_monitor.log" 2>&1 &
  MPID=$!
  sleep 1
  docker exec $R1 vtysh -c 'configure terminal' -c 'ip route 192.0.2.0/24 10.1.0.1' >/dev/null 2>&1
  sleep 2
  docker exec $R1 vtysh -c 'configure terminal' -c 'no ip route 192.0.2.0/24 10.1.0.1' >/dev/null 2>&1
  wait $MPID
  NEWR=$(grep -E '^\[.*\] 192\.0\.2\.0/24' "$OUT_DIR/netlink_monitor.log" | grep -vc Deleted)
  DELR=$(grep -cE 'Deleted 192\.0\.2\.0/24' "$OUT_DIR/netlink_monitor.log")
  NH=$(grep -cE '(^\[.*\] |Deleted )id [0-9]+' "$OUT_DIR/netlink_monitor.log")
  NHID=$(grep -cE '192\.0\.2\.0/24 nhid [0-9]+' "$OUT_DIR/netlink_monitor.log")
  ev="RTM_NEWROUTE lines $NEWR, RTM_DELROUTE lines $DELR, nexthop object lines $NH, routes referencing nhid $NHID (raw: $OUT_DIR/netlink_monitor.log)"
  if [ "$NEWR" -gt 0 ] && [ "$DELR" -gt 0 ] && [ "$NH" -gt 0 ]; then
    check netlink_route_and_nexthop true "$ev"
  else
    check netlink_route_and_nexthop false "$ev"
  fi

  # 7. netem on a veth inside the node.
  sudo nsenter -t "$PID1" -n tc qdisc add dev eth1 root netem loss 100% 2>"$OUT_DIR/netem.err"
  NETEM_RC=$?
  LOSS_ON=$(docker exec $R2 ping -c 5 -i 0.1 -W 1 10.1.0.0 2>&1 | grep -oE '[0-9.]+% packet loss')
  sudo nsenter -t "$PID1" -n tc qdisc del dev eth1 root 2>>"$OUT_DIR/netem.err"
  LOSS_OFF=$(docker exec $R2 ping -c 5 -i 0.1 -W 1 10.1.0.0 2>&1 | grep -oE '[0-9.]+% packet loss')
  ev="add rc=$NETEM_RC; with netem: $LOSS_ON; after removal: $LOSS_OFF $(cat "$OUT_DIR/netem.err")"
  if [ $NETEM_RC -eq 0 ] && [ "$LOSS_ON" = "100% packet loss" ] && [ "$LOSS_OFF" = "0% packet loss" ]; then
    check netem_on_veth true "$ev"
  else
    check netem_on_veth false "$ev"
  fi

  # 8. Shared clock: router containers share the devcontainer's time namespace.
  TNS_SELF="$(sudo stat -L -c %i /proc/self/ns/time 2>&1)"
  TNS_R1="$(sudo stat -L -c %i /proc/$PID1/ns/time 2>&1)"
  if [ "$TNS_SELF" = "$TNS_R1" ]; then
    check shared_time_namespace true "time ns inode devcontainer=$TNS_SELF r1=$TNS_R1"
  else
    check shared_time_namespace false "time ns inode devcontainer=$TNS_SELF r1=$TNS_R1"
  fi

  sudo -E containerlab destroy -t "$LAB" --cleanup >>"$OUT_DIR/clab_deploy.log" 2>&1
fi

# 9. Environment versions (always pass; recorded as evidence).
check environment true "$(python3 -c "import json;m=json.load(open('$OUT_DIR/machine.json'));print(', '.join(f'{k}={m[k]}' for k in ['cpu_count','cpu_model','mem_total_bytes','kernel','docker','containerlab','frr_image','go','python']))")"

python3 - "$OUT_DIR/machine.json" "$CHECKS" "$OUT" <<'PY'
import json, sys
machine = json.load(open(sys.argv[1]))
checks = [json.loads(l) for l in open(sys.argv[2])]
by = {c["name"]: c["pass"] for c in checks}
ebpf = ["kernel_ge_5_17", "btf_vmlinux", "ebpf_build", "ebpf_attach_tracepoints", "ebpf_sees_node_netns"]
if all(by.get(n) for n in ebpf) and by.get("netlink_route_and_nexthop"):
    tier = "A"
elif by.get("netlink_route_and_nexthop"):
    tier = "B"
else:
    tier = "C"
json.dump({"machine": machine, "checks": checks, "tier": tier}, open(sys.argv[3], "w"), indent=2)
open(sys.argv[3], "a").write("\n")
print("tier", tier)
PY
rm -f "$CHECKS"
