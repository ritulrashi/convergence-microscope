// Package mono reads CLOCK_MONOTONIC in nanoseconds, the shared clock used by
// every component (eBPF bpf_ktime_get_ns uses the same clock).
package mono

// Now returns CLOCK_MONOTONIC in nanoseconds.
func Now() int64 { return now() }
