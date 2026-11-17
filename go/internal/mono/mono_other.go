//go:build !linux

package mono

import "time"

var start = time.Now()

// Off Linux there is no shared CLOCK_MONOTONIC; this exists only so unit
// tests compile on developer machines.
func now() int64 { return int64(time.Since(start)) }
