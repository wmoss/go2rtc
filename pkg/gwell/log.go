package gwell

import (
	"encoding/hex"
	"fmt"
)

// DebugLog can be set by the application to receive protocol diagnostics.
// nil by default; the internal wyze module wires it to its logger.
var DebugLog func(msg string)

// TraceLog receives raw protocol frame dumps (hex). Used by the live test
// harness to capture traffic from a real camera. nil by default.
var TraceLog func(msg string)

func debugf(format string, args ...any) {
	if DebugLog != nil {
		DebugLog(fmt.Sprintf(format, args...))
	}
}

// tracef dumps a raw protocol frame as label + hex when tracing is enabled.
func tracef(label string, data []byte) {
	if TraceLog == nil || len(data) == 0 {
		return
	}
	TraceLog(label + " " + hex.EncodeToString(data))
}
