//go:build darwin && !cgo

package main

import (
	"fmt"
	"os"
)

// runWindow needs Wails, which needs cgo: a build without it is the
// service alone.
func runWindow() {
	fmt.Fprintln(os.Stderr, "this HyRoute was built without cgo: no window (run --daemon)")
	os.Exit(1)
}
