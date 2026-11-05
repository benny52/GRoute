//go:build darwin && !cgo

package main

import (
	"fmt"
	"os"
)

func runMenubar() {
	fmt.Fprintln(os.Stderr, "this HyRoute was built without cgo: no menu bar icon")
	os.Exit(1)
}
