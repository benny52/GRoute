//go:build windows || darwin

package main

import (
	"os"
	"reflect"
	"regexp"
	"testing"
)

// Every call the page makes (the GUI interfaces of frontend/src/api.ts)
// is a method of GUI: a missing one fails only when clicked («нет такого
// вызова»).
func TestPageCallsExist(t *testing.T) {
	b, err := os.ReadFile("../../frontend/src/api.ts")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile(`(?ms)^interface GUI \{(.*?)^\}`).FindAllSubmatch(b, -1)
	if len(blocks) == 0 {
		t.Fatal("no GUI interface in api.ts")
	}
	gui := reflect.TypeOf(&GUI{})
	method := regexp.MustCompile(`(?m)^\s+([A-Z]\w*)\(`)
	n := 0
	for _, blk := range blocks {
		for _, m := range method.FindAllSubmatch(blk[1], -1) {
			n++
			if _, ok := gui.MethodByName(string(m[1])); !ok {
				t.Errorf("the page calls %s, GUI has no such method", m[1])
			}
		}
	}
	if n < 50 {
		t.Fatalf("only %d calls found in api.ts", n)
	}
}
