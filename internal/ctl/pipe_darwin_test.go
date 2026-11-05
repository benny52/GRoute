//go:build darwin

package ctl

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// The listener names the peer by its user and process.
func TestListenUnixIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctl.sock")
	ln, err := ListenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	c, id, allowed, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if id.User != strconv.Itoa(os.Getuid()) || id.PID != uint32(os.Getpid()) {
		t.Fatalf("%+v", id)
	}
	if allowed != (os.Getuid() == 0 || id.Admin) {
		t.Fatalf("allowed=%v for %+v", allowed, id)
	}
}
