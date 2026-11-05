//go:build darwin

package procinfo

import (
	"os"
	"strings"
	"testing"
)

func TestDarwinSelf(t *testing.T) {
	c := NewCache()
	in := c.Get(uint32(os.Getpid()))
	if in == nil || in.Path == "" || !strings.HasSuffix(in.Name, ".test") || in.Created == 0 {
		t.Fatalf("%+v", in)
	}
	c.Track()
	if in := c.Get(uint32(os.Getpid())); in.Parent == nil || in.Parent.PID != uint32(os.Getppid()) {
		t.Fatalf("parent %+v", in.Parent)
	}
}
