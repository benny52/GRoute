package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/core"
	"github.com/lardan099/hyroute/internal/ctl"
	"github.com/lardan099/hyroute/internal/ctl/cli"
	"github.com/lardan099/hyroute/internal/ctl/ctlserver"
)

func TestGRouteBrowserChannel(t *testing.T) {
	g := newTestGUI(t)
	g.core = &core.Manager{Dir: t.TempDir()}
	if err := g.SetCLIMode("full"); err != nil {
		t.Fatal(err)
	}
	if err := g.ctl.SetBrowserOn(true); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := user.User.Sid
	sid := me.String()
	if ctl.PipeName(sid) == ctl.BrowserPipeName(sid) || ctl.RunEventName(sid) == ctl.BrowserRunEventName(sid) {
		t.Fatal("GRoute shares an IPC name with HyRoute")
	}
	if got := hostKey("test-user", `Google\Chrome`); got != `test-user\Software\Google\Chrome\NativeMessagingHosts\com.groute.browser` {
		t.Fatalf("wrong user or product in browser registration: %s", got)
	}
	// Never open the live browser endpoint or any user's registry.
	name := ctl.BrowserPipeName(fmt.Sprintf("test-%d-%d", os.Getpid(), time.Now().UnixNano()))
	l, err := ctl.Listen(ctl.ListenConfig{Name: name, Owner: me, Users: []*windows.SID{me},
		FullAccess: []*windows.SID{me}, Allow: allowClient(sid, sid)})
	if err != nil {
		t.Fatal(err)
	}
	backend := browserBackend{ctlBackend{g}}
	if backend.Mode() != "off" {
		t.Fatal("general command line enabled on the extension's channel")
	}
	srv := ctlserver.New(backend)
	done := make(chan struct{})
	go func() { srv.Serve(l); close(done) }()
	defer func() { srv.Close(); <-done }()
	d := &cli.Deps{SelfSID: sid, Dial: func(_ string, timeout time.Duration) (net.Conn, uint32, error) {
		return ctl.Dial(name, timeout, []string{sid})
	}}
	request := func(body string) string {
		t.Helper()
		var in, out bytes.Buffer
		binary.Write(&in, binary.LittleEndian, uint32(len(body)))
		in.WriteString(body)
		if code := cli.NativeHost(context.Background(), ctl.BrowserOrigins, &in, &out, "fixture.exe", d); code != 0 {
			t.Fatal(code)
		}
		var length uint32
		if err := binary.Read(&out, binary.LittleEndian, &length); err != nil || length != uint32(out.Len()) || !json.Valid(out.Bytes()) {
			t.Fatal("invalid native reply", err)
		}
		return out.String()
	}
	if s := request(`{"cmd":"browser-add","args":{"sites":[".example.test"],"to":"block","page":"example.test"}}`); !strings.Contains(s, `"added":1`) {
		t.Fatal(s)
	}
	if s := request(`{"cmd":"browser-info","args":{"hosts":["example.test"],"page":"example.test"}}`); !strings.Contains(s, `"to":"block"`) {
		t.Fatal(s)
	}
	if s := request(`{"cmd":"browser-remove","args":{"sites":[],"page":"example.test"}}`); !strings.Contains(s, `"removed":1`) {
		t.Fatal(s)
	}
	if err := g.ctl.SetBrowserOn(false); err != nil {
		t.Fatal(err)
	}
	if s := request(`{"cmd":"browser-info","args":{"hosts":[]}}`); !strings.Contains(s, `"code":"browser-off"`) {
		t.Fatal(s)
	}
}
