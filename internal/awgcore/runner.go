package awgcore

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tunnels"
)

type Runner struct {
	path    func() (string, error)
	profile hysteria.Profile
	hooks   tunnels.Hooks
	life    sync.Mutex
	run     *instance
	mu      sync.RWMutex
	status  hysteria.Status
	proxy   socks5.Client
}

type instance struct {
	child    hysteria.Child
	input    *os.File
	output   *os.File
	stopping chan struct{}
	done     chan struct{}
}

func NewRunner(path func() (string, error), p hysteria.Profile, h tunnels.Hooks) *Runner {
	return &Runner{path: path, profile: p, hooks: h}
}

func (r *Runner) publish(st hysteria.Status, proxy socks5.Client) {
	r.mu.Lock()
	r.status, r.proxy = st, proxy
	r.mu.Unlock()
	if r.hooks.OnStatus != nil {
		r.hooks.OnStatus(st)
	}
}

func (r *Runner) Start() (err error) {
	r.life.Lock()
	defer r.life.Unlock()
	if r.run != nil {
		select {
		case <-r.run.done:
			r.run = nil
		default:
			return nil
		}
	}
	r.publish(hysteria.Status{State: hysteria.Connecting}, socks5.Client{})
	defer func() {
		if err != nil {
			r.publish(hysteria.Status{State: hysteria.Failed, Kind: hysteria.ErrOther, Message: err.Error()}, socks5.Client{})
		}
	}()

	exe, err := r.path()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(exe) {
		return errors.New("AmneziaWG: не задан путь к groute-awg.exe")
	}
	// Resolve once in the parent: the child must dial exactly the address
	// excluded from WinDivert, even if the domain has several records.
	p := r.profile
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", p.Host)
	cancel()
	if err != nil || len(ips) == 0 {
		return errors.New("AmneziaWG: не удалось определить IP сервера")
	}
	ip := ips[0].Unmap()
	p.Host = ip.String()
	if r.hooks.SetServerIPs != nil {
		if err = r.hooks.SetServerIPs([]netip.Addr{ip}); err != nil {
			return errors.New("AmneziaWG: не удалось исключить адрес сервера из перехвата")
		}
	}
	proc, err := launch(exe)
	if err != nil {
		r.clearIPs()
		return fmt.Errorf("не удалось запустить groute-awg.exe: %w", err)
	}
	r.run = proc
	ready := make(chan error, 1)
	go r.observe(proc, p.AWGConfig(), ready)
	timer := time.NewTimer(12 * time.Second)
	defer timer.Stop()
	select {
	case err = <-ready:
		if err != nil {
			<-proc.done
			r.run = nil
		}
		return err
	case <-timer.C:
		_ = proc.child.Kill() // unblock a config write if the child stopped reading
		r.stopProcess()
		return errors.New("groute-awg.exe не ответил при запуске")
	}
}

func launch(exe string) (*instance, error) {
	childInput, input, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer childInput.Close()
	output, childOutput, err := os.Pipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	defer childOutput.Close()
	child, err := hysteria.StartChildWithIO(exe, []string{"--serve"}, childInput, childOutput)
	if err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	return &instance{child: child, input: input, output: output, stopping: make(chan struct{}), done: make(chan struct{})}, nil
}

func (r *Runner) clearIPs() {
	if r.hooks.SetServerIPs != nil {
		_ = r.hooks.SetServerIPs(nil)
	}
}

func (r *Runner) observe(proc *instance, config string, ready chan<- error) {
	defer close(proc.done)
	defer r.clearIPs()
	started := false
	reason := errors.New("потеряна связь с groute-awg.exe")
	defer func() {
		proc.output.Close()
		proc.input.Close()
		select {
		case <-proc.stopping:
		default:
			_ = proc.child.Kill()
		}
		_ = proc.child.Wait()
		if !started {
			ready <- reason
			return
		}
		select {
		case <-proc.stopping:
		default:
			r.publish(hysteria.Status{State: hysteria.Failed, Kind: hysteria.ErrOther, Message: reason.Error()}, socks5.Client{})
		}
	}()
	in := bufio.NewReaderSize(proc.output, 16<<10)
	var e Event
	if Read(in, &e) != nil || e.Type != "hello" || e.Version != Protocol {
		reason = errors.New("groute-awg.exe не поддерживает протокол обмена этой версии GRoute")
		return
	}
	if err := json.NewEncoder(proc.input).Encode(Request{Config: config}); err != nil {
		return
	}
	var proxy socks5.Client
	for {
		e = Event{}
		if err := Read(in, &e); err != nil {
			return
		}
		if !started {
			if e.Type == "error" && e.Status.Message != "" {
				reason = errors.New(e.Status.Message)
				return
			}
			addr, err := netip.ParseAddrPort(e.Status.SOCKS)
			if e.Type != "ready" || err != nil || !addr.Addr().IsLoopback() || addr.Port() == 0 || e.Username == "" || e.Password == "" {
				return
			}
			proxy = socks5.Client{Server: addr.String(), Username: e.Username, Password: e.Password}
			if !validStatus(e.Status.State) {
				return
			}
			r.publish(e.Status, proxy)
			started = true
			ready <- nil
		} else {
			if e.Type != "status" || !validStatus(e.Status.State) {
				return
			}
			r.publish(e.Status, proxy)
		}
	}
}

func validStatus(s hysteria.State) bool { return s >= hysteria.Stopped && s <= hysteria.Failed }

func (r *Runner) stopProcess() {
	if r.run == nil {
		return
	}
	proc := r.run
	close(proc.stopping)
	proc.input.Close()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-proc.done:
	case <-timer.C:
		_ = proc.child.Kill()
		<-proc.done
	}
	r.run = nil
}

func (r *Runner) Stop() {
	r.life.Lock()
	defer r.life.Unlock()
	r.stopProcess()
	r.publish(hysteria.Status{State: hysteria.Stopped}, socks5.Client{})
}
func (r *Runner) Status() hysteria.Status { r.mu.RLock(); defer r.mu.RUnlock(); return r.status }
func (r *Runner) SOCKS() socks5.Client    { r.mu.RLock(); defer r.mu.RUnlock(); return r.proxy }
func (r *Runner) Available() bool         { return r.Status().State == hysteria.Connected }
func (r *Runner) UDPAvailable() bool {
	st := r.Status()
	return st.State == hysteria.Connected && st.UDPEnabled
}
func (r *Runner) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	if !r.Available() {
		return nil, errors.New("AmneziaWG: сервер недоступен")
	}
	c := r.SOCKS()
	return c.Connect(ctx, dst)
}
func (r *Runner) UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error) {
	if !r.UDPAvailable() {
		return nil, errors.New("AmneziaWG: сервер недоступен")
	}
	c := r.SOCKS()
	return c.UDPAssociate(ctx)
}
