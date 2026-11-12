package awg

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tunnels"
)

const (
	probeInterval = 15 * time.Second
	peerTimeout   = 2 * probeInterval
)

type Runner struct {
	profile hysteria.Profile
	hooks   tunnels.Hooks
	life    sync.Mutex
	stop    func()
	mu      sync.RWMutex
	status  hysteria.Status
	client  socks5.Client
}

func NewRunner(p hysteria.Profile, h tunnels.Hooks) *Runner { return &Runner{profile: p, hooks: h} }

func (r *Runner) update(st hysteria.Status) {
	r.mu.Lock()
	r.status = st
	r.mu.Unlock()
	if r.hooks.OnStatus != nil {
		r.hooks.OnStatus(st)
	}
}

func (r *Runner) Start() (err error) {
	r.life.Lock()
	defer r.life.Unlock()
	if r.stop != nil {
		return nil
	}
	r.update(hysteria.Status{State: hysteria.Connecting})
	defer func() {
		if err != nil {
			r.update(hysteria.Status{State: hysteria.Failed, Kind: hysteria.ErrOther, Message: err.Error()})
		}
	}()
	// Revalidate stored profiles as well as freshly imported profiles.
	p, err := hysteria.ParseAWGConfig(r.profile.AWGConfig())
	if err != nil {
		return errors.New("AmneziaWG: недопустимые параметры профиля")
	}
	resolveCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	ips, err := net.DefaultResolver.LookupNetIP(resolveCtx, "ip", p.Host)
	done()
	if err != nil || len(ips) == 0 {
		return errors.New("AmneziaWG: не удалось определить IP сервера")
	}
	ip := ips[0].Unmap()
	cfg, err := configForDevice(p.AWGConfig(), ip)
	if err != nil {
		return err
	}
	if r.hooks.SetServerIPs != nil {
		if err := r.hooks.SetServerIPs([]netip.Addr{ip}); err != nil {
			return errors.New("AmneziaWG: не удалось исключить адрес сервера из перехвата")
		}
		defer func() {
			if err != nil {
				_ = r.hooks.SetServerIPs(nil)
			}
		}()
	}
	tun, ns, err := netstack.CreateNetTUN(cfg.addresses, cfg.dns, cfg.mtu)
	if err != nil {
		return errors.New("AmneziaWG: не удалось создать сетевой стек")
	}
	dev := device.NewDevice(tun, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer func() {
		if err != nil {
			dev.Close()
		}
	}()
	if err := dev.IpcSet(cfg.uapi); err != nil {
		return errors.New("AmneziaWG: движок отклонил параметры профиля")
	}
	if err := dev.Up(); err != nil {
		return errors.New("AmneziaWG: не удалось открыть UDP-сокет туннеля")
	}
	peer := dev.LookupPeer(cfg.public)
	if peer == nil {
		return errors.New("AmneziaWG: не удалось создать peer")
	}
	ctx, cancel := context.WithCancel(context.Background())
	network := stackNetwork{net: ns, addresses: cfg.addresses}
	proxy := &socks5.Server{
		Username: "groute", Password: rand.Text(), UDPNetwork: network,
		Dial: func(proto, addr string) (net.Conn, error) {
			dialCtx, done := context.WithTimeout(ctx, 8*time.Second)
			defer done()
			return ns.DialContext(dialCtx, proto, addr)
		},
	}
	if err := proxy.Listen("127.0.0.1:0"); err != nil {
		cancel()
		return errors.New("AmneziaWG: не удалось открыть локальный SOCKS5")
	}
	r.mu.Lock()
	r.client = socks5.Client{Server: proxy.Addr(), Username: proxy.Username, Password: proxy.Password}
	r.mu.Unlock()
	status := hysteria.Status{State: hysteria.Connecting, SOCKS: proxy.Addr(), ServerIPs: []netip.Addr{ip}, PinnedIP: ip}
	r.update(status)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		r.monitor(ctx, dev, peer, status)
	}()
	r.stop = func() {
		cancel()
		<-stopped
		proxy.Close()
		dev.Close()
	}
	return nil
}

// An open SOCKS listener proves nothing about the remote UDP peer. Use
// authenticated receive activity and actively re-handshake idle tunnels.
func (r *Runner) monitor(ctx context.Context, dev *device.Device, peer *device.Peer, st hysteria.Status) {
	started := time.Now()
	var lastSeen, lastProbe time.Time
	var handshake string
	var rx uint64
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		now := time.Now()
		state, err := dev.IpcGet()
		if err == nil {
			var seconds, nanos string
			var bytes uint64
			for line := range strings.SplitSeq(state, "\n") {
				k, v, _ := strings.Cut(line, "=")
				switch k {
				case "last_handshake_time_sec":
					seconds = v
				case "last_handshake_time_nsec":
					nanos = v
				case "rx_bytes":
					bytes, _ = strconv.ParseUint(v, 10, 64)
				}
			}
			if seconds != "" && seconds != "0" && (handshake != seconds+"."+nanos || rx != bytes) {
				lastSeen = now
				handshake, rx = seconds+"."+nanos, bytes
			}
		}
		stateNext := hysteria.Connecting
		msg := "Ожидаем рукопожатия AmneziaWG"
		if !lastSeen.IsZero() && now.Sub(lastSeen) < peerTimeout {
			stateNext, msg = hysteria.Connected, ""
		} else if now.Sub(started) >= peerTimeout {
			stateNext, msg = hysteria.Failed, "Сервер AmneziaWG не отвечает"
		}
		if st.State != stateNext || st.Message != msg {
			st.State, st.Message, st.UDPEnabled = stateNext, msg, stateNext == hysteria.Connected
			st.Kind = hysteria.ErrNone
			if stateNext == hysteria.Failed {
				st.Kind = hysteria.ErrTimeout
			}
			r.update(st)
		}
		if now.Sub(lastSeen) >= probeInterval && now.Sub(lastProbe) >= probeInterval {
			_ = peer.SendHandshakeInitiation(false)
			lastProbe = now
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Runner) Stop() {
	r.life.Lock()
	defer r.life.Unlock()
	if r.stop == nil {
		return
	}
	r.stop()
	r.stop = nil
	r.mu.Lock()
	r.client = socks5.Client{}
	r.mu.Unlock()
	r.update(hysteria.Status{State: hysteria.Stopped})
}

func (r *Runner) Status() hysteria.Status { r.mu.RLock(); defer r.mu.RUnlock(); return r.status }
func (r *Runner) SOCKS() socks5.Client    { r.mu.RLock(); defer r.mu.RUnlock(); return r.client }
func (r *Runner) Available() bool         { return r.Status().State == hysteria.Connected }
func (r *Runner) UDPAvailable() bool      { return r.Available() }

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

type stackNetwork struct {
	net       *netstack.Net
	addresses []netip.Addr
}

func (s stackNetwork) ListenUDP(ipv6 bool) (net.PacketConn, error) {
	for _, ip := range s.addresses {
		if ip.Is6() == ipv6 {
			return s.net.ListenUDPAddrPort(netip.AddrPortFrom(ip, 0))
		}
	}
	return nil, errors.New("семейство адресов отсутствует в профиле")
}
func (s stackNetwork) ResolveUDP(ctx context.Context, dst socks5.Addr) (*net.UDPAddr, error) {
	ip := dst.IP
	if !ip.IsValid() {
		resolveCtx, done := context.WithTimeout(ctx, 5*time.Second)
		defer done()
		ips, err := s.net.LookupContextHost(resolveCtx, dst.Host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("AmneziaWG: ошибка DNS в туннеле")
		}
		ip, err = netip.ParseAddr(ips[0])
		if err != nil {
			return nil, err
		}
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, dst.Port)), nil
}
