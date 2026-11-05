package relay

import (
	"net/netip"
	"sync"
	"time"
)

// Server-first destinations. A sniffed connection whose client sent
// nothing until the timeout, after which the server spoke first, goes to a
// protocol where the client waits for the server's greeting (game servers,
// databases, mail and the like on ports DefaultServerFirstPorts lacks).
// No name can come from such a client, so later connections to the same
// address and port wait only silentWait: long enough for a client that
// does talk first to be seen (its bytes arrive from the local relay's
// accept within milliseconds), which forgets the address again. The
// connections get the route they got before, without the wait. The set is
// in memory only and holds addresses, never names.
const (
	silentWait = 30 * time.Millisecond
	silentTTL  = time.Hour
	silentMax  = 4096
)

type silentSet struct {
	mu sync.Mutex
	m  map[netip.AddrPort]time.Time // until
}

func (s *silentSet) has(dst netip.AddrPort, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.m[dst]
	if ok && now.After(until) {
		delete(s.m, dst)
		return false
	}
	return ok
}

func (s *silentSet) add(dst netip.AddrPort, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[netip.AddrPort]time.Time)
	}
	if _, ok := s.m[dst]; !ok && len(s.m) >= silentMax {
		for k, until := range s.m {
			if now.After(until) {
				delete(s.m, k)
			}
		}
		for k := range s.m {
			if len(s.m) < silentMax {
				break
			}
			delete(s.m, k)
		}
	}
	s.m[dst] = now.Add(silentTTL)
}

func (s *silentSet) forget(dst netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, dst)
}
