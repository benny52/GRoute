package app

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/relay"
	"github.com/lardan099/hyroute/internal/store"
)

// Proxies for a subscription: with Subscription.Proxies set, every server
// of the subscription gets a local proxy of its own, kept in step with it.
// A new server gets the first free port from Proxies.Port up, a server
// keeps its port while it stays, and a server that leaves (or is only
// kept as «нет в подписке») takes its proxy along. The proxies are
// ordinary ones (store.LocalProxy with Source "sub:<id>"): they open while
// HyRoute is connected and start their servers like rules do.

// maxSubProxies caps the proxies one subscription makes: every one starts
// a process of its own while HyRoute is connected.
const maxSubProxies = 200

// SubProxiesInput is the subscription page's form.
type SubProxiesInput struct {
	Port     int    `json:"port"`
	LAN      bool   `json:"lan"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// SetSubscriptionProxies turns the proxies of subscription id on (in set)
// or off (in nil) and makes them at once.
func (c *Controller) SetSubscriptionProxies(id string, in *SubProxiesInput) error {
	var conf *store.SubProxies
	if in != nil {
		conf = &store.SubProxies{Port: in.Port, LAN: in.LAN, Username: strings.TrimSpace(in.Username), Password: in.Password}
		if err := validSubProxies(*conf); err != nil {
			return err
		}
	}
	c.mu.Lock()
	if c.proxiesBroken != nil {
		c.mu.Unlock()
		return fmt.Errorf("proxies.json не загружен, прокси не меняются: %v", c.proxiesBroken)
	}
	i := slices.IndexFunc(c.subs, func(s store.Subscription) bool { return s.ID == id })
	if i < 0 {
		c.mu.Unlock()
		return errors.New("подписка не найдена")
	}
	old := c.subs[i].Proxies
	subs := slices.Clone(c.subs)
	subs[i].Proxies = conf
	if err := c.saveSubsLocked(subs); err != nil {
		c.mu.Unlock()
		return err
	}
	c.subs = subs
	if conf != nil {
		c.Redactor.SetGroup("subproxy:"+id, conf.Password)
		if err := c.restampSubProxiesLocked("sub:"+id, old, *conf); err != nil {
			c.mu.Unlock()
			return err
		}
	}
	err := c.syncSubProxiesLocked()
	c.mu.Unlock()
	c.changed()
	return err
}

// restampSubProxiesLocked gives the proxies a subscription made the access
// its form now sets (from the local network, the login and password):
// changed there, it changes on every port at once, not only on the ports
// of servers that come later. Turned on for the network, a proxy on a
// port the firewall opens for HyRoute in any network is made again on
// another (syncSubProxiesLocked). c.mu held.
func (c *Controller) restampSubProxiesLocked(source string, old *store.SubProxies, conf store.SubProxies) error {
	if old != nil && old.LAN == conf.LAN && old.Username == conf.Username && old.Password == conf.Password {
		return nil
	}
	changed := false
	next := make([]store.LocalProxy, 0, len(c.proxies))
	for _, p := range c.proxies {
		if p.Source == source {
			if conf.LAN && p.Port >= relay.PortMin && p.Port <= relay.PortMax {
				changed = true
				continue
			}
			if p.LAN != conf.LAN || p.Username != conf.Username || p.Password != conf.Password {
				p.LAN, p.Username, p.Password = conf.LAN, conf.Username, conf.Password
				normalizeProxy(&p)
				changed = true
			}
		}
		next = append(next, p)
	}
	if !changed {
		return nil
	}
	if err := c.saveProxiesLocked(next); err != nil {
		return err
	}
	for _, p := range next {
		if p.Source == source {
			c.Redactor.SetGroup("proxy:"+p.ID, p.Password)
		}
	}
	go c.syncProxiesLife() // the open ports take the new access
	return nil
}

func validSubProxies(p store.SubProxies) error {
	if p.Port < 1024 || p.Port > 65535 {
		return errors.New("первый порт — от 1024 до 65535")
	}
	if (p.Username == "") != (p.Password == "") {
		return errors.New("укажите и логин, и пароль, или оставьте оба пустыми")
	}
	if strings.ContainsAny(p.Username, ":") {
		return errors.New("в логине не может быть двоеточия")
	}
	if len(p.Username) > 255 || len(p.Password) > 255 {
		return errors.New("логин и пароль — не длиннее 255 символов")
	}
	if p.LAN && p.Username == "" {
		return errLANNoLogin
	}
	if p.LAN && p.Port >= relay.PortMin && p.Port <= relay.PortMax {
		return fmt.Errorf("для доступа из локальной сети выберите порты от 1024 до %d: порты %d–%d брандмауэр Windows открывает для HyRoute в любой сети", relay.PortMin-1, relay.PortMin, relay.PortMax)
	}
	return nil
}

// syncSubProxiesLocked makes the proxies of the subscriptions match their
// servers (c.mu held). It saves and opens them only when something
// changed; the ports open in the background, once c.mu is free.
func (c *Controller) syncSubProxiesLocked() error {
	// With a file not loaded the servers or the subscriptions are not
	// known: nothing is made, and above all nothing removed.
	if c.proxiesBroken != nil || c.profilesBroken != nil || c.subsBroken != nil {
		return nil
	}
	confs := map[string]*store.SubProxies{}
	for _, s := range c.subs {
		if s.Proxies != nil {
			confs["sub:"+s.ID] = s.Proxies
		}
	}
	changed := false
	have := map[string]bool{} // server IDs with a proxy
	used := map[int]bool{}
	next := make([]store.LocalProxy, 0, len(c.proxies))
	for _, p := range c.proxies {
		if p.Source != "" {
			srv := c.profiles.Find(p.Profile)
			if confs[p.Source] == nil || srv == nil || srv.Source != p.Source || srv.Missing || have[srv.ID] {
				changed = true
				continue
			}
			have[srv.ID] = true
			if p.Name != srv.Name {
				p.Name, changed = srv.Name, true
			}
		}
		used[p.Port] = true
		next = append(next, p)
	}
	var full []string
	for _, s := range c.subs {
		conf := s.Proxies
		if conf == nil {
			continue
		}
		source := "sub:" + s.ID
		n := 0
		for _, p := range next {
			if p.Source == source {
				n++
			}
		}
		port := conf.Port
		for _, srv := range c.profiles.List {
			if srv.Source != source || srv.Missing || have[srv.ID] {
				continue
			}
			if n >= maxSubProxies {
				full = append(full, s.Name)
				break
			}
			for used[port] || conf.LAN && port >= relay.PortMin && port <= relay.PortMax {
				port++
			}
			if port > 65535 {
				full = append(full, s.Name)
				break
			}
			p := store.LocalProxy{ID: newID(), Name: srv.Name, Enabled: true, Profile: srv.ID, Port: port,
				LAN: conf.LAN, Username: conf.Username, Password: conf.Password, Source: source}
			normalizeProxy(&p)
			next = append(next, p)
			used[port], have[srv.ID], changed = true, true, true
			n++
		}
	}
	if len(full) > 0 {
		c.Log.Warn("subscription proxies: no more ports or the limit reached", "subscriptions", strings.Join(full, ", "), "limit", maxSubProxies)
	}
	if !changed {
		return nil
	}
	if err := c.saveProxiesLocked(next); err != nil {
		return err
	}
	for _, p := range next {
		if p.Source != "" {
			c.Redactor.SetGroup("proxy:"+p.ID, p.Password)
		}
	}
	c.applyRoutingLocked() // their servers must run
	go c.syncProxiesLife()
	return nil
}

// subProxyRange is "N прокси, порты A–B" of a subscription (c.mu held).
func (c *Controller) subProxySummaryLocked(id string) (n, from, to int) {
	for _, p := range c.proxies {
		if p.Source != "sub:"+id {
			continue
		}
		if n == 0 || p.Port < from {
			from = p.Port
		}
		to = max(to, p.Port)
		n++
	}
	return n, from, to
}
