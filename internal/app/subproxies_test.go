package app

import (
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/store"
)

// subProxies are the proxies kept for subscription id, by server name.
func subProxies(c *Controller, id string) map[string]store.LocalProxy {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]store.LocalProxy{}
	for _, p := range c.proxies {
		if p.Source == "sub:"+id {
			out[p.Name] = p
		}
	}
	return out
}

func TestSubscriptionProxies(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@one.example:443#ONE\nhy2://a@two.example:443#TWO\nhy2://a@three.example:443#THREE\n"
	v := addSub(t, c, &body)
	// A proxy of the user's holds the first port: the subscription's go
	// around it.
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Name: "mine", Enabled: true, Port: 20001}}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetSubscriptionProxies(v.ID, &SubProxiesInput{Port: 20000}); err != nil {
		t.Fatal(err)
	}
	ps := subProxies(c, v.ID)
	if len(ps) != 3 || ps["ONE"].Port != 20000 || ps["TWO"].Port != 20002 || ps["THREE"].Port != 20003 || !ps["ONE"].Enabled {
		t.Fatalf("%+v", ps)
	}
	sv := c.Subscriptions()[0]
	if sv.ProxyCount != 3 || sv.ProxyFrom != 20000 || sv.ProxyTo != 20003 || sv.Proxies == nil {
		t.Fatalf("%+v", sv)
	}

	// TWO leaves, FOUR comes: TWO's proxy goes with it (its server is not
	// kept for it), the others keep their ports, FOUR takes the freed one.
	body = "hy2://a@one.example:443#ONE\nhy2://a@three.example:443#THREE\nhy2://a@four.example:443#FOUR\n"
	if ms, err := c.UpdateSubscription(v.ID); err != nil || ms.Removed != 1 || ms.MissingKept != 0 {
		t.Fatalf("%+v %v", ms, err)
	}
	ps = subProxies(c, v.ID)
	if len(ps) != 3 || ps["ONE"].Port != 20000 || ps["THREE"].Port != 20003 || ps["FOUR"].Port != 20002 {
		t.Fatalf("%+v", ps)
	}

	// The user may switch one off or move it, not delete it or point it
	// elsewhere.
	one := ps["ONE"]
	if err := c.DeleteProxy(one.ID); err == nil || !strings.Contains(err.Error(), "подписки") {
		t.Fatalf("deleted: %v", err)
	}
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{ID: one.ID, Name: "x", Enabled: false, Profile: "", Port: 21000}}); err != nil {
		t.Fatal(err)
	}
	if p := subProxies(c, v.ID)["ONE"]; p.Enabled || p.Port != 21000 || p.Profile != one.Profile || p.Source != one.Source {
		t.Fatalf("%+v", p)
	}

	// Off: every one of them goes, the user's stays.
	if err := c.SetSubscriptionProxies(v.ID, nil); err != nil {
		t.Fatal(err)
	}
	if ps := subProxies(c, v.ID); len(ps) != 0 || len(c.Proxies()) != 1 {
		t.Fatalf("%+v %+v", ps, c.Proxies())
	}
}

// The form's access (from the network, the login and password) changes on
// every proxy the subscription made, not only on the ones made later.
func TestSubscriptionProxiesAccessChanges(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@one.example:443#ONE\nhy2://a@two.example:443#TWO\n"
	v := addSub(t, c, &body)
	if err := c.SetSubscriptionProxies(v.ID, &SubProxiesInput{Port: 20000, LAN: true, Username: "u", Password: "old-pass"}); err != nil {
		t.Fatal(err)
	}
	check := func(lan bool, user, pass string) {
		t.Helper()
		ps := subProxies(c, v.ID)
		if len(ps) != 2 {
			t.Fatalf("%+v", ps)
		}
		for _, p := range ps {
			if p.LAN != lan || p.Username != user || p.Password != pass {
				t.Fatalf("%s: lan %v %q %q", p.Name, p.LAN, p.Username, p.Password)
			}
		}
	}
	check(true, "u", "old-pass")
	if err := c.SetSubscriptionProxies(v.ID, &SubProxiesInput{Port: 20000, LAN: true, Username: "u", Password: "new-pass"}); err != nil {
		t.Fatal(err)
	}
	check(true, "u", "new-pass")
	if err := c.SetSubscriptionProxies(v.ID, &SubProxiesInput{Port: 20000}); err != nil {
		t.Fatal(err)
	}
	check(false, "", "")
}

func TestSubscriptionProxiesGoWithIt(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@one.example:443#ONE\nhy2://a@two.example:443#TWO\n"
	v := addSub(t, c, &body)
	if err := c.SetSubscriptionProxies(v.ID, &SubProxiesInput{Port: 20000, LAN: true, Username: "u", Password: "secret-pw"}); err != nil {
		t.Fatal(err)
	}
	ps := subProxies(c, v.ID)
	if p := ps["ONE"]; !p.LAN || p.Username != "u" || p.Password != "secret-pw" || p.UDP != "off" {
		t.Fatalf("%+v", p)
	}
	if got := c.Redactor.Redact("pw secret-pw"); strings.Contains(got, "secret-pw") {
		t.Fatalf("password in a log line: %s", got)
	}
	// Its proxies do not keep its servers: they leave with it, all but ONE,
	// the main server, which stays as a manual one (as without proxies).
	if err := c.DeleteSubscription(v.ID); err != nil {
		t.Fatal(err)
	}
	if ps := c.Profiles(); len(ps) != 1 || ps[0].Name != "ONE" || ps[0].Source != "" || len(c.Proxies()) != 0 {
		t.Fatalf("%+v %+v", c.Profiles(), c.Proxies())
	}
}

func TestSubscriptionProxiesRefused(t *testing.T) {
	c, _ := newCtl(t)
	body := "hy2://a@one.example:443#ONE\n"
	v := addSub(t, c, &body)
	for _, in := range []SubProxiesInput{
		{Port: 80},
		{Port: 20000, LAN: true},                      // LAN without a login
		{Port: 20000, Username: "u"},                  // a login without a password
		{Port: 20000, Username: "a:b", Password: "p"}, // a colon
	} {
		if err := c.SetSubscriptionProxies(v.ID, &in); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	if err := c.SetSubscriptionProxies("nope", &SubProxiesInput{Port: 20000}); err == nil {
		t.Error("an unknown subscription")
	}
}
