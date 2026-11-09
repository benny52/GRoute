package apply

import (
	"context"
	"reflect"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// cascadeOutbound is the outbound a deployed cascade link puts first in
// the config of the server that sends through it (cascade.OutboundName;
// cascade is not imported here).
const cascadeOutbound = "cascade"

// chainLister is the store's list of cascades (the real store has it).
type chainLister interface {
	ListChains(ctx context.Context) ([]model.Chain, error)
}

// keepsCascade refuses a candidate that drops or changes the outbound of
// a deployed cascade link of the server, as the routing page does: the
// link's checks test its service, not the entry's config, and the entry's
// clients would go out from the entry itself while they say «работает».
// The link is removed on the cascades page.
func (x *applier) keepsCascade(ctx context.Context, serverID int64, cur, cand []byte) error {
	cl, ok := x.Store.(chainLister)
	if !ok {
		return nil
	}
	chains, err := cl.ListChains(ctx)
	if err != nil {
		return err
	}
	if !sendsThrough(chains, serverID) {
		return nil
	}
	a, err1 := hyconfig.ParseServer(cur)
	b, err2 := hyconfig.ParseServer(cand)
	if err1 != nil || err2 != nil {
		return nil // the other checks say what is wrong
	}
	var lock *hyconfig.Outbound
	for i := range a.Outbounds {
		if strings.EqualFold(a.Outbounds[i].Name, cascadeOutbound) {
			lock = &a.Outbounds[i]
		}
	}
	if lock == nil || len(b.Outbounds) > 0 && reflect.DeepEqual(b.Outbounds[0], *lock) {
		return nil
	}
	return &model.FieldError{Field: "outbounds", Msg: "Outbound «" + lock.Name + "» ведёт в каскад: он остаётся первым и без изменений. Чтобы убрать его, снимите связь на странице каскада."}
}

// sendsThrough reports whether server sends through a deployed link of a
// chain, as its entry or a relay (routing.Sender, not imported here).
func sendsThrough(chains []model.Chain, server int64) bool {
	for _, c := range chains {
		i := slices.Index(c.Nodes, server)
		if i >= 0 && i < len(c.Nodes)-1 && i < len(c.Links) && c.Links[i].State != model.LinkNew && c.Links[i].State != model.LinkFailed {
			return true
		}
	}
	return false
}
