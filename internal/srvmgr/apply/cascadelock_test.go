package apply

import (
	"context"
	"errors"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// chainsOnly is a store with cascades only: keepsCascade asks nothing else.
type chainsOnly struct {
	Store
	chains []model.Chain
}

func (c chainsOnly) ListChains(context.Context) ([]model.Chain, error) { return c.chains, nil }

const linkedConfig = `listen: :443
auth:
  type: password
  password: fake-pass
outbounds:
  - name: cascade
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
  - name: direct
    type: direct
`

// A config of a cascade's entry keeps the link's outbound first and as it
// is: dropped (an old revision, the editor), its clients would go out
// from the entry while the link's checks say it works.
func TestKeepsCascade(t *testing.T) {
	x := &applier{Deps{Store: chainsOnly{chains: []model.Chain{{Nodes: []int64{1, 2}, Links: []model.ChainLink{{State: model.LinkActive}}}}}}}
	ctx := context.Background()
	dropped := "listen: :443\nauth:\n  type: password\n  password: fake-pass\noutbounds:\n  - name: direct\n    type: direct\n"
	var fe *model.FieldError
	if err := x.keepsCascade(ctx, 1, []byte(linkedConfig), []byte(dropped)); !errors.As(err, &fe) || fe.Field != "outbounds" {
		t.Fatalf("dropped: %v", err)
	}
	if err := x.keepsCascade(ctx, 1, []byte(linkedConfig), []byte(linkedConfig)); err != nil {
		t.Fatal(err)
	}
	// The exit of the chain, and a server of a link not deployed, are free.
	if err := x.keepsCascade(ctx, 2, []byte(linkedConfig), []byte(dropped)); err != nil {
		t.Fatal(err)
	}
	x.Store = chainsOnly{chains: []model.Chain{{Nodes: []int64{1, 2}, Links: []model.ChainLink{{State: model.LinkNew}}}}}
	if err := x.keepsCascade(ctx, 1, []byte(linkedConfig), []byte(dropped)); err != nil {
		t.Fatal(err)
	}
}
