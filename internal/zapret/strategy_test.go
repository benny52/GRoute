package zapret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrategyIDs(t *testing.T) {
	all := Broad(400, 1)
	if len(all) < 300 {
		t.Fatalf("only %d strategies", len(all))
	}
	families := map[string]bool{}
	for _, s := range all {
		id := s.ID()
		got, ok := ParseStrategy(id)
		if !ok || got != s {
			t.Fatalf("%s: %+v %v", id, got, ok)
		}
		m, ok := FindMethod(id)
		if !ok || len(m.tcp) == 0 || m.Name == "" {
			t.Fatalf("%s: %+v", id, m)
		}
		for _, inst := range m.tcp {
			// Every value is from the lists: no spaces, quotes or a second
			// option smuggled in.
			if strings.ContainsAny(inst, " \"'@\\") || strings.Contains(inst, "--") || strings.Contains(inst, "%") {
				t.Fatalf("%s: %q", id, inst)
			}
		}
		families[s.Split+"/"+map[bool]string{true: "fake", false: ""}[s.Fake != ""]] = true
		for _, n := range Neighbors(s) {
			if _, ok := ParseStrategy(n.ID()); !ok {
				t.Fatalf("neighbor %s of %s", n.ID(), id)
			}
		}
	}
	if len(families) < 9 {
		t.Fatalf("families %v", families)
	}
	// Repeatable for a seed, different for another.
	if Broad(5, 1)[0] != all[0] || Broad(5, 2)[0] == all[0] && Broad(5, 2)[1] == all[1] {
		t.Fatal("seed")
	}
	for id, s := range libraryAsStrategy {
		if !s.valid() || len(Neighbors(s)) < 10 {
			t.Fatalf("%s: %+v", id, s)
		}
		if _, ok := FindMethod(id); !ok {
			t.Fatalf("no library method %s", id)
		}
	}
}

func TestStrategyRefused(t *testing.T) {
	for _, id := range []string{
		"g:", "g:f=google", // a fake needs a fooling and repeats
		"g:f=google;o=ts;r=6;s=multisplit;p=1:lua-init=@x.lua",
		"g:f=../../x;o=ts;r=6",
		"g:f=google;o=ttl;r=6",        // ttl without a value
		"g:f=google;o=ts;t=3;r=6",     // a value without ttl
		"g:f=google;o=ts;r=60",        // too many
		"g:f=google;o=ts;r=06",        // not canonical
		"g:o=ts;r=6;s=multisplit;p=1", // a fooling with nothing to fool
		"g:s=multisplit;p=1;q=999;n=vk",
		"g:s=hostfakesplit;o=ts;r=6;h=evil.example",
		"g:r=6;o=ts;f=google", // keys out of order
		"g:f=google;o=ts;r=6;f=vk",
		"fake-seqovl", "", "g:s=multisplit;p=1 ;q=568;n=vk",
	} {
		if s, ok := ParseStrategy(id); ok {
			t.Errorf("%q accepted: %+v", id, s)
		}
	}
	if _, ok := FindMethod("g:s=multisplit;p=evil"); ok {
		t.Fatal("found")
	}
}

func TestStrategyNameAndBuild(t *testing.T) {
	s := Strategy{Fake: "w_ya_ru", Fool: "md5", Repeats: 6, Split: "multisplit", Pos: "midsld", Seqovl: 568, Pattern: "w_gosuslugi_ru"}
	if !s.valid() {
		t.Fatal("invalid")
	}
	if n := s.Name(); n != "Фейк ya.ru (TCP MD5, ×6) + разрез на середине домена с перекрытием gosuslugi.ru" {
		t.Fatalf("%q", n)
	}
	dir, lists := t.TempDir(), t.TempDir()
	if err := WriteLists(lists, nil, nil); err != nil {
		t.Fatal(err)
	}
	args, err := Build(BuildConfig{Dir: dir, Lists: lists, Plans: map[Target]Plan{YouTube: {Methods: []string{s.ID(), "fake"}, Circular: true}}})
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(args, " ")
	for _, want := range []string{
		"--blob=w_gosuslugi_ru:@" + filepath.Join(lists, "fake_w_gosuslugi_ru.bin"),
		"--blob=w_ya_ru:@" + filepath.Join(lists, "fake_w_ya_ru.bin"),
		"--lua-desync=fake:blob=w_ya_ru:tcp_ts=-1000:tcp_md5:repeats=6:strategy=1",
		"--lua-desync=multisplit:pos=midsld:seqovl=568:seqovl_pattern=w_gosuslugi_ru:strategy=1",
		"--lua-desync=fake:blob=google_tls:tcp_ts=-1000:tcp_md5:repeats=7:strategy=2",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("no %q in\n%s", want, CommandLine(args))
		}
	}
	// The made fakes: one TLS record each, small enough for one packet.
	for _, w := range WhiteNames[1:] {
		b, err := os.ReadFile(filepath.Join(lists, fakeFile(whiteKey(w))))
		if err != nil || !looksLikeHello(b, w) || len(b) > 1300 || len(b) < 200 || int(b[3])<<8|int(b[4]) != len(b)-5 {
			t.Fatalf("%s: %d bytes, %v", w, len(b), err)
		}
	}
}
