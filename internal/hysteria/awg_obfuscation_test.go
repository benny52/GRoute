package hysteria

import "testing"

func TestBoundSpecialHandshakePackets(t *testing.T) {
	for _, chain := range []string{"<r -1>", "<rd 999999999>", "<r 60000><rc 6000>", "<dz -12>", "<b 0xabc>", "<b 0x>"} {
		if safeIPacket(chain) {
			t.Errorf("unsafe special packet accepted: %s", chain)
		}
	}
	if !safeIPacket("<b 0xdeadbeef><r 32><rc 4><rd 4><t><dz 2>") {
		t.Error("ordinary obfuscation chain rejected")
	}
}
