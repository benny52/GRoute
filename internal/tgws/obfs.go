// Package tgws carries Telegram's MTProto over WebSocket: a client's
// obfuscated MTProto connection (a local MTProto proxy, or Telegram's own
// connection to a data center) goes to Telegram through the WebSocket
// endpoints of its web version (kwsN.web.telegram.org/apiws), which a DPI
// that blocks the data centers' addresses tends to let through. The data
// stays MTProto-encrypted end to end; the bridge only re-keys the
// obfuscation layer. A port of Flowseal's tg-ws-proxy (MIT).
package tgws

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"slices"
)

// The obfuscated transport's 64-byte init: 8 random bytes, a 32-byte key,
// a 16-byte IV, then (encrypted with them) the transport's tag and the
// data center.
const (
	initLen   = 64
	keyPos    = 8
	ivPos     = 40
	tagPos    = 56
	dcPos     = 60
	keyIVEnd  = 56
	keyIVSize = keyIVEnd - keyPos
)

// Transport tags.
const (
	ProtoAbridged     uint32 = 0xefefefef
	ProtoIntermediate uint32 = 0xeeeeeeee
	ProtoPadded       uint32 = 0xdddddddd
)

// Hello is what a client's init says, with the client side's ciphers.
type Hello struct {
	DC    int // 1..5, 203 (the data center), without the test offset
	Media bool
	Test  bool // a test data center (10000+)
	Proto uint32
	// dec decrypts what the client sends (already past the init), enc
	// encrypts what goes to it.
	dec, enc cipher.Stream
}

func ctr(key, iv []byte) cipher.Stream {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // a 32-byte key never fails
	}
	return cipher.NewCTR(b, iv)
}

func clientKey(k, secret []byte) []byte {
	if secret == nil {
		return k // Telegram's own connection: no proxy secret
	}
	h := sha256.Sum256(append(slices.Clone(k), secret...))
	return h[:]
}

// ReadHello reads a client's init with secret (nil: a connection without a
// proxy secret). ok is false when the init does not decode to a known
// transport (a wrong secret, not MTProto).
func ReadHello(init []byte, secret []byte) (Hello, bool) {
	if len(init) != initLen {
		return Hello{}, false
	}
	kiv := init[keyPos:keyIVEnd]
	dec := ctr(clientKey(kiv[:32], secret), kiv[32:])
	plain := make([]byte, initLen)
	dec.XORKeyStream(plain, init)
	tag := binary.LittleEndian.Uint32(plain[tagPos:])
	if tag != ProtoAbridged && tag != ProtoIntermediate && tag != ProtoPadded {
		return Hello{}, false
	}
	idx := int(int16(binary.LittleEndian.Uint16(plain[dcPos:])))
	h := Hello{Proto: tag, dec: dec}
	if idx < 0 {
		h.Media, idx = true, -idx
	}
	if idx >= 10000 {
		h.Test, idx = true, idx-10000
	}
	h.DC = idx
	rev := reversed(kiv)
	h.enc = ctr(clientKey(rev[:32], secret), rev[32:])
	return h, true
}

func reversed(b []byte) []byte {
	r := slices.Clone(b)
	slices.Reverse(r)
	return r
}

// relayInit makes the init of the connection to Telegram for a transport
// and a data center index (negative: media), with that side's ciphers:
// enc for what goes to Telegram (past the init), dec for what comes back.
func relayInit(proto uint32, dcIdx int16) (init []byte, enc, dec cipher.Stream) {
	init = make([]byte, initLen)
	for {
		if _, err := rand.Read(init); err != nil {
			panic(err)
		}
		if !reservedStart(init) {
			break
		}
	}
	enc = ctr(init[keyPos:ivPos], init[ivPos:keyIVEnd])
	ks := make([]byte, initLen)
	enc.XORKeyStream(ks, make([]byte, initLen)) // the keystream of the init
	var tail [8]byte
	binary.LittleEndian.PutUint32(tail[0:], proto)
	binary.LittleEndian.PutUint16(tail[4:], uint16(dcIdx))
	if _, err := rand.Read(tail[6:]); err != nil {
		panic(err)
	}
	for i := range tail {
		init[tagPos+i] = tail[i] ^ ks[tagPos+i]
	}
	rev := reversed(init[keyPos:keyIVEnd])
	dec = ctr(rev[:32], rev[32:])
	return init, enc, dec
}

// reservedStart: an init a server would take for another protocol (HTTP,
// TLS, the plain transports).
func reservedStart(b []byte) bool {
	if b[0] == 0xef {
		return true
	}
	switch string(b[:4]) {
	case "HEAD", "POST", "GET ", "OPTI", "\xee\xee\xee\xee", "\xdd\xdd\xdd\xdd", "\x16\x03\x01\x02":
		return true
	}
	return b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0
}

// dcIndex is a data center's index in an init: negative for media, 10000
// on for test.
func dcIndex(dc int, media, test bool) int16 {
	if test {
		dc += 10000
	}
	if media {
		dc = -dc
	}
	return int16(dc)
}
