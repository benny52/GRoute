package tgws

import "encoding/binary"

// splitter cuts the stream going to Telegram into the transport's packets:
// over WebSocket each packet travels as a message of its own, as the web
// version sends them. It reads the lengths from the plain bytes and cuts
// the encrypted ones at the same places. A length it cannot make sense of
// turns it off: the rest goes as it comes.
type splitter struct {
	proto    uint32
	enc      []byte // encrypted bytes not yet sent
	plain    []byte // the same, plain
	disabled bool
}

func newSplitter(proto uint32) *splitter { return &splitter{proto: proto} }

// add takes the next encrypted bytes and their plain form and returns the
// whole packets now complete.
func (s *splitter) add(enc, plain []byte) [][]byte {
	if len(enc) == 0 {
		return nil
	}
	if s.disabled {
		return [][]byte{append([]byte(nil), enc...)}
	}
	s.enc = append(s.enc, enc...)
	s.plain = append(s.plain, plain...)
	var out [][]byte
	off := 0
	for off < len(s.enc) {
		n, ok := s.next(off)
		if !ok {
			break // not all there yet
		}
		if n <= 0 {
			out = append(out, append([]byte(nil), s.enc[off:]...))
			off = len(s.enc)
			s.disabled = true
			break
		}
		out = append(out, append([]byte(nil), s.enc[off:off+n]...))
		off += n
	}
	s.enc = append(s.enc[:0], s.enc[off:]...)
	s.plain = append(s.plain[:0], s.plain[off:]...)
	return out
}

// flush returns what is left (the client closed mid-packet).
func (s *splitter) flush() []byte {
	if len(s.enc) == 0 {
		return nil
	}
	b := append([]byte(nil), s.enc...)
	s.enc, s.plain = s.enc[:0], s.plain[:0]
	return b
}

// next is the length of the packet at off; ok false: more bytes needed;
// a length <= 0: not one this transport makes.
func (s *splitter) next(off int) (int, bool) {
	avail := len(s.plain) - off
	if avail <= 0 {
		return 0, false
	}
	p := s.plain[off:]
	switch s.proto {
	case ProtoAbridged:
		hdr, n := 1, int(p[0]&0x7f)*4
		if p[0]&0x7f == 0x7f {
			if avail < 4 {
				return 0, false
			}
			hdr, n = 4, int(uint32(p[1])|uint32(p[2])<<8|uint32(p[3])<<16)*4
		}
		if n <= 0 {
			return 0, true
		}
		if avail < hdr+n {
			return 0, false
		}
		return hdr + n, true
	case ProtoIntermediate, ProtoPadded:
		if avail < 4 {
			return 0, false
		}
		n := int(binary.LittleEndian.Uint32(p) & 0x7fffffff)
		if n <= 0 || n > 16<<20 {
			return 0, true
		}
		if avail < 4+n {
			return 0, false
		}
		return 4 + n, true
	}
	return 0, true
}
