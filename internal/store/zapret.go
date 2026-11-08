package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/lardan099/hyroute/internal/zapret"
)

// zapret.json holds «Обход DPI»: the services and sites that go through
// winws2 and the methods auto-pick found per network. No secrets. It is
// read as data only: the command line is built from HyRoute's own blocks
// (internal/zapret), so a hand-edited file cannot pass options to winws2.
const zapretFile = "zapret.json"

const maxZapretFile = 256 << 10

// LoadZapret reads zapret.json; a missing file is the bypass off.
func (s *Store) LoadZapret() (zapret.Settings, error) {
	b, err := s.readRegular(zapretFile, maxZapretFile)
	if errors.Is(err, os.ErrNotExist) {
		return zapret.Settings{}, nil
	}
	if err != nil {
		return zapret.Settings{}, fmt.Errorf("zapret.json: %w", err)
	}
	var z zapret.Settings
	if err := json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &z); err != nil {
		return zapret.Settings{}, fmt.Errorf("zapret.json: %w", err)
	}
	z.Normalize()
	if err := z.Validate(); err != nil {
		return zapret.Settings{}, fmt.Errorf("zapret.json: %w", err)
	}
	return z, nil
}

// SaveZapret writes zapret.json.
func (s *Store) SaveZapret(z zapret.Settings) error {
	z.Normalize()
	if err := z.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(z, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(s.path(zapretFile), b)
}
