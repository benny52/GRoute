package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// CopyInstallSettings copies a consistent set of configuration files into a
// fresh staging directory. Credentials and subscription snapshots stay sealed.
func (s *Store) CopyInstallSettings(dst *os.Root) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyOne := func(name string) error {
		b, err := readDataFile(s.path(name), maxRawBytes)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		f, err := dst.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(b)
		return errors.Join(writeErr, f.Close())
	}
	for name := range rawFiles {
		if err := copyOne(name); err != nil {
			return err
		}
	}
	if err := copyOne(zapretFile); err != nil {
		return err
	}
	entries, err := os.ReadDir(s.path("subs"))
	if err != nil {
		return err
	}
	if err := dst.Mkdir("subs", 0700); err != nil {
		return err
	}
	for _, entry := range entries {
		ext := filepath.Ext(entry.Name())
		id := strings.TrimSuffix(entry.Name(), ext)
		if (ext == ".cur" || ext == ".prev") && snapName(id) == id {
			if err := copyOne(filepath.Join("subs", entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
