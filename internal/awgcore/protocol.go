// Package awgcore defines the private, versioned pipe protocol between
// GRoute and its separately updatable AmneziaWG executable.
package awgcore

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"

	"github.com/lardan099/hyroute/internal/hysteria"
)

const Protocol = 1

type Request struct {
	Config string `json:"config"`
}

type Event struct {
	Type     string          `json:"type"`
	Version  int             `json:"version,omitempty"`
	Status   hysteria.Status `json:"status,omitempty"`
	Username string          `json:"username,omitempty"`
	Password string          `json:"password,omitempty"`
}

// Read one bounded JSON line, leaving subsequent messages on the stream.
func Read[T any](r *bufio.Reader, msg *T) error {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return err
	}
	if err := json.Unmarshal(line, msg); err != nil {
		return errors.New("некорректный ответ движка AmneziaWG")
	}
	return nil
}

func Reader(in io.Reader) *bufio.Reader {
	// Imported profiles are limited to 256 KiB before JSON escaping.
	return bufio.NewReaderSize(in, 2<<20)
}
