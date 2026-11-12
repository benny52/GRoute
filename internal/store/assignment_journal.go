package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const assignmentJournal = "assignments-pending.sealed"

func (s *Store) BeginAssignments(files map[string]RawFile) error {
	if _, err := os.Lstat(s.path(assignmentJournal)); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		return errors.New("Ожидает восстановления предыдущая операция с назначениями. Перезапустите программу")
	}
	data, err := json.Marshal(files)
	if err != nil {
		return err
	}
	sealed, err := seal(data)
	if err != nil {
		return err
	}
	if len(sealed) > maxUndoBytes {
		return errors.New("Данные назначения слишком велики для безопасного восстановления")
	}
	return writeAtomic(s.path(assignmentJournal), sealed)
}

func (s *Store) EndAssignments() error { return os.Remove(s.path(assignmentJournal)) }

// A crash before the journal is removed discards the incomplete operation.
// Restore every file before deleting the journal; this is safe to retry.
func (s *Store) recoverAssignments() error {
	data, err := s.readRegular(assignmentJournal, maxUndoBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	data, err = unseal(data)
	if err != nil {
		return err
	}
	var files map[string]RawFile
	if err = json.Unmarshal(data, &files); err != nil {
		return err
	}
	for name := range files {
		switch name {
		case "settings.json", "rulesets.json", "profiles.json", "subscriptions.json", "proxies.json", "groups.json":
		default:
			return fmt.Errorf("Недопустимый файл в журнале назначений")
		}
	}
	for name, file := range files {
		if err := s.WriteRaw(name, file); err != nil {
			return err
		}
	}
	return s.EndAssignments()
}
