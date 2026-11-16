package app

import "os"

// Installation takes the same controller lock as edits spanning several files.
func (c *Controller) CopyInstallSettings(dst *os.Root) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Store.CopyInstallSettings(dst)
}
