//go:build !windows

package update

// PinFile does nothing outside Windows: HyRoute is installed into a folder
// only root may write (macOS) and never starts its own file again from
// elsewhere.
func PinFile(string) (func(), error) { return func() {}, nil }
