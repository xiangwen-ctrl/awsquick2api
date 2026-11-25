//go:build !windows

package tray

// Controller is a no-op tray handle on non-Windows platforms.
type Controller struct{}

func Start(_ Config) (*Controller, error)           { return &Controller{}, nil }
func (*Controller) Stop()                           {}
func OpenTarget(_ string) error                     { return nil }
func CopyClipboardText(_ string) error              { return nil }
func ShowErrorDialog(_, _ string)                   {}
func IsAutostartEnabled(_, _ string) bool           { return false }
func SetAutostartEnabled(_, _ string, _ bool) error { return nil }
func AcquireSingleInstance(_ string) (func(), bool) { return func() {}, false }
