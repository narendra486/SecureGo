package sandbox

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CommandRunner executes binaries without shell expansion to avoid injection.
type CommandRunner struct {
	AllowedDirs []string
	Timeout     time.Duration
}

// Run executes the binary with provided args after validating the path.
func (c CommandRunner) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	if !c.allowed(bin) {
		return nil, errors.New("binary not in allowed directories")
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{} // default to empty env to avoid leaks; caller can set explicitly.
	return cmd.CombinedOutput()
}

func (c CommandRunner) allowed(bin string) bool {
	if len(c.AllowedDirs) == 0 {
		return false
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		return false
	}
	for _, dir := range c.AllowedDirs {
		if strings.HasPrefix(abs, dir) {
			return true
		}
	}
	return false
}
