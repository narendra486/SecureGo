package secrets

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// LoadSSHVaultSecret attempts to decrypt a secret using ssh-vault CLI.
// It is optional and requires ssh-vault installed on PATH.
func LoadSSHVaultSecret(ctx context.Context, vaultFile string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh-vault", "view", vaultFile)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ssh-vault view: %w", err)
	}
	return out, nil
}
