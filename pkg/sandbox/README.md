# sandbox

Purpose: run subprocesses safely without shell injection.
When to use: executing fixed binaries with controlled args; never run user input through a shell.
Mitigates: command injection and runaway processes.

- `CommandRunner{AllowedDirs, Timeout}.Run(ctx, bin, args...)` executes the binary directly, blocks shell expansion, and enforces timeouts and path allowlists.
