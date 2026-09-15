# Repository collaboration

Build a public Rust MCP server with a documented Java adapter for Ghidra. Keep synthetic tests and live acceptance distinct. Never commit customer firmware, Ghidra projects, proprietary definitions, machine settings, logs, or third-party binaries.

The coordinating agent owns Git mutations, pushes, PRs, and merges. Use feature branches and PRs after bootstrap. Run formatting, clippy, tests, and live acceptance before claiming native support. Keep stdout reserved for MCP messages. Reject stale identities, ambiguous address mappings, and path collisions; never overwrite existing projects on creation. Use typed operations, never caller-supplied scripts or shell commands. Java metadata mutations require transactions. Read back results. Bridge uncertainty must stop automatic retries.

Required Rust checks: cargo fmt --all -- --check; cargo clippy --locked --all-targets -- -D warnings; cargo test --locked --all-targets. Java checks must compile against the installed Ghidra API and exercise synthetic import/save/reopen plus native inspection. Coordinator records final validation scope.
