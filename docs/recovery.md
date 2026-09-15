# Mailbox recovery

The client records a durable `client.pending` marker before publishing a command. It removes that marker only after validating the matching response. A timed-out command may already have changed Ghidra; do not repeat it based on the timeout alone.

1. Stop the MCP client using that mailbox.
2. Inspect its last request, any response, and the active Ghidra project. Check whether a creation, annotation, save, or import completed. Preserve these files as a private incident record.
3. Request bridge stop with the `stop` sentinel. Allow active native work to finish or cancel analysis through the existing connection if it remains usable. Confirm the bridge process has exited or the GUI bridge reports stopped.
4. Inspect project state directly in Ghidra or through a separate read-only recovery workflow. Identify created programs by their domain path and source hash. Do not recreate a project or import until its actual state is established.
5. Once state is reconciled and both processes have released their locks, move the specific stale request/response/pending files into a private recovery directory. Do not delete project files or blanket-clear a mailbox.
6. Restart the bridge and client. Read project/program identity again and verify affected data before continuing.

Zero-length `client.lock` and `bridge.lock` files can remain after processes exit; OS locks, not file existence, determine ownership. Startup never clears evidence of an unfinished exchange.
