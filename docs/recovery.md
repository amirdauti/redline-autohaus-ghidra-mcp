# Mailbox recovery

MCP initialization and tool discovery no longer require a running or unowned native bridge. A tool error saying the bridge is offline or another client owns the mailbox occurs before dispatch. Start the bridge or disconnect the owning client, then explicitly call `ghidra_status` again in the same MCP session. No pending request is created for that failed attempt. A connected client retains ownership until it disconnects; the bridge stays alive.

Cold startup occurs during the first native tool call; configure the client tool timeout to cover startup plus the request (120 seconds with the default launcher/request bounds). If startup fails or is cancelled after the launcher may have run, that MCP session refuses to launch again even if there is no pending request. Inspect the launch logs and process record first: a Java descendant may still be alive. Reconcile that process, verify that no unfinished exchange exists, then restart the MCP client. A running confirmed bridge can be reused. Do not interpret a client timeout as proof that startup failed.

The following procedure applies when a request was dispatched or stale mailbox evidence exists. Every native call checks those guards before reconnecting or launching; an offline bridge does not make uncertain state safe to reuse.

The client records a durable `client.pending` marker before publishing a command. It removes that marker only after validating the matching response. A timed-out command may already have changed Ghidra; do not repeat it based on the timeout alone.

1. Stop the MCP client using that mailbox.
2. Inspect its last request, any response, and the active Ghidra project. Check whether a creation, annotation, save, or import completed. Preserve these files as a private incident record.
3. Request bridge stop with the `stop` sentinel. Allow active native work to finish or cancel analysis through the existing connection if it remains usable. Confirm the bridge process has exited or the GUI bridge reports stopped.
4. Inspect project state directly in Ghidra or through a separate read-only recovery workflow. Identify created programs by their domain path and source hash. Do not recreate a project or import until its actual state is established.
5. Once state is reconciled and both processes have released their locks, move the specific stale request/response/pending files into a private recovery directory. Do not delete project files or blanket-clear a mailbox.
6. Restart the bridge and client. Read project/program identity again and verify affected data before continuing.

Zero-length `client.lock` and `bridge.lock` files can remain after processes exit; OS locks, not file existence, determine ownership. Startup never clears evidence of an unfinished exchange.
