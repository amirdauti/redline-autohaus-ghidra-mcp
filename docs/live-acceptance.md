# Live acceptance

## Tested environment

Windows, Ghidra 12.1.3 PUBLIC, JDK 21, Rust 1.88.0. Tests use generated synthetic firmware and private temporary projects. Customer firmware is never part of the test suite.

## Headless native acceptance

`tests/live-ghidra.mjs` passed against the real Rust executable and running Java/Ghidra bridge. It verified:

- MCP initialization and discovery of all 39 tools.
- Native language/compiler catalog, explicit selection of two different x86 compiler specs, and selection/import of a TriCore language. Invalid languages and incompatible compiler IDs are rejected.
- Project creation and raw binary import with exact source hash and complete byte readback.
- File-offset mapping, nonzero load address and subsequent image-base relocation.
- Bounded instruction and function creation, actual native decompilation of a known synthetic function, function rename/readback, reference and byte search.
- Data arrays, labels, comments, memory blocks, analysis settings, native auto-analysis and cancellation request.
- Read-only comments (including multiline text and absent types), defined-data containment/component pagination, and raw P-code for a known x86 constant. Instruction-count truncation, wrong instruction starts, defined data, unmapped addresses and stale identities are checked. Saved metadata remains unchanged and bytes read back identically, including after reopening the project.
- Explicit saving, packed-program export, project close/reopen, retained symbols/functions and unchanged source bytes.
- Rejection of stale identities, unreadable bytes, overlapping blocks, existing export destinations, overwriting defined code with data, and switching/closing with unsaved changes.

The synthetic TriCore import tests language/compiler selection, addressing and bytes. It does not establish an ECU memory layout or validate the semantics of TriCore machine code. The x86 fixture establishes native decompiler integration only.

The cancellation test accepts a job that finishes before cancellation arrives; a requested cancellation does not make partial analysis disappear. Save remains explicit. This test does not prove every analyzer responds promptly to cancellation.

Windows automatic startup also passed the full native test from a stopped bridge. MCP initialized and listed tools before Java startup; the first native call launched Ghidra. After the analysis workflow, the Rust client exited with both standard output streams closed while Java remained running. A new client reused that bridge. CI repeats cold startup and connection reuse.

## Transport and native guard checks

Rust tests run the actual MCP stdio server with a synthetic mailbox peer. They cover schema validation, all tool dispatches, locking, deadlines, malformed/partial/oversized responses, identity mismatches, and preservation of uncertain outcomes. They are not native Ghidra acceptance.

Connection regressions also cover MCP discovery while the bridge is offline or owned, explicit reconnection in the same client after startup/owner release, invalid arguments leaving stale evidence untouched, and no relaunch after timeout, cancellation, malformed responses, uncertain mutations or interrupted startup. Inspection response validation checks result bounds, pagination, contiguous instruction addresses, unsigned varnode offsets and truncation flags.

Windows startup regressions keep a synthetic descendant alive with inherited helper pipes. They verify readiness without waiting for pipe EOF, then require MCP process exit and stdout/stderr EOF while that descendant still runs. The native test also requires clean client shutdown within five seconds.

`BridgeGuardsTest.java` exercises real Java parsing, validation and OS file locks, including duplicate JSON keys, stale state and retained ownership after stop requests. It does not substitute mocked Ghidra functions.

## GUI acceptance

The extension passed a separate native GUI harness using an isolated project, the actual RedlineMcpPlugin, ProgramManagerPlugin, CodeBrowser and GoToService. Before direct plugin loading, it verifies discovery through Ghidra's production ClassSearcher and confirms the class came from the packaged `RedlineGhidraMcp/lib/RedlineGhidraMcp.jar`. A local negative run using the old JAR name failed at that discovery assertion; the corrected package passed.

MCP calls imported two synthetic versions, switched programs, rejected stale navigation identities, added labels/comments, created bounded instruction/data definitions, saved, and navigated. The same read-only inspection assertions used headlessly passed in the GUI. The Java harness independently verified the CodeBrowser cursor, selected Original, and retention of both GUI programs after stopping the bridge. Only the harness-owned tool/project were closed, with no unsaved changes left at cleanup.

The harness uses the real plugin and GUI services with a hidden test window. It does not automate the extension-installation dialog or configuration/menu clicks. Run `scripts/test-gui.ps1` for this test and the native Java guard harness.

## Scope

The current release exposes 39 operations with the documented mode restrictions. GUI project creation/open/close are handled through the headless workflow and explicit handoff; cursor navigation requires GUI mode. Debugger, emulator, arbitrary scripts, firmware patching, arbitrary data structure/signature creation, and every third-party extension are outside this version. Additional operations require native API validation and acceptance tests.
