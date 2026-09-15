# Live acceptance

## Tested environment

Windows, Ghidra 12.1.3 PUBLIC, JDK 21, Rust 1.88.0. Tests use generated synthetic firmware and private temporary projects. Customer firmware is never part of the test suite.

## Headless native acceptance

`tests/live-ghidra.mjs` passed against the real Rust executable and running Java/Ghidra bridge. It verified:

- MCP initialization and discovery of all 36 tools.
- Native language/compiler catalog, explicit selection of two different x86 compiler specs, and selection/import of a TriCore language. Invalid languages and incompatible compiler IDs are rejected.
- Project creation and raw binary import with exact source hash and complete byte readback.
- File-offset mapping, nonzero load address and subsequent image-base relocation.
- Bounded instruction and function creation, actual native decompilation of a known synthetic function, function rename/readback, reference and byte search.
- Data arrays, labels, comments, memory blocks, analysis settings, native auto-analysis and cancellation request.
- Explicit saving, packed-program export, project close/reopen, retained symbols/functions and unchanged source bytes.
- Rejection of stale identities, unreadable bytes, overlapping blocks, existing export destinations, overwriting defined code with data, and switching/closing with unsaved changes.

The synthetic TriCore import tests language/compiler selection, addressing and bytes. It does not establish an ECU memory layout or validate the semantics of TriCore machine code. The x86 fixture establishes native decompiler integration only.

The cancellation test accepts a job that finishes before cancellation arrives; a requested cancellation does not make partial analysis disappear. Save remains explicit. This test does not prove every analyzer responds promptly to cancellation.

## Transport and native guard checks

Rust tests run the actual MCP stdio server with a synthetic mailbox peer. They cover schema validation, all tool dispatches, locking, deadlines, malformed/partial/oversized responses, identity mismatches, and preservation of uncertain outcomes. They are not native Ghidra acceptance.

`BridgeGuardsTest.java` exercises real Java parsing, validation and OS file locks, including duplicate JSON keys, stale state and retained ownership after stop requests. It does not substitute mocked Ghidra functions.

## GUI acceptance

The extension passed a separate native GUI harness using an isolated project, the actual RedlineMcpPlugin, ProgramManagerPlugin, CodeBrowser and GoToService. MCP calls imported two synthetic versions, switched programs, rejected stale navigation identities, added labels/comments, saved, and navigated. The Java harness independently verified the CodeBrowser cursor, selected Original, and retention of both GUI programs after stopping the bridge. Only the harness-owned tool/project were closed, with no unsaved changes left at cleanup.

The harness uses the real plugin and GUI services with a hidden test window. It does not automate the extension-installation dialog or configuration/menu clicks. Run `scripts/test-gui.ps1` for this test and the native Java guard harness.

## Scope

The initial release covers the documented 36 operations, not all Ghidra subsystems. GUI project creation/open/close are handled through the headless workflow and explicit handoff. Debugger, emulator, arbitrary scripts, firmware patching, arbitrary data structures/signatures, and every third-party extension are outside this version. Additional operations require native API validation and acceptance tests.
