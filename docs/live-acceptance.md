# Live acceptance

## Tested environment

Windows, Ghidra 12.1.3 PUBLIC, JDK 21, Rust 1.88.0. Tests use generated synthetic firmware and private temporary projects. Customer firmware is never part of the test suite.

## Headless native acceptance

`tests/live-ghidra.mjs` passed against the real Rust executable and running Java/Ghidra bridge. It verified:

- MCP initialization and discovery of all 85 tools, with 84 advertised headless capabilities.
- Native language/compiler catalog, explicit selection of two different x86 compiler specs, and selection/import of a TriCore language. Invalid languages and incompatible compiler IDs are rejected.
- Project creation and raw binary import with exact source hash and complete byte readback.
- File-offset mapping, nonzero load address and subsequent image-base relocation.
- Bounded instruction and function creation, actual native decompilation of a known synthetic function, function rename/readback, reference and byte search.
- Data arrays, labels, comments, memory blocks, analysis settings, native auto-analysis and cancellation request.
- Read-only comments (including multiline text and absent types), defined-data containment/component pagination, and raw P-code for a known x86 constant. Instruction-count truncation, wrong instruction starts, defined data, unmapped addresses and stale identities are checked. Saved metadata remains unchanged and bytes read back identically, including after reopening the project.
- Explicit saving, packed-program export, project close/reopen, retained symbols/functions and unchanged source bytes.
- Rejection of stale identities, unreadable bytes, overlapping blocks, existing export destinations, overwriting defined code with data, and switching/closing with unsaved changes.
- Native basic blocks/branch edges, multilevel call graphs and paths, scalar/instruction/P-code searches, and range-reference cursor pagination.
- Decompiler SSA snapshots and arithmetic def-use tracing, stale snapshot rejection, batch per-item outcomes, bounded literal code search, and normalized function matching with explicit non-equivalence semantics.
- Typed variable names/types and signatures, preservation of other parameters, structures with explicit gaps, enums, unions, typedefs, pointers, nested arrays and positive typed field references. Conflicts, overlaps and stale guards are rejected.
- Listing classification, byte hashes, preview without creating instructions, register-context metadata, guarded clearing and unchanged bytes. Bookmarks, all comment types, function tags and atomic rename/comment rollback.
- Saved-program memory/function comparison without switching the active program, imported-source identity rejection and current-region hashes.
- Save/close/reopen retains the new type definitions, edited parameter type/name, bookmarks, comments, tags and function names.

The full MCP workflow emulates synthetic x86 register arithmetic with private memory overrides, verifies step limits and unknown-input failures, and confirms unchanged program bytes and metadata. A generated generic TriCore fixture computes7+5=12 in two instructions through the MCP. `scripts/test-tricore.ps1` separately assembles, disassembles and emulates the same arithmetic on a disposable TC29x ProgramDB. This avoids BinaryLoader's extra processor-default blocks while preserving the import guard. Neither fixture establishes an ECU memory layout, OS/CSA behavior, peripheral model, timing model or live hardware execution.

The cancellation test accepts a job that finishes before cancellation arrives; a requested cancellation does not make partial analysis disappear. Save remains explicit. This test does not prove every analyzer responds promptly to cancellation.

Windows automatic startup also passed the full native test from a stopped bridge. MCP initialized and listed tools before Java startup; the first native call launched Ghidra. After the analysis workflow, the Rust client exited with both standard output streams closed while Java remained running. A new client reused that bridge. CI repeats cold startup and connection reuse.

## Transport and native guard checks

Rust tests run the actual MCP stdio server with a synthetic mailbox peer. They cover discovery and strict schemas for all85 tools, the original39 dispatch contracts, new result-validation regressions, locking, deadlines, malformed/partial/oversized responses, identity mismatches, and preservation of uncertain outcomes. All expanded tool implementations are exercised through the native harnesses; the synthetic peer is not native Ghidra acceptance.

Connection regressions also cover MCP discovery while the bridge is offline or owned, explicit reconnection in the same client after startup/owner release, invalid arguments leaving stale evidence untouched, and no relaunch after timeout, cancellation, malformed responses, uncertain mutations or interrupted startup. Inspection response validation checks result bounds, pagination, contiguous instruction addresses, unsigned varnode offsets and truncation flags.

Windows startup regressions keep a synthetic descendant alive with inherited helper pipes. They verify readiness without waiting for pipe EOF, then require MCP process exit and stdout/stderr EOF while that descendant still runs. The native test also requires clean client shutdown within five seconds.

`BridgeGuardsTest.java` exercises real Java parsing, validation and OS file locks, including duplicate JSON keys, stale state and retained ownership after stop requests. It does not substitute mocked Ghidra functions.

## GUI acceptance

The extension passed a separate native GUI harness using an isolated project, the actual RedlineMcpPlugin, ProgramManagerPlugin, CodeBrowser and GoToService. Before direct plugin loading, it verifies discovery through Ghidra's production ClassSearcher and confirms the class came from the packaged `RedlineGhidraMcp/lib/RedlineGhidraMcp.jar`. A local negative run using the old JAR name failed at that discovery assertion; the corrected package passed.

MCP calls imported two synthetic versions, switched programs, rejected stale identities, saved and navigated. The shared graph/search, SSA/data-flow, type/signature, isolated x86 emulation, listing/context, annotation and saved-comparison suites also run through the real GUI adapter. The Java harness independently verifies the CodeBrowser cursor, selected Original, and retention of both GUI programs after stopping the bridge. Only the harness-owned tool/project are closed, with no unsaved changes left at cleanup.

The harness uses the real plugin and GUI services with a hidden test window. It does not automate the extension-installation dialog or configuration/menu clicks. Run `scripts/test-gui.ps1` for this test and the native Java guard harness.

## Scope

The current release exposes85 operations with documented mode restrictions. GUI project creation/open/close use the headless workflow; cursor navigation requires GUI. The isolated function emulator, typed structures and guarded signatures are included. Live debugging, whole-device emulation, arbitrary scripts, firmware patching and arbitrary third-party extensions remain outside the interface. Only synthetic fixtures support the acceptance claims; no customer firmware is used in tests.
