# Headless tool coverage

The server exposes **85 tools**. Headless Ghidra supports **84**: `go_to` requires a GUI CodeBrowser. Project creation/open/close are headless operations; the GUI adapter uses the project already open in its tool. All 46 additions below share the native implementation between headless and GUI modes.

| Added capabilities | Tools | Contract |
| --- | --- | --- |
| Function structure, graphs and searches | 8 | [Research tools](research-tools.md) |
| Decompiler SSA, data-flow, batch reads, code search, matching and emulation | 9 | [Flow tools](flow-tools.md) |
| Variables, signatures, structures, unions, enums and typed data | 13 | [Type tools](type-tools.md) |
| Listing/memory/context, annotations and saved-program comparisons | 16 | [Utility tools](utility-tools.md) |

Use `get_pcode` for existing raw instruction semantics, and `get_high_pcode` for a bounded decompiler SSA snapshot. `trace_data_flow` follows that snapshot's value definitions and uses within a function, with explicit memory/call boundaries. Graphs follow existing resolved references. Incomplete graphs and missing matches do not prove that runtime behavior is absent.

Type and annotation edits are transactional, verify readback, and retain explicit save behavior. Variable selectors include native identity/storage and signatures require an expected existing declaration. Data types apply only to undefined storage. Listing repair rejects partial code units and function overlap. Preview, comparisons and emulation leave listing and bytes unchanged.

The isolated emulator requires explicit inputs and a stop instruction, with a step/time budget. Generated x86 and TriCore arithmetic fixtures exercise it; this does not establish a whole ECU emulator, peripheral model, live debugger or flashing capability. Function fingerprints intentionally abstract constants and addresses and serve only as matching candidates.

All tools retain strict schemas, explicit program identities, address spaces, bounded output and uncertainty guards. Caller-supplied scripts and shell commands are not part of this interface. See [native acceptance scope](live-acceptance.md) and [bridge protocol](bridge-protocol.md).
