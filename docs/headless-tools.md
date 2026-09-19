# Headless tool coverage

The server exposes 39 tools. All inspection and analysis operations run through native Ghidra APIs in headless mode. `go_to` requires a GUI CodeBrowser and returns unsupported headlessly. Project creation/open/close belong to headless mode; the GUI uses the project already open in its tool.

The new read-only tools add useful analysis detail:

| Tool | What it exposes | Useful for |
| --- | --- | --- |
| `ghidra_get_comments` | Stored EOL, pre, post, plate and repeatable comments, with truncation reporting | Retrieving prior findings and annotations |
| `ghidra_get_data` | Existing type definitions, bounded scalar representations and paginated immediate components | Inspecting arrays and structures without guessing their interpretation |
| `ghidra_get_pcode` | Structured raw instruction operations and varnodes | Following arithmetic, loads, stores and branches independently of decompiled C |

P-code is raw instruction semantics, without flow overrides or decompiler SSA. Data inspection reports the native definition already in the project; it does not establish a table's real function, units or scaling. All three tools require an active program identity, obey analysis busy/context guards, and do not alter bytes or metadata. See [schemas and bounds](bridge-protocol.md).

## Candidates for later additions

These are possible future tools, not implemented capabilities:

| Candidate | Purpose | Native work still required |
| --- | --- | --- |
| Inspect code units | Show code/data/undefined intervals with pagination | Address-range and overlay handling; native acceptance |
| Hash current memory | Verify a bounded live region against source bytes | Gaps, uninitialized blocks and aliases; cancellation and limits |
| Preview disassembly | Decode candidate instructions without changing the listing | Processor context, delay slots and precise no-write validation |
| Function body and register storage | Expose body ranges and calling convention details | Noncontiguous functions, stack/register storage and result bounds |
| Function control-flow graph | Return basic blocks and branch edges | Indirect flow, incomplete analysis and bounded graph traversal |
| Structures and signatures | Apply verified layouts and function types | Strict typed inputs, transactions, conflict checks and readback |

Adding a tool requires a typed MCP schema, native API implementation, bounded output, identity/ownership guards, and synthetic native tests. General script execution is not needed for these workflows.
