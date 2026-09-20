# Read-only research tools

These tools inspect the current program's existing native analysis. Every request requires `expected_program_id`; stale identities fail before inspection. They do not decode bytes, create functions, run analysis or change the program. CPU addresses include their space, for example `ram:00400100`. File offsets are not accepted as addresses.

| Tool | Required fields beyond identity | Purpose |
| --- | --- | --- |
| `ghidra_get_function_details` | `address` | Containing function, body ranges, convention, return/parameter/local storage, and stack frame metadata. |
| `ghidra_get_control_flow` | `address` | Ghidra basic blocks and typed outgoing edges for the containing function. |
| `ghidra_get_call_graph` | `address` | Existing call-reference graph, with `direction`: `callees` (default), `callers`, or `both`. |
| `ghidra_find_call_paths` | `source`, `target` | Simple function paths through the native call-reference graph. |
| `ghidra_search_constants` | `value` | Unsigned hexadecimal scalar operand bit pattern; optional `scalar_bits` requires an exact width. |
| `ghidra_search_instructions` | `mnemonic` and/or `operand_contains` | Exact ASCII case-insensitive mnemonic and case-sensitive literal operand substring. Both filters, when supplied, must match. |
| `ghidra_search_pcode` | `opcode` | Exact uppercase raw native P-code opcode, such as `COPY` or `CALL`. |
| `ghidra_get_references_range` | `start`, `end` | References with source (`from`, default) or destination (`to`) in an inclusive CPU range. |

## Bounds and continuation

All operations have a five-second cooperative native time budget. Native calls that support a task monitor receive that deadline. Responses identify `truncated`, `truncation_reason`, and `continuation`. Large native metadata strings, pathological individual instructions, or results exceeding one million serialized characters fail explicitly rather than being silently clipped. This stays below the transport's eight-MiB limit even with UTF-8 expansion. Request bounds apply in both Rust and Java; native responses are validated before being returned to MCP.

Searches accept optional `start` and `end` together, in the same space and ordered inclusively. With neither, they scan existing instructions throughout mapped memory in native address order. They never search undecoded bytes. `cursor` resumes at the next unprocessed instruction, and must remain inside an explicit range. `limit` defaults to 100 and is capped at 200 matching instructions; `scan_limit` defaults to 20,000 and is capped at 100,000 instructions. A matching instruction is emitted once with its scalar matches or matching P-code indices. `search_pcode` uses raw instruction P-code without flow overrides, not decompiler SSA or high P-code. Individual instructions are capped at 32 operands, 128 scalar matches, and 1,024 P-code operations.

Reference queries default to 100 results (maximum 500) and 20,000 scanned references (maximum 100,000). Their continuation contains both `cursor` and `cursor_offset`; copy both into the next request with the same original range and direction. The offset addresses multiple references at one CPU address. Seeking past already returned references is separately time-bounded and reported as `cursor_skipped`. An individual address with more than 100,000 references is rejected. Pagination assumes native analysis remains unchanged between requests.

Function details apply `limit` (default 128, maximum 256) independently to body ranges, parameters and locals. Storage is the current native metadata, including exact register/stack pieces and unassigned/void flags; it does not assert an inferred C prototype is correct. Each storage description has at most 32 pieces. A truncated details response requires a larger limit or a narrower investigation; there is no opaque persistent cursor.

Control flow defaults to 128 blocks and 512 edges, capped at 256 and 2,048. Edges carry native flow type plus call/jump/conditional/computed/terminal/fallthrough flags, source block, destination block address, the exact `reference_target`, and referring instruction. `target_is_block` distinguishes resolved destination blocks from unresolved native target addresses. `target_in_function` distinguishes exits and calls. Blocks can cross a manually defined function boundary; `wholly_in_function` reports this explicitly. Missing native flow references remain missing.

Call graphs default to depth 2, 128 nodes and 512 edges, capped at depth 8, 256 nodes and 2,048 edges. Call paths default to depth 8 and ten paths, capped at depth 16 and 64 paths, with the same node/edge bounds. Both share a 100,000-step scan budget across traversal and path enumeration. They use call references to existing function entries, preserving the actual source instruction and native reference type. They do not resolve indirect calls, infer function-pointer values, treat arbitrary jumps as calls, or assume runtime reachability. Existing native references may themselves be incomplete or incorrect. Paths omit cycles and collapse multiple call sites between the same pair of functions for path enumeration; graph edges retain each call site.

`depth_limit_reached` and `frontier` identify nodes deliberately not expanded at the requested depth; this is separate from resource truncation. Resource-truncated graphs include restart guidance and frontier addresses. Query a frontier function separately or increase permitted bounds; there is no server-side graph session. An empty path list only means none was found in the returned bounded graph, not that no runtime path exists.

## Synthetic validation

`tests/native-research.mjs` exports `checkResearchTools(call, identity, fixture)` for the native GUI/headless acceptance harnesses. The generated x86 fixture includes a conditional branch, a direct call, distinct immediate constants, and saved program metadata. Checks cover graph direction, paths, basic-block edges, literal searches, raw P-code matches, cursor pagination, scan/node/block limits, stale identities, malformed inputs, unchanged bytes and unchanged metadata dirty state. Rust unit tests separately reject malformed or request-inconsistent responses. No customer binary or project is needed.
