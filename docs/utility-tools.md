# Memory, listing and research annotations

All tools require the active `expected_program_id`. CPU addresses use `space:hex`, never file offsets. Scans have deadlines and bounded output. Metadata edits use transactions and require `save_program` for persistence. Failed guards roll back the entire batch. These tools do not patch firmware bytes.

| Tool | Inputs and behavior |
| --- | --- |
| `get_listing` | `address`, `length` (1..65536), `limit` (default128/max256). Complete containing code units, kind, address/end, size and bounded display. Boundary units may extend beyond the interval. `next_address` resumes after the last returned unit when truncated. |
| `hash_memory` | `address`, `length` (1..16777216). SHA-256 of current initialized bytes; rejects gaps and uninitialized memory. Separate from imported source hash. |
| `preview_instructions` | `address`, `count` (1..200). Sequential pseudo-disassembly with private flowing context. Instruction text, sizes, delay slots and stop reason; no listing writes or branch following. |
| `get_processor_context` | `address`, optional exact `register`, `offset` (default0/max65536), `limit` (default128/max256). Language register descriptions and stored context values/masks; null means unknown. These are analysis values, not live registers. |
| `set_processor_context` | `address`, `length` (1..65536), `register`, hexadecimal `value` (max1024bits; must fit register). Mapped range must be free of instructions. Verifies the complete range. |
| `clear_listing` | `address`, `length` (1..65536), `expected_kind` (`data`, `instruction`, `any`). Complete units only; rejects function overlap. Clears definitions and verifies undefined storage and unchanged bytes. Native clearing may remove references derived from the cleared units. |
| `list_bookmarks` | `offset` (default0/max2147483647), `limit` (default128/max256), five-second scan deadline. Native bookmarks, categories and bounded comments. Pagination follows current iteration order; concurrent edits can change it. |
| `set_bookmark` | `address`, `bookmark_type` (1..64 printable characters), `category` (1..128), `comment` (max8192), optional `expected_comment`. Existing bookmarks require their exact current comment; omit expectation to create. |
| `delete_bookmark` | Address/type/category and required exact `expected_comment`; deletes only that bookmark. |
| `list_comments` | `address`, `length` (1..16777216), `comment_type` (`eol`, `pre`, `post`, `plate`, `repeatable`), optional literal `query` (1..256), `limit` (default128/max128). At most10000 addresses scanned; text truncation and continuation explicit. Matching uses full stored text. |
| `batch_set_comments` | 1..64 `updates`: `{address,comment_type,comment,expected_comment}`. Null comment deletes; null expectation requires absence. Rejects duplicate targets. Aggregate new/expected text max65536 UTF-16 units natively. |
| `get_function_tags` | Exact function-entry `address`; up to256 tags of at most128 characters. |
| `update_function_tags` | Exact entry `address`, `add` and `remove` arrays (max32 each). Rejects duplicate/contradictory changes and verifies membership. |
| `batch_rename` | 1..64 `updates`: `{kind,address,name,expected_name}`. Function entries or primary labels, guarded by exact current names. Null expectation creates a label only if no primary symbol exists. |
| `compare_program_memory` | Active `address`, `other_program_path`, `expected_other_source_sha256`, `other_address`, `length` (1..1048576), `limit` (default128/max256 changed ranges). Opens a read-only saved program in the same local project without switching. Actual hashes, total changed bytes/ranges and bounded contiguous differences. Unsaved edits to the second program are excluded. |
| `compare_saved_function` | Same saved-program path/source identity and both addresses, with `max_instructions` (default1024/max4096). Requires matching language/compiler IDs. Normalized comparison follows [flow tools](flow-tools.md); equality does not prove semantic equivalence. |

Saved comparisons reject link files, traversal, source-hash mismatches and non-program objects. Source hash identifies the imported binary; returned region hashes describe actual compared bytes. The saved-program consumer is always released; active identities are checked again afterwards.

MCP `tools/list` supplies strict schemas and defaults. Other contracts: [research](research-tools.md), [types](type-tools.md), [decompiler/data-flow](flow-tools.md).
