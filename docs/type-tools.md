# Native types and variables

These tools operate on the selected program in the native GUI or headless bridge. Every request includes `expected_program_id`; stale identities and an active analysis job are rejected by the dispatcher. Addresses include their space, for example `ram:00400180`. Function operations require the exact function entry.

Mutations run in a Ghidra transaction and check the resulting database state before committing. They change analysis metadata, not firmware bytes. Save the program with the normal save tool to persist edits. No tool accepts source code, scripts, a C declaration parser, or arbitrary commands.

## Type descriptors

The same descriptor is used for fields, parameters, return types, aliases, variables, and listing data:

```json
{"kind":"builtin","name":"u32"}
{"kind":"path","path":"/Research/Request"}
{"kind":"pointer","to":{"kind":"path","path":"/Research/Request"}}
{"kind":"array","element":{"kind":"builtin","name":"u16"},"count":12}
```

Builtins are `u8`, `s8`, `u16`, `s16`, `u32`, `s32`, `u64`, `s64`, `f32`, `f64`, and `void`. `void` is permitted only as a function return type or pointer target. Pointers use the program's native pointer width. Arrays have 1–65,536 elements. Use nested array descriptors for multiple dimensions; wrapping an existing array path as an array element is rejected. Ghidra names dimensions outermost first, such as `/word[2][4]`. Nesting is limited to four levels, and each resolved fixed-size object to 1 MiB. Named paths refer only to the current program's data type manager; no archive is loaded implicitly. Native type names are returned, such as `/dword` for `u32` and `/sdword` for `s32`.

## Inspecting and creating types

| Tool | Inputs beyond identity | Behavior |
| --- | --- | --- |
| `list_data_types` | Optional `query`, `offset`, `limit` | Type-path substring search; at most 200 entries per page. |
| `get_data_type` | `path` | Exact type, byte length, kind, and up to 256 fields or enum members. Reports truncation. |
| `create_structure` | `path`, `size`, `fields` | Fixed unpacked layout. Each field has `offset`, `name`, `data_type`, optional `comment`. Gaps remain undefined. Overlap and overflow fail. |
| `set_structure_field` | `path`, `offset`, `expected_name`, `expected_type_path`, `name`, `data_type`, optional `comment` | Guarded edit of an existing named field. Replacement preserves its exact length. Omitted comment preserves the current comment. |
| `create_enum` | `path`, `size`, `members` | Size 1, 2, 4, or 8 bytes; each member has `name`, `value`. |
| `create_union` | `path`, `fields` | Each member has `name`, `data_type`, optional `comment`; all offsets are zero. |
| `create_typedef` | `path`, `data_type` | New named alias. |
| `apply_data_type` | `address`, `data_type` | Defines data in undefined mapped storage only. Existing code/data are preserved. |

New type categories, type names, field names, parameter names, and renamed variables use ASCII identifiers. Creation fails if the exact type path already exists; it does not silently replace or generate a `.conflict` type. Structures and unions accept at most 256 fields, enums at most 256 members. Enum inputs use signed 64-bit JSON integers. For smaller widths, values must consistently fit either unsigned representation or signed representation when any member is negative. Unsigned 64-bit values above `i64::MAX` are not supported.

Structure edits reject packed structures, bitfields, unnamed fields, resizing, and changes that could move neighboring fields. Edited structures must fit the 256-field and 1 MiB readback limits. Existing type inspection may report bitfields sharing an offset; this does not make bitfield editing supported. Type responses are capped at 1 MiB of UTF-8 JSON; a mutation that cannot return its bounded readback rolls back.

Example structure:

```json
{
  "expected_program_id":"<selected-program-id>",
  "path":"/Research/Request",
  "size":8,
  "fields":[
    {"offset":0,"name":"state","data_type":{"kind":"builtin","name":"u16"}},
    {"offset":4,"name":"value","data_type":{"kind":"builtin","name":"u32"}}
  ]
}
```

## Variables and function signatures

`get_function_variables` decompiles one function with a timeout and returns a bounded page of high symbols. Each variable includes its type, parameter index, editability, and a selector containing the exact `symbol_id`, current `name`, and serialized native `storage`. It also returns the current database signature and compiler calling-convention names. Its `offset` and `limit` apply to variables; the signature summary includes at most 64 parameters.

Pass that complete selector to `rename_variable` with `name`, or `set_variable_type` with `data_type`. Selectors are checked against a fresh decompilation. Missing, changed, or ambiguous selections fail. Global, constant, unique, and unassigned storage are not edited. Inferred parameters need an explicit committed signature with matching storage first and are reported as not editable. Renames reject existing variable names; type changes preserve the storage width. Native database readback confirms the variable name, type, and storage. A transaction snapshot guards the other parameters and locals, return type/storage, calling convention, variable-argument flag, and function storage properties. Ghidra helper changes to merged or conflicting variables cause rollback. An intended parameter edit may promote the signature source to `USER_DEFINED`; the response reports its before/after source. Refresh the variable list after every mutation because decompiler symbol IDs can change. Optimized-away expressions and unnamed temporaries are not necessarily editable symbols.

`set_function_signature` accepts:

```json
{
  "expected_program_id":"<selected-program-id>",
  "address":"ram:00400180",
  "expected_signature":"<exact signature returned by inspection>",
  "return_type":{"kind":"builtin","name":"u32"},
  "parameters":[{"name":"request","data_type":{"kind":"pointer","to":{"kind":"path","path":"/Research/Request"}}}],
  "calling_convention":"<name returned by inspection>",
  "varargs":false
}
```

It replaces the signature only when `expected_signature` matches, uses native dynamic parameter storage, and does not force conflicting local storage out of the way. There are at most 64 parameters. Existing custom storage and auto parameters are rejected. Unusual ABIs and register-specific signatures need a separate, explicitly designed operation; this tool does not guess them.

## Structure field references

`get_structure_field_references` takes a function `address`, exact structure `path`, `field_offset`, and optional `limit` of 1–200. It inspects real decompiler high P-code and reports `PTRSUB` operations only when the base variable has a pointer to the requested structure and the constant offset matches a defined field. Results include the instruction address and P-code sequence number.

These are field-pointer derivations, not proof of a read or write. `coverage` is always `single_function_typed_ptrsub_only` and `exhaustive` is always false. Casts, untyped arithmetic, other functions, and optimizations can hide references. Empty results therefore do not prove the field is unused. The scan is bounded to 100,000 high-P-code operations and the decompiler timeout.

## Verification scope

`tests/native-types.mjs` uses synthetic x86 functions and data, including a function that actually dereferences a typed structure field. It checks all operation families, conflict and stale guards, unchanged bytes, and readback. `checkTypePersistence` is a separate read-only check for the harness to run after saving, closing, and reopening. Rust tests independently reject malformed descriptors and inconsistent native responses. These tests do not establish behavior on a customer's ECU program or prove inferred type semantics.
