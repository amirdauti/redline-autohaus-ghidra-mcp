# Bridge protocol v1 (implementation contract)

Local single-client file mailbox. Rust owns `client.lock`; Java owns `bridge.lock`. Request file `request.json` and response file `response.json` are published by atomic rename from unique temporary files. No stale files are removed on startup. One outstanding request. Invalid/mismatched response or timeout poisons the client connection; never retry a mutation automatically. Maximum request 1 MiB, response 8 MiB. UTF-8 JSON.

Request: `{ "protocol": 1, "id": "uuid", "operation": "status", "params": {} }`.
Success: `{ "protocol": 1, "id": "same uuid", "ok": true, "result": {} }`.
Failure: `{ "protocol": 1, "id": "same uuid", "ok": false, "error": { "code": "invalid_argument", "message": "..." } }`.

Java consumes request (removes request.json) before publishing response. Rust consumes response after validating it. Stop sentinel `stop` terminates bridge only after the current command completes. Root-provided launcher removes `stop` only when no pending requests/responses exist. Do not automatically retry commands. Java must reject unknown operations and fields where feasible.

## Operations and parameters

All MCP tools are `ghidra_` + operation. All listed keys are required unless marked optional. Every project/program ID is an opaque runtime identifier supplied by the bridge. IDs and source hashes are separate fields. Program operations always verify the active program identity. Addresses are strings with address space, e.g. `ram:00400000`; file offsets are integers, never CPU addresses.

- `status {}` -> backend/mode/version, project/program if present, capabilities
- `list_languages {}` -> language IDs, processor, endian, size, compiler IDs
- `get_project {}` -> id,name,path or error if none
- `create_project {path,name}` -> project; path is existing parent directory, reject any .gpr/.rep collision
- `open_project {path,name}` -> project; reject switching while another project is open
- `close_project {expected_project_id}` -> closed; reject unsaved programs or active analysis
- `list_programs {expected_project_id}` -> recursive domain paths and names
- `import_program {expected_project_id,path,name,language_id,compiler_spec_id,image_base}` -> program; raw binary only, `name` simple filename, explicit language/compiler and hex image_base; no overwrite; one contiguous initial block. More complex layouts remain explicit future work.
- `select_program {expected_project_id,program_path}` -> program; domain path e.g. /Original
- `get_program {}` -> id,project_id,name,program_path,language_id,compiler_spec_id,source_sha256,image_base,memory_blocks,changed
- `save_program {expected_program_id}` -> program; saved explicitly
- `analyze {expected_program_id}` -> job_id,state immediately; background auto-analysis
- `job_status {job_id}` -> queued/running/completed/failed,error if any
- `read_bytes {expected_program_id,address,count}` -> address,bytes; count 1..4096
- `map_file_offset {expected_program_id,file_offset}` -> all matching addresses plus provenance; never silently resolve aliases; reject multiple source files unless unique mapping established
- `list_functions {expected_program_id,offset?,limit?}` -> total/functions; offset default0,limit default50 max200
- `decompile {expected_program_id,address}` -> function address/name,C text; native timeout30sec; cap text1MiB
- `disassemble {expected_program_id,address,count}` -> existing listing instructions (does not force code over data), count1..200
- `get_references {expected_program_id,address,direction?,limit?}` -> refs, direction default to (to/from), limit default100 max500
- `search_bytes {expected_program_id,pattern,limit?}` -> exact hex bytes matches, limit default100 max500, pattern1..256bytes; cancellation/bounded scanning
- `set_label {expected_program_id,address,name}` -> readback label; USER_DEFINED symbol transaction
- `set_comment {expected_program_id,address,comment}` -> readback EOL comment; max8192chars transaction
- `go_to {expected_program_id,address}` -> GUI cursor navigation; headless returns unsupported

Bridge configuration restricts create/open under project root and import under allowed import roots. User input is data. No arbitrary script, shell, firmware patch, or delete operation. GUI and headless share command semantics but GUI project lifecycle may return a clearly documented unsupported error if not safely implemented; headless lifecycle must be complete. Analysis busy guards prevent program mutation/switch/closure during a job; status and job_status remain available.
