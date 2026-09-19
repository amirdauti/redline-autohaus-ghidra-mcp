# Bridge protocol v1 (implementation contract)

Local single-client file mailbox. Rust acquires `client.lock` on the first native tool call and retains it after a successful connection; Java owns `bridge.lock`. MCP initialization and tool discovery do not acquire either lock or launch Java. Offline/busy errors before dispatch allow an explicit later tool call in the same client; they never queue or replay a request. Request file `request.json` and response file `response.json` are published by atomic rename from unique temporary files. No stale files are removed on startup. One outstanding request. Invalid/mismatched response or timeout poisons the client connection; never retry a mutation automatically. Maximum request 1 MiB, response 8 MiB. UTF-8 JSON.

Before publishing a request, Rust writes and syncs `client.pending` containing its request ID and operation. It removes this durable guard only after validating and consuming a definitive response. Startup refuses an existing guard, including when Java has already consumed the request but has not finished it. A timeout, cancellation, crash, or uncertain result therefore prevents automatic reuse across client restarts. Preserve pending files for inspection; recover only after the native operation's outcome is known. Temporary filenames use `request.<uuid>.tmp` and `response.<uuid>.tmp`; unfinished temporary files also block startup.

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

## Extended analysis workflow

The following operations use the same project/program identity, path, transaction and busy guards:

- `get_analysis_options {expected_program_id}` -> names, types and values of current program analysis options
- `set_analysis_options {expected_program_id,options}` -> readback; options is an object mapping existing Boolean option names to Boolean values; reject unknown or non-Boolean options
- `cancel_analysis {job_id}` -> cancellation requested; keep job busy until native analysis actually stops
- `set_image_base {expected_program_id,address}` -> updated program; transaction, commit rebasing, reject invalid/overflowing relocation
- `create_memory_block {expected_program_id,name,address,size,read,write,execute}` -> uninitialized memory block readback; size1..67108864, no overlaps; permissions refer to modeled ECU memory
- `create_instructions {expected_program_id,address,length}` -> bounded disassembly in existing initialized memory, length1..65536, never clear existing data/code; does not patch bytes
- `create_function {expected_program_id,address,name?}` -> function detail; create from decoded instructions using native flow detection, reject duplicate entry
- `rename_function {expected_program_id,address,name}` -> function detail; USER_DEFINED name transaction
- `get_function {expected_program_id,address}` -> containing function, signature, parameters, callers and callees (bounded)
- `get_comments {expected_program_id,address}` -> address, comments keyed by eol/pre/post/plate/repeatable (string or null), truncated_types; exact mapped address, each stored comment capped at8192 UTF-16 code units without splitting a surrogate pair
- `get_data {expected_program_id,address,component_offset?,component_limit?}` -> found,data,components,component_offset,has_more; existing defined data containing the address, or found=false/data=null for mapped code or undefined storage. Data metadata includes its own start address,type path,display type,length,num_components and nullable value representation. Immediate components include their index; offset default0 max2147483647, limit default32 max128. No recursive expansion. Value rendering is omitted for composites/arrays or definitions over4096bytes; other representations are capped at4096 UTF-16 code units. value_omitted/value_truncated are explicit. Incomplete native definitions return an error. No type, unit or scaling is inferred.
- `get_pcode {expected_program_id,address,count}` -> address,pcode_kind=raw,includes_flow_overrides=false,instructions,operation_count,varnode_count,truncated,truncation_reason; count1..200 contiguous existing instructions beginning exactly at the requested address. Each instruction contains address,length,mnemonic,operations; each operation contains index,opcode,nullable output and inputs. Varnodes contain space,hexadecimal offset string,size in bytes (1..65536); offsets preserve unsigned64-bit values. No instruction creation or decompiler SSA. Bound2048 operations and8192 varnodes total; at most32 inputs per operation. Whole instructions are returned; an instruction exceeding the remaining budget is omitted. Truncation reason is instruction_count or operation_or_varnode_limit, otherwise null. Stops at listing gaps/address-space end. Unsupported varnodes/oversized input lists return an error.
- `define_data {expected_program_id,address,type_name,count}` -> readback array/scalar; type_name one of u8,s8,u16,s16,u32,s32,u64,s64,f32,f64; count1..65536; require undefined storage, no clearing code or existing data
- `list_symbols {expected_program_id,query?,offset?,limit?}` -> matching symbols; substring filter, offset default0,limit default100 max500
- `list_strings {expected_program_id,offset?,limit?}` -> existing defined string data, offset default0,limit default100 max500
- `export_program {expected_program_id,path}` -> Ghidra packed program (.gzf) export, preserving analysis; output must be under project root and not exist

Address/ID parameter rules match the base operations. Definition operations alter analysis metadata, not firmware bytes. These tools do not claim debugger control or arbitrary third-party plugin coverage.
