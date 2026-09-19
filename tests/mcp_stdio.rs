//! Full stdio MCP contract using a synthetic file-mailbox peer. No Ghidra is launched.

use std::{process::Stdio, time::Duration};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout, Command},
    time::timeout,
};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

struct Client {
    child: Child,
    input: Option<ChildStdin>,
    output: Lines<BufReader<ChildStdout>>,
    next_id: u64,
}

impl Client {
    async fn start(directory: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ghidra-mcp"))
            .arg("--bridge-dir")
            .arg(directory)
            .args(["--timeout-ms", "3000"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("start the MCP executable");
        let input = child.stdin.take().expect("piped stdin");
        let output = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        let mut client = Self {
            child,
            input: Some(input),
            output,
            next_id: 1,
        };
        let initialized = client
            .rpc(
                "initialize",
                json!({
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "stdio-integration-test", "version": "1.0.0"}
                }),
            )
            .await;
        assert!(initialized.get("error").is_none(), "{initialized}");
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(initialized["result"]["serverInfo"]["name"], "ghidra-mcp");
        assert_eq!(
            initialized["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert!(initialized["result"]["capabilities"]["tools"].is_object());
        client
            .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        client
    }

    async fn send(&mut self, message: Value) {
        let mut bytes = serde_json::to_vec(&message).unwrap();
        bytes.push(b'\n');
        timeout(RESPONSE_TIMEOUT, async {
            let input = self.input.as_mut().expect("stdin still open");
            input.write_all(&bytes).await.unwrap();
            input.flush().await.unwrap();
        })
        .await
        .expect("MCP stdin write timed out");
    }

    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        let line = timeout(RESPONSE_TIMEOUT, self.output.next_line())
            .await
            .expect("MCP response timed out")
            .expect("read MCP stdout")
            .expect("MCP server closed stdout before responding");
        let response: Value = serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("non-protocol stdout: {line:?}: {error}"));
        assert_eq!(response["jsonrpc"], "2.0", "{response}");
        assert_eq!(response["id"], id, "unexpected stdout message: {response}");
        response
    }

    async fn call_raw(&mut self, name: &str, arguments: Value) -> Value {
        self.rpc("tools/call", json!({"name": name, "arguments": arguments}))
            .await
    }

    async fn call(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.call_raw(name, arguments).await;
        assert!(response.get("error").is_none(), "{name}: {response}");
        assert_ne!(response["result"]["isError"], true, "{name}: {response}");
        let result = &response["result"];
        let structured = result["structuredContent"].clone();
        assert!(structured.is_object(), "{name}: {response}");
        // Clients without structured-content support must receive the same data.
        let text = result["content"][0]["text"]
            .as_str()
            .expect("text fallback");
        assert_eq!(serde_json::from_str::<Value>(text).unwrap(), structured);
        structured
    }

    async fn tool_error(&mut self, name: &str, arguments: Value, expected: &str) {
        let response = self.call_raw(name, arguments).await;
        assert!(response.get("error").is_none(), "{name}: {response}");
        assert_eq!(response["result"]["isError"], true, "{name}: {response}");
        let message = response["result"]["structuredContent"]["error"]
            .as_str()
            .expect("structured tool error message");
        assert!(
            message.contains(expected),
            "expected {expected:?}: {message}"
        );
    }

    async fn close(mut self) {
        // Closing stdin is how a stdio MCP client disconnects.
        drop(self.input.take());
        let status = timeout(RESPONSE_TIMEOUT, self.child.wait())
            .await
            .expect("MCP server did not exit after stdin closed")
            .expect("wait for MCP server");
        assert!(status.success(), "MCP server exited with {status}");
        let leftover = timeout(RESPONSE_TIMEOUT, self.output.next_line())
            .await
            .expect("stdout did not close")
            .expect("read remaining stdout");
        assert!(
            leftover.is_none(),
            "unexpected trailing stdout: {leftover:?}"
        );
    }
}

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{fs, sync::watch, task::JoinHandle};

fn program() -> Value {
    json!({"id":"synthetic-program","project_id":"synthetic-project","name":"Synthetic","program_path":"/Synthetic","language_id":"x86:LE:32:default","compiler_spec_id":"default","source_sha256":"00".repeat(32),"image_base":"ram:00400000","memory_blocks":[],"changed":false})
}

fn fixture_result(operation: &str, params: &Value) -> Value {
    match operation {
        "status" => {
            json!({"backend":"ghidra","mode":"headless","version":"synthetic-transport-fixture","project":null,"program":null,"capabilities":["status","read_bytes"]})
        }
        "list_languages" => {
            json!({"languages":[{"id":"x86:LE:32:default","processor":"x86","endian":"little","size":32,"description":"Synthetic language listing","compilers":[{"id":"default","name":"Synthetic compiler"}]}]})
        }
        "get_project" | "open_project" | "create_project" => {
            json!({"id":"synthetic-project","name":"Synthetic","path":"synthetic-project-root"})
        }
        "close_project" => json!({"closed":true}),
        "get_program" | "save_program" | "import_program" | "select_program" | "set_image_base" => {
            program()
        }
        "list_programs" => {
            json!({"project_id":"synthetic-project","programs":[{"name":"Synthetic","program_path":"/Synthetic"}]})
        }
        "analyze" | "job_status" => json!({"job_id":"synthetic-job","state":"completed"}),
        "read_bytes" => {
            json!({"address":params["address"],"bytes":vec![42; params["count"].as_u64().unwrap() as usize]})
        }
        // Two aliases deliberately differ from the file offset and must both survive.
        "map_file_offset" => {
            json!({"file_offset":params["file_offset"],"source_file":"synthetic.bin","source_file_offset":0,"source_size":64,"matches":[{"address":"ram:00400008","block":"ROM","source_file":"synthetic.bin","file_offset":params["file_offset"]},{"address":"mirror:00800008","block":"ROM_ALIAS","source_file":"synthetic.bin","file_offset":params["file_offset"]}],"ambiguous":true})
        }
        "list_functions" => {
            assert_eq!(params["limit"], 50);
            json!({"total":0,"offset":params["offset"],"functions":[]})
        }
        "list_symbols" => json!({"total":0,"symbols":[]}),
        "list_strings" => json!({"total":0,"strings":[]}),
        "decompile" => {
            json!({"address":params["address"],"name":"synthetic","c":"void synthetic(void) { return; }"})
        }
        "disassemble" => {
            json!({"address":params["address"],"instructions":[{"address":params["address"],"length":1,"mnemonic":"RET","text":"RET","bytes":[195]}]})
        }
        "get_comments" => {
            json!({"address":params["address"],"comments":{"eol":"Synthetic\ncomment","pre":null,"post":null,"plate":null,"repeatable":null},"truncated_types":[]})
        }
        "get_data" => {
            json!({"address":params["address"],"found":false,"data":null,"components":[],"component_offset":params["component_offset"],"has_more":false})
        }
        "get_pcode" => {
            json!({"address":params["address"],"pcode_kind":"raw","includes_flow_overrides":false,"instructions":[{"address":params["address"],"length":1,"mnemonic":"RET","operations":[]}],"operation_count":0,"varnode_count":0,"truncated":false,"truncation_reason":null})
        }
        "get_references" => {
            assert_eq!(params["direction"], "to");
            json!({"address":params["address"],"direction":"to","refs":[],"truncated":false})
        }
        "search_bytes" => json!({"matches":["ram:00400008"],"truncated":false}),
        "set_label" => {
            json!({"address":params["address"],"name":params["name"],"source":"USER_DEFINED"})
        }
        "set_comment" => {
            json!({"address":params["address"],"comment":params["comment"],"type":"EOL"})
        }
        _ => json!({"synthetic_transport_ack":operation}),
    }
}

async fn peer(directory: &Path) -> (watch::Sender<bool>, JoinHandle<()>, Arc<AtomicUsize>) {
    peer_with_lock(directory, true).await
}

async fn peer_with_lock(
    directory: &Path,
    own_lock: bool,
) -> (watch::Sender<bool>, JoinHandle<()>, Arc<AtomicUsize>) {
    use fs2::FileExt;
    let native = if own_lock {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("bridge.lock"))
            .unwrap();
        file.try_lock_exclusive().unwrap();
        Some(file)
    } else {
        None
    };
    let (stop, mut stopped) = watch::channel(false);
    let root = directory.to_path_buf();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        let _native = native;
        loop {
            tokio::select! {
                _ = stopped.changed() => break,
                _ = tokio::time::sleep(Duration::from_millis(2)) => {}
            }
            let path = root.join("request.json");
            if !path.exists() {
                continue;
            }
            let req: Value = serde_json::from_slice(&fs::read(&path).await.unwrap()).unwrap();
            assert_eq!(req["protocol"], 1);
            assert!(root.join("client.pending").exists());
            let operation = req["operation"].as_str().unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let result = if req["params"].get("expected_program_id")
                == Some(&json!("stale-program"))
            {
                json!({"protocol":1,"id":req["id"],"ok":false,"error":{"code":"stale_identity","message":"Synthetic active program changed"}})
            } else {
                json!({"protocol":1,"id":req["id"],"ok":true,"result":fixture_result(operation,&req["params"])})
            };
            let temporary = root.join(format!("response.{}.tmp", req["id"].as_str().unwrap()));
            fs::write(&temporary, serde_json::to_vec(&result).unwrap())
                .await
                .unwrap();
            fs::remove_file(path).await.unwrap();
            fs::rename(temporary, root.join("response.json"))
                .await
                .unwrap();
        }
    });
    (stop, task, calls)
}

fn arguments(operation: &str, root: &Path) -> Value {
    let mut p = json!({"expected_program_id":"synthetic-program"});
    match operation {
        "status" | "list_languages" | "get_project" | "get_program" => return json!({}),
        "create_project" | "open_project" => return json!({"path":root,"name":"Synthetic"}),
        "close_project" | "list_programs" => {
            return json!({"expected_project_id":"synthetic-project"});
        }
        "select_program" => {
            return json!({"expected_project_id":"synthetic-project","program_path":"/Synthetic"});
        }
        "import_program" => {
            return json!({"expected_project_id":"synthetic-project","path":root.join("synthetic.bin"),"name":"Synthetic","language_id":"x86:LE:32:default","compiler_spec_id":"default","image_base":"0x400000"});
        }
        "job_status" | "cancel_analysis" => return json!({"job_id":"synthetic-job"}),
        "map_file_offset" => p["file_offset"] = json!(8),
        "read_bytes" => {
            p["address"] = json!("ram:00400000");
            p["count"] = json!(4);
        }
        "disassemble" | "get_pcode" => {
            p["address"] = json!("ram:00400000");
            p["count"] = json!(1);
        }
        "search_bytes" => p["pattern"] = json!("AA BB"),
        "set_analysis_options" => p["options"] = json!({"Synthetic analyzer":false}),
        "set_label" | "rename_function" => {
            p["address"] = json!("ram:00400000");
            p["name"] = json!("synthetic_label");
        }
        "set_comment" => {
            p["address"] = json!("ram:00400000");
            p["comment"] = json!("Synthetic comment");
        }
        "create_memory_block" => {
            p["address"] = json!("ram:00500000");
            p["name"] = json!("RAM");
            p["size"] = json!(1024);
            p["read"] = json!(true);
            p["write"] = json!(true);
            p["execute"] = json!(false);
        }
        "create_instructions" => {
            p["address"] = json!("ram:00400000");
            p["length"] = json!(16);
        }
        "define_data" => {
            p["address"] = json!("ram:00400010");
            p["type_name"] = json!("u16");
            p["count"] = json!(2);
        }
        "export_program" => p["path"] = json!(root.join("export.gzf")),
        "save_program"
        | "analyze"
        | "list_functions"
        | "get_analysis_options"
        | "list_symbols"
        | "list_strings" => {}
        _ => p["address"] = json!("ram:00400000"),
    }
    p
}

#[tokio::test]
async fn executable_negotiates_all_typed_tools_and_dispatches_over_the_mailbox() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("synthetic.bin"), [0x90, 0xc3, 0, 0])
        .await
        .unwrap();
    let (stop, task, calls) = peer(directory.path()).await;
    let mut client = Client::start(directory.path()).await;
    let listed = client.rpc("tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().unwrap();
    let mut names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "ghidra_analyze",
            "ghidra_cancel_analysis",
            "ghidra_close_project",
            "ghidra_create_function",
            "ghidra_create_instructions",
            "ghidra_create_memory_block",
            "ghidra_create_project",
            "ghidra_decompile",
            "ghidra_define_data",
            "ghidra_disassemble",
            "ghidra_export_program",
            "ghidra_get_analysis_options",
            "ghidra_get_comments",
            "ghidra_get_data",
            "ghidra_get_function",
            "ghidra_get_pcode",
            "ghidra_get_program",
            "ghidra_get_project",
            "ghidra_get_references",
            "ghidra_go_to",
            "ghidra_import_program",
            "ghidra_job_status",
            "ghidra_list_functions",
            "ghidra_list_languages",
            "ghidra_list_programs",
            "ghidra_list_strings",
            "ghidra_list_symbols",
            "ghidra_map_file_offset",
            "ghidra_open_project",
            "ghidra_read_bytes",
            "ghidra_rename_function",
            "ghidra_save_program",
            "ghidra_search_bytes",
            "ghidra_select_program",
            "ghidra_set_analysis_options",
            "ghidra_set_comment",
            "ghidra_set_image_base",
            "ghidra_set_label",
            "ghidra_status"
        ]
    );
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false, "{tool}");
        assert_eq!(tool["annotations"]["openWorldHint"], false);
        if tool["inputSchema"]["properties"]
            .as_object()
            .is_some_and(|fields| fields.contains_key("expected_program_id"))
        {
            assert!(
                tool["inputSchema"]["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("expected_program_id"))
            );
        }
        let name = tool["name"].as_str().unwrap();
        if ["ghidra_get_comments", "ghidra_get_data", "ghidra_get_pcode"].contains(&name) {
            assert_eq!(tool["annotations"]["readOnlyHint"], true);
            assert_eq!(tool["annotations"]["destructiveHint"], false);
        }
        let result = client
            .call(
                name,
                arguments(name.strip_prefix("ghidra_").unwrap(), directory.path()),
            )
            .await;
        if name == "ghidra_map_file_offset" {
            assert_eq!(result["ambiguous"], true);
            assert_eq!(result["matches"].as_array().unwrap().len(), 2);
            assert_eq!(result["matches"][0]["address"], "ram:00400008");
            assert_eq!(result["matches"][1]["address"], "mirror:00800008");
        }
        if name == "ghidra_list_languages" {
            assert_eq!(result["languages"][0]["compilers"][0]["id"], "default");
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 39);
    client
        .tool_error(
            "ghidra_read_bytes",
            json!({"expected_program_id":"stale-program","address":"ram:0","count":1}),
            "active program changed",
        )
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), 40);
    for (name, args) in [
        ("ghidra_status", json!({"unknown":true})),
        (
            "ghidra_read_bytes",
            json!({"expected_program_id":"synthetic-program","address":"ram:0","count":4097}),
        ),
        (
            "ghidra_read_bytes",
            json!({"expected_program_id":"","address":"ram:0","count":1}),
        ),
        (
            "ghidra_read_bytes",
            json!({"expected_program_id":"synthetic-program","address":0,"count":1}),
        ),
        (
            "ghidra_import_program",
            json!({"expected_project_id":"synthetic-project","path":directory.path().join("synthetic.bin"),"name":"Synthetic","image_base":"0x400000"}),
        ),
        (
            "ghidra_set_analysis_options",
            json!({"expected_program_id":"synthetic-program","options":{"X":42}}),
        ),
        (
            "ghidra_define_data",
            json!({"expected_program_id":"synthetic-program","address":"ram:0","type_name":"script","count":1}),
        ),
        (
            "ghidra_get_data",
            json!({"expected_program_id":"synthetic-program","address":"ram:0","component_offset":2147483648_u32}),
        ),
        (
            "ghidra_get_data",
            json!({"expected_program_id":"synthetic-program","address":"ram:0","component_limit":129}),
        ),
        (
            "ghidra_get_pcode",
            json!({"expected_program_id":"synthetic-program","address":"ram:0","count":201}),
        ),
    ] {
        let response = client.call_raw(name, args).await;
        assert_eq!(response["result"]["isError"], true, "{response}");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        40,
        "invalid input reached native transport"
    );
    client.call("ghidra_status", json!({})).await;
    assert_eq!(calls.load(Ordering::SeqCst), 41);
    client.close().await;
    stop.send(true).unwrap();
    task.await.unwrap();
    assert!(!directory.path().join("client.pending").exists());
}

#[tokio::test]
async fn doctor_outputs_only_status_json_and_cli_rejects_out_of_range_timeout() {
    let directory = tempfile::tempdir().unwrap();
    let (stop, task, calls) = peer(directory.path()).await;
    let output = timeout(
        RESPONSE_TIMEOUT,
        Command::new(env!("CARGO_BIN_EXE_ghidra-mcp"))
            .arg("--bridge-dir")
            .arg(directory.path())
            .arg("--doctor")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["version"], "synthetic-transport-fixture");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop.send(true).unwrap();
    task.await.unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ghidra-mcp"))
        .arg("--bridge-dir")
        .arg(directory.path())
        .args(["--timeout-ms", "120001"])
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[tokio::test]
async fn discovery_survives_offline_bridge_and_same_client_connects_after_manual_start() {
    let directory = tempfile::tempdir().unwrap();
    let mut client = Client::start(directory.path()).await;
    let listed = client.rpc("tools/list", json!({})).await;
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 39);
    assert!(!directory.path().join("client.lock").exists());
    client
        .tool_error("ghidra_status", json!({}), "bridge is not running")
        .await;
    assert!(!directory.path().join("client.pending").exists());
    assert!(!directory.path().join("request.json").exists());
    let (stop, task, calls) = peer(directory.path()).await;
    client.call("ghidra_status", json!({})).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop.send(true).unwrap();
    task.await.unwrap();
    client
        .tool_error("ghidra_status", json!({}), "bridge is not running")
        .await;
    assert!(!directory.path().join("client.pending").exists());
    let (stop, task, calls) = peer(directory.path()).await;
    client.call("ghidra_status", json!({})).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    client.close().await;
    stop.send(true).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn busy_bridge_is_a_tool_error_and_owner_release_does_not_require_mcp_restart() {
    let directory = tempfile::tempdir().unwrap();
    let (stop, task, calls) = peer(directory.path()).await;
    let mut owner = Client::start(directory.path()).await;
    owner.call("ghidra_status", json!({})).await;
    let mut next = Client::start(directory.path()).await;
    assert!(next.rpc("tools/list", json!({})).await["error"].is_null());
    next.tool_error("ghidra_status", json!({}), "another MCP client owns")
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!directory.path().join("client.pending").exists());
    owner.close().await;
    next.call("ghidra_status", json!({})).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    next.close().await;
    stop.send(true).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn discovery_and_invalid_arguments_leave_stale_evidence_untouched() {
    let directory = tempfile::tempdir().unwrap();
    for name in ["client.pending", "stop"] {
        fs::write(directory.path().join(name), b"preserve recovery evidence")
            .await
            .unwrap();
    }
    let mut client = Client::start(directory.path()).await;
    assert!(client.rpc("tools/list", json!({})).await["error"].is_null());
    client
        .tool_error(
            "ghidra_read_bytes",
            json!({"expected_program_id":"fixture","address":"ram:0","count":0}),
            "invalid_argument",
        )
        .await;
    assert!(!directory.path().join("client.lock").exists());
    client
        .tool_error("ghidra_status", json!({}), "unfinished or stopped mailbox")
        .await;
    for name in ["client.pending", "stop"] {
        assert_eq!(
            fs::read(directory.path().join(name)).await.unwrap(),
            b"preserve recovery evidence"
        );
    }
    assert!(!directory.path().join("request.json").exists());
    client.close().await;
}

#[tokio::test]
async fn doctor_rejects_bad_launch_configuration_before_dispatch_or_launch() {
    let root = tempfile::tempdir().unwrap();
    let bridge = root.path().join("bridge");
    let config_path = root.path().join("config.json");
    fs::write(&config_path, b"{\"unexpected\":true}")
        .await
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ghidra-mcp"))
        .arg("--bridge-dir")
        .arg(&bridge)
        .arg("--launch-config")
        .arg(&config_path)
        .arg("--doctor")
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid launch config"));

    let script = root.path().join("not-executed.ps1");
    let jar = root.path().join("not-loaded.jar");
    fs::write(&script, b"throw 'Synthetic fixture must never be executed'")
        .await
        .unwrap();
    fs::write(&jar, b"Synthetic path validation only")
        .await
        .unwrap();
    let config = json!({"launcher_script":script,"ghidra_home":root.path(),"java_home":root.path(),"adapter_jar":jar,"bridge_dir":root.path(),"project_root":root.path(),"import_roots":[root.path()]});
    fs::write(&config_path, serde_json::to_vec(&config).unwrap())
        .await
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ghidra-mcp"))
        .arg("--bridge-dir")
        .arg(&bridge)
        .arg("--launch-config")
        .arg(&config_path)
        .arg("--doctor")
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("bridge_dir must match"));
    assert!(!bridge.join("client.pending").exists());
}

#[cfg(windows)]
#[tokio::test]
async fn launch_config_skips_launch_when_native_lock_is_already_held() {
    let root = tempfile::tempdir().unwrap();
    let script = root.path().join("not-executed.ps1");
    let jar = root.path().join("not-loaded.jar");
    fs::write(&script, b"throw 'Synthetic fixture must never be executed'")
        .await
        .unwrap();
    fs::write(&jar, b"Synthetic path validation only")
        .await
        .unwrap();
    let config = json!({"launcher_script":script,"ghidra_home":root.path(),"java_home":root.path(),"adapter_jar":jar,"bridge_dir":root.path(),"project_root":root.path(),"import_roots":[root.path()]});
    let config_path = root.path().join("config.json");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap())
        .await
        .unwrap();
    let (stop, task, calls) = peer(root.path()).await;
    let output = timeout(
        RESPONSE_TIMEOUT,
        Command::new(env!("CARGO_BIN_EXE_ghidra-mcp"))
            .arg("--bridge-dir")
            .arg(root.path())
            .arg("--launch-config")
            .arg(config_path)
            .arg("--doctor")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["version"], "synthetic-transport-fixture");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop.send(true).unwrap();
    task.await.unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn cold_mcp_streams_close_while_the_bridge_grandchild_remains_running() {
    use tokio::io::AsyncReadExt;
    let root = tempfile::tempdir().unwrap();
    let script = root.path().join("launcher.ps1");
    let jar = root.path().join("synthetic.jar");
    fs::write(&jar, b"Synthetic path fixture; no Java process is launched")
        .await
        .unwrap();
    fs::write(root.path().join("grandchild.ps1"), r#"
param([string]$Root)
$native = [IO.File]::Open((Join-Path $Root 'bridge.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
$native.Lock(0, 1)
[IO.File]::WriteAllText((Join-Path $Root 'child-ready'), 'ready')
$watch = [Diagnostics.Stopwatch]::StartNew()
while (-not [IO.File]::Exists((Join-Path $Root 'release-child')) -and $watch.Elapsed.TotalSeconds -lt 45) {
    Start-Sleep -Milliseconds 10
}
$native.Unlock(0, 1)
$native.Dispose()
[IO.File]::WriteAllText((Join-Path $Root 'child-finished'), 'finished')
"#).await.unwrap();
    fs::write(&script,r#"
param([string]$ConfigPath)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetDirectoryName($ConfigPath)
$info = New-Object Diagnostics.ProcessStartInfo
$info.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$info.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $root 'grandchild.ps1') + '" -Root "' + $root + '"'
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$child = [Diagnostics.Process]::Start($info)
$watch = [Diagnostics.Stopwatch]::StartNew()
while (-not [IO.File]::Exists((Join-Path $root 'child-ready'))) {
    if ($watch.Elapsed.TotalSeconds -gt 15) { throw 'Synthetic grandchild did not start' }
    Start-Sleep -Milliseconds 10
}
[Console]::Out.WriteLine('{"state":"ready"}')
"#).await.unwrap();
    let config = json!({"launcher_script":script,"ghidra_home":root.path(),"java_home":root.path(),"adapter_jar":jar,"bridge_dir":root.path(),"project_root":root.path(),"import_roots":[root.path()]});
    let config_path = root.path().join("config.json");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap())
        .await
        .unwrap();
    let (stop, task, calls) = peer_with_lock(root.path(), false).await;
    let mut server = Command::new(env!("CARGO_BIN_EXE_ghidra-mcp"))
        .arg("--bridge-dir")
        .arg(root.path())
        .arg("--launch-config")
        .arg(config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = server.stdin.take().unwrap();
    let mut output = BufReader::new(server.stdout.take().unwrap()).lines();
    let mut errors = server.stderr.take().unwrap();
    let result: Result<(), String> = async {
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"synthetic-cold-stdio","version":"1"}}});
        let mut bytes = serde_json::to_vec(&init).unwrap(); bytes.push(b'\n');
        input.write_all(&bytes).await.map_err(|e| e.to_string())?;
        input.flush().await.map_err(|e| e.to_string())?;
        let line = timeout(RESPONSE_TIMEOUT,output.next_line()).await.map_err(|_| "cold MCP handshake timed out")?
            .map_err(|e|e.to_string())?.ok_or("MCP closed before initialization")?;
        let initialized: Value = serde_json::from_str(&line).map_err(|e|e.to_string())?;
        if initialized["result"]["serverInfo"]["name"] != "ghidra-mcp" { return Err(format!("invalid initialization: {initialized}")); }
        input.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.map_err(|e|e.to_string())?;
        input.flush().await.map_err(|e|e.to_string())?;
        if root.path().join("child-ready").exists() { return Err("initialization unexpectedly launched native bridge".into()); }
        let status_request = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ghidra_status","arguments":{}}});
        let mut bytes = serde_json::to_vec(&status_request).unwrap(); bytes.push(b'\n');
        input.write_all(&bytes).await.map_err(|e|e.to_string())?;
        input.flush().await.map_err(|e|e.to_string())?;
        let line = timeout(RESPONSE_TIMEOUT,output.next_line()).await.map_err(|_| "native status timed out")?
            .map_err(|e|e.to_string())?.ok_or("MCP closed before status")?;
        let status_response: Value = serde_json::from_str(&line).map_err(|e|e.to_string())?;
        if status_response["result"]["structuredContent"]["version"] != "synthetic-transport-fixture" { return Err(format!("invalid status: {status_response}")); }
        drop(input);
        let status = timeout(RESPONSE_TIMEOUT,server.wait()).await.map_err(|_| "MCP did not exit after stdin closed")?.map_err(|e|e.to_string())?;
        if !status.success() { return Err(format!("MCP exited with {status}")); }
        let trailing = timeout(Duration::from_secs(5),output.next_line()).await.map_err(|_| "MCP stdout remained inherited after Rust exited")?.map_err(|e|e.to_string())?;
        if trailing.is_some() { return Err("unexpected trailing MCP stdout".into()); }
        let mut stderr = Vec::new();
        timeout(Duration::from_secs(5),errors.read_to_end(&mut stderr)).await.map_err(|_| "MCP stderr remained inherited after Rust exited")?.map_err(|e|e.to_string())?;
        if !stderr.is_empty() { return Err(format!("unexpected MCP stderr: {}",String::from_utf8_lossy(&stderr))); }
        if !root.path().join("child-ready").exists() || root.path().join("child-finished").exists() {
            return Err("synthetic bridge did not remain running through MCP shutdown".into());
        }
        Ok(())
    }.await;
    // Release our synthetic descendant even when the regression is detected. Never touch Ghidra.
    fs::write(root.path().join("release-child"), b"release")
        .await
        .unwrap();
    let cleanup = timeout(RESPONSE_TIMEOUT, async {
        while !root.path().join("child-finished").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    stop.send(true).unwrap();
    task.await.unwrap();
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        cleanup.is_ok(),
        "synthetic grandchild failed to stop after release"
    );
}
