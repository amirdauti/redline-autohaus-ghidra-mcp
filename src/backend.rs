use crate::{
    domain::{self, Validate},
    launch,
    mailbox::Mailbox,
};
use serde::Serialize;
use serde_json::Value;
use std::{path::PathBuf, time::Duration};

mod inspection;

struct ConnectionConfig {
    directory: PathBuf,
    launch_config: Option<PathBuf>,
    timeout: Duration,
}

impl ConnectionConfig {
    async fn prepare(&self, mailbox: &Mailbox, launch_uncertain: &mut bool) -> Result<(), String> {
        mailbox.ensure_reusable()?;
        if *launch_uncertain {
            return Err("bridge startup outcome is uncertain; inspect the launcher logs and native process before restarting this MCP client. No automatic relaunch or request is allowed".into());
        }
        if let Some(config) = &self.launch_config {
            launch::validate_config(config, &self.directory)?;
            if !launch::bridge_running(&self.directory)? {
                // Cancellation may leave the Java descendant alive. Only confirmed
                // readiness clears this latch; another tool call must not relaunch.
                *launch_uncertain = true;
                launch::ensure_bridge(config, &self.directory).await?;
                if !launch::bridge_running(&self.directory)? {
                    return Err("launcher reported ready without bridge ownership; inspect native startup before restarting this MCP client".into());
                }
                *launch_uncertain = false;
            }
        }
        if !launch::bridge_running(&self.directory)? {
            return Err("Ghidra bridge is not running; start the headless or GUI bridge, or configure --launch-config for automatic Windows headless startup, then call ghidra_status again. No request was sent".into());
        }
        Ok(())
    }
}

pub struct Backend {
    mailbox: Option<Mailbox>,
    connection_config: Option<ConnectionConfig>,
    launch_uncertain: bool,
}

impl Backend {
    pub fn new(mailbox: Mailbox) -> Self {
        Self {
            mailbox: Some(mailbox),
            connection_config: None,
            launch_uncertain: false,
        }
    }

    /// MCP discovery must not depend on native availability or another client's
    /// ownership. Native connection errors remain recoverable tool errors until
    /// a request is actually dispatched; uncertain exchanges still fail closed.
    pub fn configured(
        directory: PathBuf,
        launch_config: Option<PathBuf>,
        timeout: Duration,
    ) -> Result<Self, String> {
        if !directory.is_absolute() {
            return Err("bridge directory must be an absolute path".into());
        }
        if !(Duration::from_millis(100)..=Duration::from_secs(120)).contains(&timeout) {
            return Err("timeout must be between 100 and 120000 milliseconds".into());
        }
        Ok(Self {
            mailbox: None,
            connection_config: Some(ConnectionConfig {
                directory,
                launch_config,
                timeout,
            }),
            launch_uncertain: false,
        })
    }

    async fn connected_mailbox(&mut self) -> Result<&mut Mailbox, String> {
        if let Some(config) = &self.connection_config {
            if let Some(mailbox) = &self.mailbox {
                config.prepare(mailbox, &mut self.launch_uncertain).await?;
            } else {
                let mailbox = Mailbox::open(&config.directory, config.timeout)?;
                config.prepare(&mailbox, &mut self.launch_uncertain).await?;
                self.mailbox = Some(mailbox);
            }
        }
        self.mailbox
            .as_mut()
            .ok_or_else(|| "missing mailbox configuration".into())
    }

    pub async fn execute<T: Validate + Serialize>(
        &mut self,
        operation: &str,
        params: &T,
    ) -> Result<Value, String> {
        params
            .validate()
            .map_err(|e| format!("invalid_argument: {e}"))?;
        let params = serde_json::to_value(params).map_err(|e| e.to_string())?;
        self.connected_mailbox()
            .await?
            .call_validated(operation, params.clone(), |value| {
                validate_result(operation, &params, value)
            })
            .await
    }
}

fn string<'a>(value: &'a Value, name: &str, max: usize) -> Result<&'a str, String> {
    let field = value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or invalid {name}"))?;
    domain::text(field, name, max)?;
    Ok(field)
}

fn same_address(value: &Value, params: &Value) -> Result<(), String> {
    let actual = string(value, "address", 512)?;
    let expected = params["address"]
        .as_str()
        .ok_or("missing requested address")?;
    if domain::address(actual)? != domain::address(expected)? {
        return Err("returned address does not match request".into());
    }
    Ok(())
}

fn array<'a>(value: &'a Value, name: &str) -> Result<&'a Vec<Value>, String> {
    value
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing {name} array"))
}

fn boolean(value: &Value, name: &str) -> Result<bool, String> {
    value
        .get(name)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing {name} Boolean"))
}

/// Validate stable result invariants without treating unclassified analysis metadata as executable input.
fn validate_result(operation: &str, params: &Value, value: &Value) -> Result<(), String> {
    if !value.is_object() {
        return Err("result must be an object".into());
    }
    match operation {
        "get_comments" | "get_data" | "get_pcode" => {
            inspection::validate(operation, params, value)?
        }
        "status" => {
            if string(value, "backend", 64)? != "ghidra" {
                return Err("unexpected backend".into());
            }
            if !matches!(string(value, "mode", 64)?, "gui" | "headless") {
                return Err("unexpected bridge mode".into());
            }
            string(value, "version", 128)?;
            for capability in array(value, "capabilities")? {
                domain::text(
                    capability.as_str().ok_or("capability must be a string")?,
                    "capability",
                    128,
                )?;
            }
        }
        "list_languages" => {
            for language in array(value, "languages")? {
                for field in ["id", "processor", "endian", "description"] {
                    string(language, field, 4096)?;
                }
                if language
                    .get("size")
                    .and_then(Value::as_u64)
                    .is_none_or(|n| n == 0)
                {
                    return Err("invalid language size".into());
                }
                for compiler in array(language, "compilers")? {
                    string(compiler, "id", 256)?;
                    string(compiler, "name", 1024)?;
                }
            }
        }
        "get_project" | "create_project" | "open_project" => {
            domain::identity(string(value, "id", 512)?)?;
            string(value, "name", 1024)?;
            string(value, "path", 4096)?;
        }
        "get_program" | "save_program" | "import_program" | "select_program" | "set_image_base" => {
            let id = string(value, "id", 512)?;
            let project_id = string(value, "project_id", 512)?;
            if params
                .get("expected_program_id")
                .is_some_and(|expected| expected != id)
            {
                return Err("returned program identity does not match request".into());
            }
            if params
                .get("expected_project_id")
                .is_some_and(|expected| expected != project_id)
            {
                return Err("returned project identity does not match request".into());
            }
            for field in [
                "name",
                "program_path",
                "language_id",
                "compiler_spec_id",
                "image_base",
            ] {
                string(value, field, 4096)?;
            }
            if let Some(hash) = value.get("source_sha256").and_then(Value::as_str) {
                if hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return Err("invalid source_sha256".into());
                }
            } else if value.get("source_sha256") != Some(&Value::Null) {
                return Err("missing source_sha256".into());
            }
            if !value.get("memory_blocks").is_some_and(Value::is_array)
                || !value.get("changed").is_some_and(Value::is_boolean)
            {
                return Err("missing memory_blocks or changed state".into());
            }
        }
        "read_bytes" => {
            same_address(value, params)?;
            let bytes = value
                .get("bytes")
                .and_then(Value::as_array)
                .ok_or("missing bytes array")?;
            if Some(bytes.len() as u64) != params["count"].as_u64()
                || bytes.iter().any(|b| b.as_u64().is_none_or(|n| n > 255))
            {
                return Err("byte response must contain exactly count unsigned bytes".into());
            }
        }
        "list_programs" => {
            if value.get("project_id") != params.get("expected_project_id") {
                return Err("returned project identity does not match request".into());
            }
            for program in array(value, "programs")? {
                string(program, "name", 1024)?;
                string(program, "program_path", 4096)?;
            }
        }
        "close_project" => {
            if !boolean(value, "closed")? {
                return Err("project closure not confirmed".into());
            }
        }
        "analyze" | "job_status" => {
            let id = string(value, "job_id", 512)?;
            if params.get("job_id").is_some_and(|expected| expected != id) {
                return Err("job identity mismatch".into());
            }
            if !matches!(
                string(value, "state", 64)?,
                "queued" | "running" | "completed" | "failed" | "cancelled"
            ) {
                return Err("unrecognized analysis state".into());
            }
        }
        "map_file_offset" => {
            if value.get("file_offset") != params.get("file_offset") {
                return Err("returned file offset does not match request".into());
            }
            string(value, "source_file", 4096)?;
            for field in ["source_file_offset", "source_size"] {
                if value.get(field).and_then(Value::as_u64).is_none() {
                    return Err(format!("invalid {field}"));
                }
            }
            let matches = array(value, "matches")?;
            if boolean(value, "ambiguous")? != (matches.len() > 1) {
                return Err("inconsistent mapping ambiguity flag".into());
            }
            for matched in matches {
                domain::address(string(matched, "address", 512)?)?;
                string(matched, "block", 1024)?;
                string(matched, "source_file", 4096)?;
                if matched.get("file_offset") != params.get("file_offset") {
                    return Err("mapping provenance offset mismatch".into());
                }
            }
        }
        "decompile" => {
            domain::address(string(value, "address", 512)?)?;
            string(value, "name", 4096)?;
            let c = value
                .get("c")
                .and_then(Value::as_str)
                .ok_or("missing decompiler C text")?;
            if c.len() > 1_048_576 {
                return Err("decompiler C text exceeds 1 MiB".into());
            }
        }
        "disassemble" => {
            same_address(value, params)?;
            let instructions = array(value, "instructions")?;
            if instructions.len() as u64 > params["count"].as_u64().unwrap_or_default() {
                return Err("instruction response exceeds count".into());
            }
            for instruction in instructions {
                domain::address(string(instruction, "address", 512)?)?;
                let bytes = array(instruction, "bytes")?;
                if instruction.get("length").and_then(Value::as_u64) != Some(bytes.len() as u64)
                    || bytes.is_empty()
                    || bytes.iter().any(|b| b.as_u64().is_none_or(|n| n > 255))
                {
                    return Err("invalid instruction length/bytes".into());
                }
                string(instruction, "mnemonic", 1024)?;
                string(instruction, "text", 65536)?;
            }
        }
        "get_references" => {
            same_address(value, params)?;
            if value.get("direction") != params.get("direction") {
                return Err("reference direction mismatch".into());
            }
            let refs = array(value, "refs")?;
            if refs.len() as u64 > params["limit"].as_u64().unwrap_or_default() {
                return Err("references exceed limit".into());
            }
            boolean(value, "truncated")?;
            for reference in refs {
                for field in ["from", "to"] {
                    domain::address(string(reference, field, 512)?)?;
                }
            }
        }
        "search_bytes" => {
            let matches = array(value, "matches")?;
            if matches.len() as u64 > params["limit"].as_u64().unwrap_or_default() {
                return Err("search result exceeds limit".into());
            }
            boolean(value, "truncated")?;
            for matched in matches {
                domain::address(matched.as_str().ok_or("search match must be an address")?)?;
            }
        }
        "set_label" | "set_comment" => {
            same_address(value, params)?;
            let field = if operation == "set_label" {
                "name"
            } else {
                "comment"
            };
            if value.get(field) != params.get(field) {
                return Err("metadata readback does not match request".into());
            }
        }
        "list_functions" | "list_symbols" | "list_strings" => {
            let key = match operation {
                "list_functions" => "functions",
                "list_symbols" => "symbols",
                _ => "strings",
            };
            let items = value
                .get(key)
                .and_then(Value::as_array)
                .ok_or_else(|| format!("missing {key} array"))?;
            if items.len() as u64 > params["limit"].as_u64().unwrap_or_default() {
                return Err("result exceeds requested page limit".into());
            }
            if let Some(total) = value.get("total") {
                if total.as_u64().is_none_or(|n| n < items.len() as u64) {
                    return Err("invalid total count".into());
                }
            }
        }
        _ => {}
    }
    Ok(())
}
