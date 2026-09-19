//! Locked, bounded file transport. Synthetic transport tests do not establish native Ghidra support.

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};

pub const MAX_REQUEST_BYTES: usize = 1_048_576;
pub const MAX_RESPONSE_BYTES: usize = 8_388_608;

#[derive(Serialize)]
struct Request<'a> {
    protocol: u32,
    id: &'a str,
    operation: &'a str,
    params: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    protocol: u32,
    id: String,
    ok: bool,
    result: Option<Value>,
    error: Option<BridgeError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeError {
    code: String,
    message: String,
}

pub struct Mailbox {
    directory: PathBuf,
    timeout: Duration,
    _lock: File,
    failed: bool,
}

fn pending_name(name: &str) -> bool {
    matches!(
        name,
        "client.pending"
            | "request.json"
            | "response.json"
            | "request.tmp"
            | "response.tmp"
            | "stop"
    ) || (name.ends_with(".tmp") && (name.starts_with("request.") || name.starts_with("response.")))
}

fn ensure_idle(directory: &Path) -> Result<(), String> {
    for entry in std::fs::read_dir(directory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if pending_name(&entry.file_name().to_string_lossy()) {
            return Err(format!(
                "unfinished or stopped mailbox file {}; inspect Ghidra and recover before restarting",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    Ok(())
}

impl Mailbox {
    pub fn open(directory: &Path, timeout: Duration) -> Result<Self, String> {
        if !directory.is_absolute() {
            return Err("bridge directory must be an absolute path".into());
        }
        if !(Duration::from_millis(100)..=Duration::from_secs(120)).contains(&timeout) {
            return Err("timeout must be between 100 and 120000 milliseconds".into());
        }
        std::fs::create_dir_all(directory)
            .map_err(|e| format!("cannot create bridge directory: {e}"))?;
        let directory = directory.canonicalize().map_err(|e| e.to_string())?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("client.lock"))
            .map_err(|e| format!("cannot open mailbox lock: {e}"))?;
        lock.try_lock_exclusive()
            .map_err(|_| "another MCP client owns this bridge directory; disconnect that client, then call ghidra_status again. No request was sent".to_string())?;
        ensure_idle(&directory)?;
        Ok(Self {
            directory,
            timeout,
            _lock: lock,
            failed: false,
        })
    }

    pub async fn call(&mut self, operation: &str, params: Value) -> Result<Value, String> {
        self.call_validated(operation, params, |_| Ok(())).await
    }

    /// Check before any launcher runs. An uncertain exchange must never trigger a
    /// replacement bridge, even if the prior native process has disappeared.
    pub(crate) fn ensure_reusable(&self) -> Result<(), String> {
        if self.failed {
            return Err("bridge connection stopped after an uncertain exchange; inspect Ghidra and recover the mailbox before restarting; do not retry mutations".into());
        }
        ensure_idle(&self.directory)
    }

    /// Result validation runs before removing either response or durable pending guard.
    pub async fn call_validated<F>(
        &mut self,
        operation: &str,
        params: Value,
        validate: F,
    ) -> Result<Value, String>
    where
        F: FnOnce(&Value) -> Result<(), String>,
    {
        if self.failed {
            return Err("bridge connection stopped after an uncertain exchange; inspect Ghidra and recover the mailbox before restarting; do not retry mutations".into());
        }
        if !params.is_object() {
            return Err("bridge params must be an object".into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        let bytes = serde_json::to_vec(&Request {
            protocol: 1,
            id: &id,
            operation,
            params,
        })
        .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("bridge request exceeds 1 MiB".into());
        }
        // Cancellation leaves both the in-memory poison and durable marker in place.
        self.failed = true;
        ensure_idle(&self.directory)?;
        let marker_path = self.directory.join("client.pending");
        let mut marker = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker_path)
            .await
            .map_err(|e| e.to_string())?;
        marker
            .write_all(
                &serde_json::to_vec(&json!({"id": id, "operation": operation}))
                    .map_err(|e| e.to_string())?,
            )
            .await
            .map_err(|e| e.to_string())?;
        marker.sync_all().await.map_err(|e| e.to_string())?;
        drop(marker);
        let temporary = self.directory.join(format!("request.{id}.tmp"));
        let mut request_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
            .map_err(|e| e.to_string())?;
        request_file
            .write_all(&bytes)
            .await
            .map_err(|e| e.to_string())?;
        request_file.sync_all().await.map_err(|e| e.to_string())?;
        drop(request_file);
        fs::rename(&temporary, self.directory.join("request.json"))
            .await
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + self.timeout;
        let response_path = self.directory.join("response.json");
        loop {
            if fs::try_exists(&response_path)
                .await
                .map_err(|e| e.to_string())?
            {
                let mut bytes = Vec::new();
                fs::File::open(&response_path)
                    .await
                    .map_err(|e| e.to_string())?
                    .take(MAX_RESPONSE_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .await
                    .map_err(|e| e.to_string())?;
                if bytes.len() > MAX_RESPONSE_BYTES {
                    return Err("bridge response exceeds 8 MiB; mailbox requires recovery".into());
                }
                let response: Response = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("invalid bridge response: {e}"))?;
                if response.protocol != 1 || response.id != id {
                    return Err(
                        "bridge response ID or protocol mismatch; mailbox requires recovery".into(),
                    );
                }
                let raw: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                if response.ok
                    && (!response.result.as_ref().is_some_and(Value::is_object)
                        || raw.get("error").is_some())
                    || !response.ok && (response.error.is_none() || raw.get("result").is_some())
                {
                    return Err("inconsistent bridge response envelope".into());
                }
                if fs::try_exists(self.directory.join("request.json"))
                    .await
                    .map_err(|e| e.to_string())?
                {
                    return Err("bridge published a response before consuming its request".into());
                }
                let outcome = if response.ok {
                    let result = response.result.unwrap();
                    validate(&result).map_err(|e| {
                        format!("invalid {operation} result: {e}; mailbox requires recovery")
                    })?;
                    Ok(result)
                } else {
                    let error = response.error.unwrap();
                    if error.code.is_empty()
                        || error.code.len() > 128
                        || !error
                            .code
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
                        || error.message.trim().is_empty()
                        || error.message.chars().count() > 8192
                    {
                        return Err("invalid bridge error fields".into());
                    }
                    if matches!(error.code.as_str(), "mutation_uncertain" | "bridge_halted") {
                        return Err(format!(
                            "{}: {}; mailbox requires recovery",
                            error.code, error.message
                        ));
                    }
                    Err(format!("{}: {}", error.code, error.message))
                };
                fs::remove_file(&response_path)
                    .await
                    .map_err(|e| e.to_string())?;
                fs::remove_file(&marker_path)
                    .await
                    .map_err(|e| e.to_string())?;
                self.failed = false;
                return outcome;
            }
            if Instant::now() >= deadline {
                return Err("Ghidra bridge timed out; outcome may be unknown. Do not retry mutations; inspect Ghidra and recover the mailbox".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
