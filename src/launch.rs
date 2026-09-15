//! Optional Windows bridge bootstrap. Rust always retains MCP stdin/stdout ownership.
//!
//! The short-lived launcher receives no stdin. Its output is captured, never forwarded to MCP
//! stdout. Only the launcher helper is bounded/killed on timeout; a started Java bridge remains
//! independent so closing an MCP connection cannot discard an unsaved Ghidra project.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchConfig {
    launcher_script: PathBuf,
    ghidra_home: PathBuf,
    java_home: PathBuf,
    adapter_jar: PathBuf,
    bridge_dir: PathBuf,
    project_root: PathBuf,
    import_roots: Vec<PathBuf>,
}

fn absolute(path: &Path, field: &str) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("launch config {field} must be an absolute path"));
    }
    Ok(())
}

fn existing(path: &Path, field: &str, directory: bool) -> Result<(), String> {
    absolute(path, field)?;
    if (directory && !path.is_dir()) || (!directory && !path.is_file()) {
        return Err(format!(
            "launch config {field} must be an existing {}",
            if directory { "directory" } else { "file" }
        ));
    }
    Ok(())
}

fn load_config(path: &Path, expected_bridge_dir: &Path) -> Result<LaunchConfig, String> {
    existing(path, "file", false)?;
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.len() > 65536 {
        return Err("launch config exceeds 64 KiB".into());
    }
    // Windows PowerShell can write a UTF-8 BOM. It is not part of the JSON document.
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read launch config: {e}"))?;
    if bytes.len() > 65536 {
        return Err("launch config exceeds 64 KiB".into());
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    let config: LaunchConfig =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid launch config: {e}"))?;
    existing(&config.launcher_script, "launcher_script", false)?;
    existing(&config.ghidra_home, "ghidra_home", true)?;
    existing(&config.java_home, "java_home", true)?;
    existing(&config.adapter_jar, "adapter_jar", false)?;
    existing(&config.project_root, "project_root", true)?;
    if config.import_roots.is_empty() || config.import_roots.len() > 64 {
        return Err("launch config import_roots must contain 1 to 64 existing directories".into());
    }
    for root in &config.import_roots {
        existing(root, "import_roots entry", true)?;
    }
    absolute(&config.bridge_dir, "bridge_dir")?;
    absolute(expected_bridge_dir, "--bridge-dir")?;
    // Only the explicitly selected CLI mailbox may be created; an unrelated config directory
    // must not be created merely to discover that it does not match.
    std::fs::create_dir_all(expected_bridge_dir)
        .map_err(|e| format!("cannot create bridge directory: {e}"))?;
    let expected = expected_bridge_dir
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if config
        .bridge_dir
        .canonicalize()
        .map_err(|_| "launch config bridge_dir must match --bridge-dir".to_string())?
        != expected
    {
        return Err("launch config bridge_dir must match --bridge-dir".into());
    }
    Ok(config)
}

#[cfg(any(windows, test))]
fn bridge_running(directory: &Path) -> Result<bool, String> {
    use fs2::FileExt;
    let probe = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("bridge.lock"))
        .map_err(|e| format!("cannot probe bridge.lock: {e}"))?;
    match probe.try_lock_exclusive() {
        Ok(()) => {
            // Closing this independent handle releases the probe before any launcher is spawned.
            drop(probe);
            Ok(false)
        }
        Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock
                || error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
        {
            Ok(true)
        }
        Err(error) => Err(format!("cannot probe bridge ownership: {error}")),
    }
}

pub async fn ensure_bridge(config_path: &Path, bridge_dir: &Path) -> Result<(), String> {
    let config = load_config(config_path, bridge_dir)?;
    #[cfg(windows)]
    {
        windows::launch_if_needed(config_path, &config).await
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        Err("--launch-config is supported only on Windows; start the bridge separately on this platform".into())
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        process::Stdio,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt},
        process::Command,
        task::JoinHandle,
    };

    const CAPTURE_LIMIT: usize = 131072;
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(55);

    #[derive(Default)]
    struct Capture {
        bytes: Vec<u8>,
        truncated: bool,
        finished: bool,
        read_error: Option<String>,
        changed: Arc<tokio::sync::Notify>,
    }

    fn capture<R: AsyncRead + Unpin + Send + 'static>(
        mut reader: R,
    ) -> (Arc<Mutex<Capture>>, JoinHandle<Result<(), String>>) {
        let captured = Arc::new(Mutex::new(Capture::default()));
        let output = captured.clone();
        let task = tokio::spawn(async move {
            let mut chunk = [0_u8; 8192];
            loop {
                let count = match reader.read(&mut chunk).await {
                    Ok(count) => count,
                    Err(error) => {
                        let mut output = output
                            .lock()
                            .map_err(|_| "launcher log lock poisoned".to_string())?;
                        output.finished = true;
                        output.read_error = Some(error.to_string());
                        output.changed.notify_one();
                        return Err(error.to_string());
                    }
                };
                if count == 0 {
                    let mut output = output
                        .lock()
                        .map_err(|_| "launcher log lock poisoned".to_string())?;
                    output.finished = true;
                    output.changed.notify_one();
                    return Ok(());
                }
                let mut output = output
                    .lock()
                    .map_err(|_| "launcher log lock poisoned".to_string())?;
                let keep = count.min(CAPTURE_LIMIT.saturating_sub(output.bytes.len()));
                output.bytes.extend_from_slice(&chunk[..keep]);
                output.truncated |= keep < count;
                output.changed.notify_one();
                // Keep draining even after the bounded capture fills, so the child cannot block
                // on a full pipe and callers never allocate unbounded launcher output.
            }
        });
        (captured, task)
    }

    fn log_text(capture: &Arc<Mutex<Capture>>) -> String {
        let captured = capture.lock().unwrap_or_else(|e| e.into_inner());
        let mut text = String::from_utf8_lossy(&captured.bytes).into_owned();
        if captured.truncated {
            text.push_str("\n[launcher output truncated]");
        }
        text
    }

    async fn wait_for_readiness(stdout: &Arc<Mutex<Capture>>) -> Result<(), String> {
        let changed = stdout
            .lock()
            .map_err(|_| "launcher log lock poisoned".to_string())?
            .changed
            .clone();
        loop {
            let notification = changed.notified();
            {
                let output = stdout
                    .lock()
                    .map_err(|_| "launcher log lock poisoned".to_string())?;
                if let Some(error) = &output.read_error {
                    return Err(format!("cannot read launcher output: {error}"));
                }
                if output.truncated {
                    return Err("bridge launcher readiness output exceeds capture limit".into());
                }
                let bytes = output
                    .bytes
                    .strip_prefix(&[0xef, 0xbb, 0xbf])
                    .unwrap_or(&output.bytes);
                match serde_json::from_slice::<serde_json::Value>(bytes) {
                    Ok(ready) => {
                        if ready.get("state").and_then(serde_json::Value::as_str) != Some("ready") {
                            return Err("bridge launcher did not report state ready".into());
                        }
                        return Ok(());
                    }
                    Err(error) if error.is_eof() && !output.finished => {}
                    Err(error) => return Err(format!("invalid launcher readiness JSON: {error}")),
                }
            }
            notification.await;
        }
    }

    pub(super) async fn launch_if_needed(
        config_path: &Path,
        config: &LaunchConfig,
    ) -> Result<(), String> {
        protect_mcp_standard_handles()?;
        if bridge_running(&config.bridge_dir)? {
            return Ok(());
        }
        // Resolve the OS copy explicitly. A bare executable name would let Windows search
        // the current workspace and PATH before reaching the intended system launcher.
        let system_root = std::env::var_os("SystemRoot")
            .ok_or("SystemRoot is unavailable; cannot locate Windows PowerShell")?;
        let powershell = PathBuf::from(system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if !powershell.is_absolute() || !powershell.is_file() {
            return Err("Windows system PowerShell is unavailable; no PATH or workspace fallback is permitted".into());
        }
        let mut command = Command::new(powershell);
        command
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&config.launcher_script)
            .arg("-ConfigPath")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(0x08000000) // CREATE_NO_WINDOW: bootstrap is not an interactive console.
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot start bridge launcher: {e}"))?;
        let (stdout, out_task) =
            capture(child.stdout.take().ok_or("missing launcher stdout pipe")?);
        let (stderr, err_task) =
            capture(child.stderr.take().ok_or("missing launcher stderr pipe")?);
        let outcome = tokio::time::timeout(STARTUP_TIMEOUT, async {
            let status = child.wait().await.map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("bridge launcher exited with {status}"));
            }
            // A Java descendant can retain a duplicate pipe handle after the launcher exits.
            // Readiness is complete JSON plus successful helper exit, not descendant pipe EOF.
            wait_for_readiness(&stdout).await
        })
        .await;
        // Abort reader tasks if the timeout interrupted waiting. Kill only our launcher helper,
        // never the independently started Java daemon; the native outcome may need inspection.
        let result = match outcome {
            Ok(result) => result,
            Err(_) => {
                let _ = child.start_kill();
                Err("bridge startup timed out after 55 seconds; inspect launcher/native state before restarting; no automatic retry".into())
            }
        };
        out_task.abort();
        err_task.abort();
        result.map_err(|error| {
            format!(
                "{error}\nlauncher stdout:\n{}\nlauncher stderr:\n{}",
                log_text(&stdout),
                log_text(&stderr)
            )
        })
    }

    fn protect_mcp_standard_handles() -> Result<(), String> {
        use windows_sys::Win32::{
            Foundation::{HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation},
            System::Console::{
                GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
            },
        };
        for (name, selector) in [
            ("stdin", STD_INPUT_HANDLE),
            ("stdout", STD_OUTPUT_HANDLE),
            ("stderr", STD_ERROR_HANDLE),
        ] {
            // SAFETY: These selectors retrieve borrowed process-owned handles. We never close
            // them or change their I/O state, only their inheritance flag before child creation.
            let handle = unsafe { GetStdHandle(selector) };
            if handle.is_null() {
                continue;
            }
            if handle == INVALID_HANDLE_VALUE {
                return Err(format!(
                    "cannot locate MCP {name} handle: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: `handle` is a valid process standard handle and the mask/flags only clear
            // HANDLE_FLAG_INHERIT. The launcher's separately created pipe handles remain usable.
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
                return Err(format!(
                    "cannot prevent inheritance of MCP {name}: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(root: &Path) -> (PathBuf, serde_json::Value) {
        let script = root.join("launcher.ps1");
        let jar = root.join("adapter.jar");
        std::fs::write(
            &script,
            b"# Synthetic path validation fixture; never executed",
        )
        .unwrap();
        std::fs::write(
            &jar,
            b"Synthetic path validation fixture; not a Java archive",
        )
        .unwrap();
        let config = json!({"launcher_script":script,"ghidra_home":root,"java_home":root,"adapter_jar":jar,"bridge_dir":root.join("bridge"),"project_root":root,"import_roots":[root]});
        (root.join("config.json"), config)
    }

    #[test]
    fn config_is_strict_bounded_and_mailbox_identity_checked_before_launch() {
        let root = tempfile::tempdir().unwrap();
        let (path, valid) = fixture(root.path());
        let bridge = root.path().join("bridge");
        std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        load_config(&path, &bridge).unwrap();
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend(serde_json::to_vec(&valid).unwrap());
        std::fs::write(&path, bom).unwrap();
        load_config(&path, &bridge).unwrap();
        for (key, value) in [
            ("extra", json!(true)),
            ("launcher_script", json!("relative.ps1")),
            ("adapter_jar", json!(root.path().join("missing.jar"))),
            ("import_roots", json!([])),
            ("bridge_dir", json!(root.path())),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value;
            std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(load_config(&path, &bridge).is_err(), "{key}");
        }
    }

    #[test]
    fn bridge_probe_detects_held_lock_and_releases_its_own_lock() {
        use fs2::FileExt;
        let root = tempfile::tempdir().unwrap();
        assert!(!bridge_running(root.path()).unwrap());
        let native = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.path().join("bridge.lock"))
            .unwrap();
        native.try_lock_exclusive().unwrap();
        assert!(bridge_running(root.path()).unwrap());
        drop(native);
        assert!(!bridge_running(root.path()).unwrap());
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn non_windows_launch_is_explicitly_unsupported() {
        let root = tempfile::tempdir().unwrap();
        let (path, valid) = fixture(root.path());
        std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        let error = ensure_bridge(&path, &root.path().join("bridge"))
            .await
            .unwrap_err();
        assert!(error.contains("supported only on Windows"));
        assert!(!root.path().join("bridge/bridge.lock").exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn readiness_does_not_wait_for_grandchild_to_close_inherited_pipes() {
        use std::time::Duration;
        let root = tempfile::tempdir().unwrap();
        let (path, valid) = fixture(root.path());
        std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        std::fs::write(root.path().join("grandchild.ps1"), r#"
param([string]$Root)
[IO.File]::WriteAllText((Join-Path $Root 'child-ready'), 'ready')
$watch = [Diagnostics.Stopwatch]::StartNew()
while (-not [IO.File]::Exists((Join-Path $Root 'release-child')) -and $watch.Elapsed.TotalSeconds -lt 30) {
    Start-Sleep -Milliseconds 10
}
[IO.File]::WriteAllText((Join-Path $Root 'child-finished'), 'finished')
"#).unwrap();
        std::fs::write(root.path().join("launcher.ps1"), r#"
param([string]$ConfigPath)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetDirectoryName($ConfigPath)
$info = New-Object Diagnostics.ProcessStartInfo
$info.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$info.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $root 'grandchild.ps1') + '" -Root "' + $root + '"'
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
# All three standard handles are inherited. No daemon/Ghidra process is involved.
$child = [Diagnostics.Process]::Start($info)
$watch = [Diagnostics.Stopwatch]::StartNew()
while (-not [IO.File]::Exists((Join-Path $root 'child-ready'))) {
    if ($watch.Elapsed.TotalSeconds -gt 15) { throw 'Synthetic grandchild did not start' }
    Start-Sleep -Milliseconds 10
}
[Console]::Out.WriteLine('{"state":"ready"}')
"#).unwrap();
        let bridge = root.path().join("bridge");
        let mut launch = tokio::spawn(async move { ensure_bridge(&path, &bridge).await });
        let child_ready = root.path().join("child-ready");
        let barrier = tokio::time::timeout(Duration::from_secs(15), async {
            while !child_ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let result = tokio::time::timeout(Duration::from_secs(5), &mut launch).await;
        let child_still_running = !root.path().join("child-finished").exists();
        // Always release the owned synthetic grandchild before asserting, including regressions.
        std::fs::write(root.path().join("release-child"), b"release").unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            while !root.path().join("child-finished").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let outcome = match result {
            Ok(outcome) => outcome.unwrap(),
            Err(_) => {
                let _ = tokio::time::timeout(Duration::from_secs(15), &mut launch).await;
                Err(
                    "launcher waited for descendant pipe EOF despite complete readiness JSON"
                        .into(),
                )
            }
        };
        assert!(
            barrier.is_ok(),
            "synthetic grandchild did not reach pipe-holding barrier"
        );
        assert!(
            child_still_running,
            "test did not hold inherited pipes open"
        );
        assert!(outcome.is_ok(), "{outcome:?}");
    }
}
