//! Connection lifecycle tests use file peers, never customer projects or native Ghidra.
use fs2::FileExt;
use ghidra_mcp::{backend::Backend, domain::EmptyParams};
use serde_json::{Value, json};
use std::{
    fs::File,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{fs, time::timeout};

fn native_lock(root: &Path) -> File {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join("bridge.lock"))
        .unwrap();
    file.try_lock_exclusive().unwrap();
    file
}

fn config(root: &Path, script: &str) -> PathBuf {
    let launcher = root.join("launcher.ps1");
    std::fs::write(&launcher, script).unwrap();
    let jar = root.join("synthetic.jar");
    std::fs::write(&jar, b"path validation fixture").unwrap();
    let path = root.join("launch.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "launcher_script":launcher,"ghidra_home":root,"java_home":root,
            "adapter_jar":jar,"bridge_dir":root,"project_root":root,"import_roots":[root]
        }))
        .unwrap(),
    )
    .unwrap();
    path
}

async fn request(root: &Path) -> Value {
    timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(bytes) = fs::read(root.join("request.json")).await {
                let value = serde_json::from_slice(&bytes).unwrap();
                fs::remove_file(root.join("request.json")).await.unwrap();
                return value;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

async fn publish(root: &Path, response: Value) {
    fs::write(
        root.join("response.test.tmp"),
        serde_json::to_vec(&response).unwrap(),
    )
    .await
    .unwrap();
    fs::rename(root.join("response.test.tmp"), root.join("response.json"))
        .await
        .unwrap();
}

#[tokio::test]
async fn uncertain_exchange_blocks_relaunch_after_native_owner_disappears() {
    for kind in ["timeout", "cancel", "malformed", "mutation_uncertain"] {
        let root = tempfile::tempdir().unwrap();
        let native = native_lock(root.path());
        let path = config(
            root.path(),
            "throw 'Launcher must not run after an uncertain exchange'",
        );
        let mut backend = Backend::configured(
            root.path().to_owned(),
            Some(path),
            Duration::from_millis(200),
        )
        .unwrap();
        let peer_root = root.path().to_owned();
        let (sent, received) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let req = request(&peer_root).await;
            sent.send(()).unwrap();
            match kind {
                "malformed" => publish(&peer_root, json!({"protocol":1,"id":"wrong-id","ok":true,"result":{}})).await,
                "mutation_uncertain" => publish(&peer_root, json!({"protocol":1,"id":req["id"],"ok":false,"error":{"code":"mutation_uncertain","message":"Synthetic uncertain outcome"}})).await,
                _ => {}
            }
        });
        if kind == "cancel" {
            let mut call = Box::pin(backend.execute("status", &EmptyParams {}));
            tokio::select! {
                outcome = &mut call => panic!("exchange ended before cancellation: {outcome:?}"),
                _ = received => {}
            }
            drop(call);
        } else {
            assert!(backend.execute("status", &EmptyParams {}).await.is_err());
        }
        peer.await.unwrap();
        drop(native);
        let marker = fs::read(root.path().join("client.pending")).await.unwrap();
        let response = fs::read(root.path().join("response.json")).await.ok();
        let error = backend
            .execute("status", &EmptyParams {})
            .await
            .unwrap_err();
        assert!(error.contains("uncertain exchange"), "{kind}: {error}");
        assert_eq!(
            fs::read(root.path().join("client.pending")).await.unwrap(),
            marker
        );
        assert_eq!(
            fs::read(root.path().join("response.json")).await.ok(),
            response
        );
        assert!(!root.path().join("request.json").exists());
    }
}

#[tokio::test]
async fn stale_state_after_a_successful_call_prevents_launcher_and_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let native = native_lock(root.path());
    let path = config(
        root.path(),
        "throw 'Launcher must not run with stale state'",
    );
    let mut backend =
        Backend::configured(root.path().to_owned(), Some(path), Duration::from_secs(2)).unwrap();
    let peer_root = root.path().to_owned();
    let peer = tokio::spawn(async move {
        let req = request(&peer_root).await;
        publish(&peer_root, json!({"protocol":1,"id":req["id"],"ok":true,"result":{"backend":"ghidra","mode":"headless","version":"fixture","capabilities":["status"]}})).await;
    });
    backend.execute("status", &EmptyParams {}).await.unwrap();
    peer.await.unwrap();
    drop(native);
    fs::write(root.path().join("stop"), b"preserve")
        .await
        .unwrap();
    assert!(
        backend
            .execute("status", &EmptyParams {})
            .await
            .unwrap_err()
            .contains("unfinished or stopped mailbox")
    );
    assert_eq!(
        fs::read(root.path().join("stop")).await.unwrap(),
        b"preserve"
    );
    assert!(!root.path().join("client.pending").exists());
    assert!(!root.path().join("request.json").exists());
}

#[cfg(windows)]
#[tokio::test]
async fn failed_or_cancelled_launcher_is_not_reinvoked_on_the_next_call() {
    for cancel in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let script = if cancel {
            "param([string]$ConfigPath)\n$root=[IO.Path]::GetDirectoryName($ConfigPath)\n[IO.File]::AppendAllText((Join-Path $root 'attempts'), '1')\nStart-Sleep -Seconds 20\n"
        } else {
            "param([string]$ConfigPath)\n$root=[IO.Path]::GetDirectoryName($ConfigPath)\n[IO.File]::AppendAllText((Join-Path $root 'attempts'), '1')\nthrow 'Synthetic launcher failure'\n"
        };
        let path = config(root.path(), script);
        let mut backend =
            Backend::configured(root.path().to_owned(), Some(path), Duration::from_secs(2))
                .unwrap();
        if cancel {
            let mut call = Box::pin(backend.execute("status", &EmptyParams {}));
            let started = timeout(Duration::from_secs(10), async {
                while !root.path().join("attempts").exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
            tokio::select! {
                outcome = &mut call => panic!("launcher ended before cancellation: {outcome:?}"),
                result = started => result.unwrap()
            }
            drop(call);
        } else {
            assert!(
                backend
                    .execute("status", &EmptyParams {})
                    .await
                    .unwrap_err()
                    .contains("launcher exited")
            );
        }
        let error = backend
            .execute("status", &EmptyParams {})
            .await
            .unwrap_err();
        assert!(error.contains("startup outcome is uncertain"), "{error}");
        assert_eq!(fs::read(root.path().join("attempts")).await.unwrap(), b"1");
        assert!(!root.path().join("client.pending").exists());
        assert!(!root.path().join("request.json").exists());
    }
}
