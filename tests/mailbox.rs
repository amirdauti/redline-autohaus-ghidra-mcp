//! Synthetic mailbox peers only. These tests never launch or claim to validate Ghidra.
use ghidra_mcp::{
    backend::Backend,
    domain::{ReadBytesParams, Validate},
    mailbox::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Mailbox},
};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio::{
    fs,
    time::{sleep, timeout},
};

async fn request(directory: &Path) -> Value {
    timeout(Duration::from_secs(5), async {
        let file = directory.join("request.json");
        loop {
            if file.exists() {
                let request: Value =
                    serde_json::from_slice(&fs::read(&file).await.unwrap()).unwrap();
                assert_eq!(request["protocol"], 1);
                uuid::Uuid::parse_str(request["id"].as_str().unwrap()).unwrap();
                let pending: Value = serde_json::from_slice(
                    &fs::read(directory.join("client.pending")).await.unwrap(),
                )
                .unwrap();
                assert_eq!(pending["id"], request["id"]);
                assert_eq!(pending["operation"], request["operation"]);
                return request;
            }
            sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("synthetic peer did not receive request")
}

async fn publish(directory: &Path, bytes: &[u8], consume_request: bool) {
    let temp = directory.join(format!("response.{}.tmp", uuid::Uuid::new_v4()));
    fs::write(&temp, bytes).await.unwrap();
    if consume_request {
        fs::remove_file(directory.join("request.json"))
            .await
            .unwrap();
    }
    fs::rename(temp, directory.join("response.json"))
        .await
        .unwrap();
}

#[test]
fn exclusive_lock_and_all_stale_files_block_startup_without_removal() {
    let directory = tempfile::tempdir().unwrap();
    let owner = Mailbox::open(directory.path(), Duration::from_secs(1)).unwrap();
    assert!(
        Mailbox::open(directory.path(), Duration::from_secs(1))
            .err()
            .unwrap()
            .contains("another MCP")
    );
    drop(owner);
    for name in [
        "request.json",
        "response.json",
        "client.pending",
        "request.anything.tmp",
        "response.anything.tmp",
        "request.tmp",
        "response.tmp",
        "stop",
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, b"evidence").unwrap();
        assert!(
            Mailbox::open(directory.path(), Duration::from_secs(1)).is_err(),
            "{name}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"evidence");
        std::fs::remove_file(&path).unwrap();
    }
    assert!(Mailbox::open(directory.path(), Duration::from_secs(1)).is_ok());
    assert!(Mailbox::open(Path::new("relative"), Duration::from_secs(1)).is_err());
    for duration in [
        Duration::ZERO,
        Duration::from_millis(99),
        Duration::from_millis(120001),
    ] {
        assert!(Mailbox::open(directory.path(), duration).is_err());
    }
}

#[tokio::test]
async fn atomic_exchange_and_definitive_errors_allow_sequential_calls() {
    let directory = tempfile::tempdir().unwrap();
    let mut mailbox = Mailbox::open(directory.path(), Duration::from_secs(2)).unwrap();
    let peer_dir = directory.path().to_path_buf();
    let peer = tokio::spawn(async move {
        for index in 0..3 {
            let req = request(&peer_dir).await;
            let body = if index == 1 {
                json!({"protocol":1,"id":req["id"],"ok":false,"error":{"code":"invalid_argument","message":"Synthetic rejection"}})
            } else {
                json!({"protocol":1,"id":req["id"],"ok":true,"result":{"sequence":index}})
            };
            publish(&peer_dir, &serde_json::to_vec(&body).unwrap(), true).await;
            // Wait for consumption before looking for the next request.
            while peer_dir.join("response.json").exists() {
                sleep(Duration::from_millis(2)).await;
            }
        }
    });
    assert_eq!(
        mailbox.call("status", json!({})).await.unwrap()["sequence"],
        0
    );
    assert!(
        mailbox
            .call("open_project", json!({}))
            .await
            .unwrap_err()
            .contains("Synthetic rejection")
    );
    assert_eq!(
        mailbox.call("status", json!({})).await.unwrap()["sequence"],
        2
    );
    peer.await.unwrap();
    assert!(!directory.path().join("client.pending").exists());
    assert!(!directory.path().join("response.json").exists());
}

#[tokio::test]
async fn invalid_responses_poison_client_and_preserve_evidence() {
    for case in [
        "partial",
        "oversized",
        "wrong_id",
        "wrong_protocol",
        "unknown_field",
        "both_outcomes",
        "null_error",
        "bad_bytes_envelope",
        "unconsumed",
        "uncertain",
        "halted",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut mailbox = Mailbox::open(directory.path(), Duration::from_secs(2)).unwrap();
        let peer_dir = directory.path().to_path_buf();
        let peer = tokio::spawn(async move {
            let req = request(&peer_dir).await;
            let mut body = json!({"protocol":1,"id":req["id"],"ok":true,"result":{}});
            match case {
                "wrong_id" => body["id"] = json!(uuid::Uuid::new_v4().to_string()),
                "wrong_protocol" => body["protocol"] = json!(2),
                "unknown_field" => body["ignored"] = json!(true),
                "both_outcomes" => {
                    body["error"] = json!({"code":"invalid_argument","message":"bad"})
                }
                "null_error" => body["error"] = Value::Null,
                "bad_bytes_envelope" => body["result"] = json!([1, 2, 3]),
                "uncertain" => {
                    body = json!({"protocol":1,"id":req["id"],"ok":false,"error":{"code":"mutation_uncertain","message":"Synthetic uncertain result"}})
                }
                "halted" => {
                    body = json!({"protocol":1,"id":req["id"],"ok":false,"error":{"code":"bridge_halted","message":"Synthetic bridge halted"}})
                }
                _ => {}
            }
            let bytes = match case {
                "partial" => b"{\"protocol\":1,".to_vec(),
                "oversized" => vec![b' '; MAX_RESPONSE_BYTES + 1],
                _ => serde_json::to_vec(&body).unwrap(),
            };
            publish(&peer_dir, &bytes, case != "unconsumed").await;
        });
        assert!(
            mailbox.call("create_project", json!({})).await.is_err(),
            "{case}"
        );
        peer.await.unwrap();
        assert!(directory.path().join("response.json").exists(), "{case}");
        assert!(directory.path().join("client.pending").exists(), "{case}");
        assert!(
            mailbox
                .call("status", json!({}))
                .await
                .unwrap_err()
                .contains("stopped"),
            "{case}"
        );
        drop(mailbox);
        assert!(
            Mailbox::open(directory.path(), Duration::from_secs(1)).is_err(),
            "{case}"
        );
    }
}

#[tokio::test]
async fn timeout_after_native_consumption_and_cancellation_block_restart() {
    for cancel in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        // Cancellation is controlled by native consumption, not by elapsed filesystem time.
        // Its transport deadline is irrelevant: the future is dropped as soon as the barrier fires.
        let deadline = if cancel {
            Duration::from_secs(120)
        } else {
            Duration::from_millis(100)
        };
        let mut mailbox = Mailbox::open(directory.path(), deadline).unwrap();
        let (consumed_tx, consumed_rx) = tokio::sync::oneshot::channel();
        let peer_dir = directory.path().to_path_buf();
        let peer = tokio::spawn(async move {
            request(&peer_dir).await;
            fs::remove_file(peer_dir.join("request.json"))
                .await
                .unwrap();
            consumed_tx.send(()).unwrap();
        });
        if cancel {
            let mut exchange = Box::pin(mailbox.call("save_program", json!({})));
            tokio::select! {
                consumed = consumed_rx => consumed.unwrap(),
                result = &mut exchange => panic!("exchange finished before controlled cancellation: {result:?}"),
            }
            drop(exchange);
        } else {
            assert!(
                mailbox
                    .call("save_program", json!({}))
                    .await
                    .unwrap_err()
                    .contains("timed out")
            );
            consumed_rx.await.unwrap();
        }
        peer.await.unwrap();
        assert!(!directory.path().join("request.json").exists());
        assert!(!directory.path().join("response.json").exists());
        assert!(directory.path().join("client.pending").exists());
        assert!(mailbox.call("status", json!({})).await.is_err());
        drop(mailbox);
        assert!(Mailbox::open(directory.path(), Duration::from_secs(1)).is_err());
    }
}

#[tokio::test]
async fn partial_unpublished_response_is_ignored_until_atomic_publication() {
    let directory = tempfile::tempdir().unwrap();
    let mut mailbox = Mailbox::open(directory.path(), Duration::from_secs(2)).unwrap();
    let peer_dir = directory.path().to_path_buf();
    let peer = tokio::spawn(async move {
        let req = request(&peer_dir).await;
        fs::remove_file(peer_dir.join("request.json"))
            .await
            .unwrap();
        let temp = peer_dir.join("response.synthetic.tmp");
        fs::write(&temp, b"{").await.unwrap();
        sleep(Duration::from_millis(40)).await;
        fs::write(
            &temp,
            serde_json::to_vec(
                &json!({"protocol":1,"id":req["id"],"ok":true,"result":{"complete":true}}),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        fs::rename(temp, peer_dir.join("response.json"))
            .await
            .unwrap();
    });
    assert_eq!(
        mailbox.call("status", json!({})).await.unwrap()["complete"],
        true
    );
    peer.await.unwrap();
}

#[tokio::test]
async fn oversized_requests_and_invalid_params_never_publish_or_poison() {
    let directory = tempfile::tempdir().unwrap();
    let mut mailbox = Mailbox::open(directory.path(), Duration::from_secs(2)).unwrap();
    assert!(
        mailbox
            .call("status", json!({"large":"x".repeat(MAX_REQUEST_BYTES)}))
            .await
            .unwrap_err()
            .contains("1 MiB")
    );
    assert!(!directory.path().join("client.pending").exists());
    let mut backend = Backend::new(mailbox);
    for (id, addr, count) in [
        ("", "ram:0", 1),
        ("synthetic", "400000", 1),
        ("synthetic", "ram:0", 4097),
        ("synthetic", "ram:ffffffffffffffff", 2),
    ] {
        let params = ReadBytesParams {
            expected_program_id: id.into(),
            address: addr.into(),
            count,
        };
        assert!(params.validate().is_err());
        assert!(
            backend
                .execute("read_bytes", &params)
                .await
                .unwrap_err()
                .contains("invalid_argument")
        );
        assert!(!directory.path().join("request.json").exists());
        assert!(!directory.path().join("client.pending").exists());
    }
    let peer_dir = directory.path().to_path_buf();
    let peer = tokio::spawn(async move {
        let req = request(&peer_dir).await;
        publish(&peer_dir, &serde_json::to_vec(&json!({"protocol":1,"id":req["id"],"ok":true,"result":{"address":"ram:0000","bytes":[255]}})).unwrap(), true).await;
    });
    let params = ReadBytesParams {
        expected_program_id: "synthetic".into(),
        address: "ram:0".into(),
        count: 1,
    };
    assert_eq!(
        backend.execute("read_bytes", &params).await.unwrap()["bytes"],
        json!([255])
    );
    peer.await.unwrap();
}

#[tokio::test]
async fn malformed_operation_results_preserve_durable_guard() {
    for result in [
        json!({"address":"ram:1","bytes":[1]}),
        json!({"address":"ram:0","bytes":[]}),
        json!({"address":"ram:0","bytes":[256]}),
        json!({"address":"ram:0","bytes":[-1]}),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut backend =
            Backend::new(Mailbox::open(directory.path(), Duration::from_secs(2)).unwrap());
        let peer_dir = directory.path().to_path_buf();
        let peer = tokio::spawn(async move {
            let req = request(&peer_dir).await;
            publish(
                &peer_dir,
                &serde_json::to_vec(
                    &json!({"protocol":1,"id":req["id"],"ok":true,"result":result}),
                )
                .unwrap(),
                true,
            )
            .await;
        });
        let params = ReadBytesParams {
            expected_program_id: "synthetic".into(),
            address: "ram:0".into(),
            count: 1,
        };
        assert!(
            backend
                .execute("read_bytes", &params)
                .await
                .unwrap_err()
                .contains("invalid read_bytes result")
        );
        peer.await.unwrap();
        assert!(directory.path().join("client.pending").exists());
        assert!(directory.path().join("response.json").exists());
    }
}
