//! Local argument validation; no transport or native applications.
use ghidra_mcp::domain::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn invalid<T: DeserializeOwned + Validate>(value: Value) {
    if let Ok(value) = serde_json::from_value::<T>(value) {
        assert!(value.validate().is_err());
    }
}

#[test]
fn identity_address_and_integer_bounds_are_not_interchangeable() {
    for bad in ["", " ", "bad\nidentity"] {
        assert!(identity(bad).is_err());
    }
    for bad in [
        "400000",
        "0x400000",
        "ram:",
        ":4000",
        "ram:0x4000",
        "ram:10000000000000000",
        "ram:-1",
        "ram: 1",
        "ram::1",
    ] {
        assert!(address(bad).is_err(), "{bad}");
    }
    assert_eq!(address("ram:FFFFFFFFFFFFFFFF").unwrap(), ("ram", u64::MAX));
    for value in ["0", "0x0", "0123456789abcdef"] {
        assert!(hex(value, "image_base").is_ok());
    }
    invalid::<ReadBytesParams>(json!({"expected_program_id":"p","address":"ram:0","count":0}));
    invalid::<ReadBytesParams>(
        json!({"expected_program_id":"p","address":"ram:0","count":1,"write":true}),
    );
    invalid::<EmptyParams>(json!({"script":"ignored?"}));
    invalid::<MapFileOffsetParams>(json!({"expected_program_id":"p","file_offset":u64::MAX}));
    invalid::<MemoryBlockParams>(
        json!({"expected_program_id":"p","name":"RAM","address":"ram:ffffffffffffffff","size":2,"read":true,"write":false,"execute":false}),
    );
    invalid::<DefineDataParams>(
        json!({"expected_program_id":"p","address":"ram:fffffffffffffffe","type_name":"u32","count":1}),
    );
    invalid::<DefineDataParams>(
        json!({"expected_program_id":"p","address":"ram:0","type_name":"pointer","count":1}),
    );
    invalid::<ReferencesParams>(
        json!({"expected_program_id":"p","address":"ram:0","direction":"both"}),
    );
}

#[test]
fn exact_search_patterns_and_comment_limits() {
    for pattern in [
        "",
        "A",
        "A A",
        "AA ??",
        "0xAA",
        "GG",
        "AA\u{a0}BB",
        &"AA".repeat(257),
    ] {
        invalid::<SearchBytesParams>(json!({"expected_program_id":"p","pattern":pattern}));
    }
    for pattern in ["AABB", "AA BB", "AA\tBB\n00", &"FF".repeat(256)] {
        serde_json::from_value::<SearchBytesParams>(
            json!({"expected_program_id":"p","pattern":pattern}),
        )
        .unwrap()
        .validate()
        .unwrap();
    }
    invalid::<CommentParams>(
        json!({"expected_program_id":"p","address":"ram:0","comment":"\u{0}"}),
    );
    invalid::<CommentParams>(
        json!({"expected_program_id":"p","address":"ram:0","comment":"x".repeat(8193)}),
    );
    serde_json::from_value::<CommentParams>(
        json!({"expected_program_id":"p","address":"ram:0","comment":""}),
    )
    .unwrap()
    .validate()
    .unwrap();
    invalid::<AnalysisOptionsParams>(
        json!({"expected_program_id":"p","options":{"Analyzer":"true"}}),
    );
    let options: serde_json::Map<String, Value> = (0..201)
        .map(|i| (format!("Synthetic option {i}"), json!(false)))
        .collect();
    invalid::<AnalysisOptionsParams>(json!({"expected_program_id":"p","options":options}));
    invalid::<ListSymbolsParams>(json!({"expected_program_id":"p","offset":1000001}));
    invalid::<ListStringsParams>(json!({"expected_program_id":"p","offset":1000001}));
    invalid::<ListFunctionsParams>(json!({"expected_program_id":"p","offset":2147483648_u32}));
}

#[test]
fn paths_names_and_export_collisions_fail_before_native_transport() {
    for name in [
        "../map", "a/b", "a\\b", "NUL", "CON.txt", "LPT9", "a.", "..", "bad:",
    ] {
        assert!(simple_name(name).is_err(), "{name}");
    }
    for path in [
        "Original",
        "/../Original",
        "/folder//Original",
        "/folder/./Original",
        "/folder\\Original",
    ] {
        invalid::<SelectProgramParams>(
            json!({"expected_project_id":"project","program_path":path}),
        );
    }
    invalid::<ProjectLocationParams>(json!({"path":"relative","name":"project"}));
    let directory = tempfile::tempdir().unwrap();
    let existing = directory.path().join("existing.gzf");
    std::fs::write(&existing, b"synthetic").unwrap();
    invalid::<ExportProgramParams>(json!({"expected_program_id":"p","path":existing}));
    invalid::<ImportProgramParams>(
        json!({"expected_project_id":"p","path":directory.path(),"name":"Program","language_id":"x86:LE:32:default","compiler_spec_id":"default","image_base":"0"}),
    );
    serde_json::from_value::<ExportProgramParams>(
        json!({"expected_program_id":"p","path":directory.path().join("new.gzf")}),
    )
    .unwrap()
    .validate()
    .unwrap();
    assert_eq!(std::fs::read(existing).unwrap(), b"synthetic");
}
