//! Result invariants for bounded native flow tools. Invalid results preserve mailbox evidence.
use super::{array, boolean, same_address, string};
use crate::domain;
use serde_json::Value;
use std::collections::HashSet;

pub(super) fn supports(op: &str) -> bool {
    matches!(
        op,
        "get_high_pcode"
            | "trace_data_flow"
            | "batch_decompile"
            | "batch_references"
            | "search_decompiled_code"
            | "get_function_fingerprint"
            | "compare_functions"
            | "find_similar_functions"
            | "emulate_function"
    )
}
fn n(v: &Value, key: &str, max: u64) -> Result<u64, String> {
    v.get(key)
        .and_then(Value::as_u64)
        .filter(|x| *x <= max)
        .ok_or_else(|| format!("invalid {key}"))
}
fn addr(v: &Value, key: &str) -> Result<(), String> {
    domain::address(string(v, key, 512)?)?;
    Ok(())
}
fn same(actual: &Value, expected: &Value) -> Result<(), String> {
    if domain::address(actual.as_str().ok_or("missing actual address")?)?
        != domain::address(expected.as_str().ok_or("missing requested address")?)?
    {
        return Err("address mismatch".into());
    }
    Ok(())
}
fn advances(previous: &Value, current: &Value) -> Result<(), String> {
    let (old_space, old) = domain::address(previous.as_str().ok_or("missing previous cursor")?)?;
    let (new_space, new) = domain::address(current.as_str().ok_or("missing current cursor")?)?;
    // Native Ghidra owns inter-space ordering; within a space the unsigned offsets must advance.
    if old_space == new_space && new <= old {
        return Err("scan cursor did not advance".into());
    }
    Ok(())
}
fn nullable(v: &Value, key: &str, max: usize) -> Result<(), String> {
    match v.get(key) {
        Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s.chars().count() <= max => Ok(()),
        _ => Err(format!("invalid {key}")),
    }
}
fn hash(v: &Value, key: &str) -> Result<(), String> {
    let s = string(v, key, 64)?;
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid {key} hash"));
    }
    Ok(())
}
fn score(v: &Value) -> Result<(), String> {
    if v.get("score")
        .and_then(Value::as_f64)
        .is_none_or(|x| !x.is_finite() || !(0.0..=1.0).contains(&x))
    {
        return Err("invalid similarity score".into());
    }
    Ok(())
}
fn negative(v: &Value, key: &str) -> Result<(), String> {
    if boolean(v, key)? {
        return Err(format!("unexpected {key} claim"));
    }
    Ok(())
}
fn sequence(v: &Value) -> Result<(), String> {
    addr(v, "address")?;
    n(v, "time", u32::MAX as u64)?;
    string(v, "opcode", 128)?;
    Ok(())
}
fn node(v: &Value) -> Result<(), String> {
    let id = string(v, "id", 16)?;
    if !id
        .strip_prefix('v')
        .is_some_and(|x| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err("invalid SSA node id".into());
    }
    string(v, "space", 256)?;
    domain::hex(string(v, "offset", 16)?, "varnode offset")?;
    if n(v, "size", 65536)? == 0 {
        return Err("zero-sized SSA node".into());
    }
    for key in ["input", "constant", "register"] {
        boolean(v, key)?;
    }
    nullable(v, "high_name", 256)?;
    nullable(v, "high_type", 512)?;
    match v.get("definition") {
        Some(Value::Null) => {}
        Some(d) => sequence(d)?,
        None => return Err("missing node definition".into()),
    }
    Ok(())
}
fn operation(v: &Value) -> Result<(), String> {
    sequence(v)?;
    let inputs = array(v, "inputs")?;
    if inputs.len() > 32 {
        return Err("SSA input bound exceeded".into());
    }
    for input in inputs {
        node(input)?;
    }
    match v.get("output") {
        Some(Value::Null) => {}
        Some(output) => node(output)?,
        None => return Err("missing SSA output".into()),
    }
    Ok(())
}
fn fingerprint(v: &Value, max: u64) -> Result<(), String> {
    addr(v, "function_address")?;
    string(v, "name", 256)?;
    if string(v, "algorithm", 128)? != "mnemonic-operand-kinds-registers-v1" {
        return Err("unexpected fingerprint algorithm".into());
    }
    hash(v, "sha256")?;
    if n(v, "instruction_count", max)? == 0 {
        return Err("empty fingerprint".into());
    }
    boolean(v, "truncated")?;
    negative(v, "semantic_equivalence")
}
fn decompiled(v: &Value, with_code: bool) -> Result<(), String> {
    addr(v, "address")?;
    let ok = boolean(v, "ok")?;
    boolean(v, "truncated")?;
    nullable(v, "error", 2048)?;
    if ok {
        addr(v, "function_address")?;
        string(v, "name", 256)?;
        if !v["error"].is_null() {
            return Err("successful decompilation has error".into());
        }
        if with_code {
            nullable(v, "c", 65536)?;
            if !v["c"].is_string() {
                return Err("missing decompiled C".into());
            }
        }
    } else if !v["function_address"].is_null()
        || !v["name"].is_null()
        || !v["error"].is_string()
        || boolean(v, "truncated")?
        || (with_code && !v["c"].is_null())
    {
        return Err("invalid failed decompilation result".into());
    }
    Ok(())
}
fn cursor(v: &Value, scanned: u64) -> Result<(), String> {
    boolean(v, "has_more")?;
    match v.get("next_cursor") {
        Some(Value::Null) if scanned == 0 => Ok(()),
        Some(Value::String(s)) if scanned > 0 => {
            domain::address(s)?;
            Ok(())
        }
        _ => Err("invalid scan cursor".into()),
    }
}

pub(super) fn validate(op: &str, params: &Value, v: &Value) -> Result<(), String> {
    match op {
        "get_high_pcode" => {
            same_address(v, params)?;
            addr(v, "function_address")?;
            hash(v, "snapshot_id")?;
            if string(v, "pcode_kind", 32)? != "decompiler_ssa" {
                return Err("unexpected SSA kind".into());
            }
            let total = n(v, "total", 20000)?;
            let offset = n(v, "offset", 20000)?;
            let ops = array(v, "operations")?;
            if v.get("offset") != params.get("offset")
                || ops.len() as u64
                    != total
                        .saturating_sub(offset)
                        .min(params["limit"].as_u64().unwrap())
                || boolean(v, "has_more")? != (offset + (ops.len() as u64) < total)
            {
                return Err("invalid SSA pagination".into());
            }
            for (i, op) in ops.iter().enumerate() {
                operation(op)?;
                if op["index"].as_u64() != Some(offset + i as u64) {
                    return Err("invalid SSA operation index".into());
                }
            }
        }
        "trace_data_flow" => {
            same_address(v, params)?;
            addr(v, "function_address")?;
            hash(v, "snapshot_id")?;
            if !v["snapshot_id"]
                .as_str()
                .unwrap()
                .eq_ignore_ascii_case(params["expected_snapshot_id"].as_str().unwrap())
                || v.get("direction") != params.get("direction")
            {
                return Err("trace snapshot/direction mismatch".into());
            }
            negative(v, "interprocedural")?;
            negative(v, "memory_alias_analysis")?;
            boolean(v, "truncated")?;
            let nodes = array(v, "nodes")?;
            let edges = array(v, "edges")?;
            let terminals = array(v, "terminals")?;
            if nodes.is_empty()
                || nodes.len() as u64 > params["max_nodes"].as_u64().unwrap()
                || edges.len() > 512
                || terminals.len() > 1024
            {
                return Err("trace exceeds bounds".into());
            }
            let mut ids = HashSet::new();
            for item in nodes {
                node(item)?;
                n(item, "depth", params["max_depth"].as_u64().unwrap())?;
                if !ids.insert(item["id"].as_str().unwrap()) {
                    return Err("duplicate trace node".into());
                }
            }
            if !ids.contains(string(v, "root_node", 16)?) {
                return Err("trace root missing".into());
            }
            for edge in edges {
                if !ids.contains(string(edge, "from", 16)?)
                    || !ids.contains(string(edge, "to", 16)?)
                {
                    return Err("trace edge references missing node".into());
                }
                sequence(&edge["operation"])?;
            }
            for terminal in terminals {
                if !ids.contains(string(terminal, "node_id", 16)?) {
                    return Err("terminal references missing node".into());
                }
                if !matches!(
                    string(terminal, "reason", 64)?,
                    "constant"
                        | "no_ssa_edge"
                        | "depth_limit"
                        | "call_boundary"
                        | "memory_boundary"
                        | "indirect_effect_boundary"
                        | "no_output"
                ) {
                    return Err("unknown trace boundary".into());
                }
                if !terminal["operation"].is_null() {
                    sequence(&terminal["operation"])?;
                }
            }
        }
        "batch_decompile" | "batch_references" => {
            let rows = array(v, "results")?;
            let requested = params["addresses"]
                .as_array()
                .ok_or("missing requested addresses")?;
            if rows.len() != requested.len() || n(v, "count", 32)? != rows.len() as u64 {
                return Err("batch count mismatch".into());
            }
            if op == "batch_references" && v.get("direction") != params.get("direction") {
                return Err("batch reference direction mismatch".into());
            }
            for (row, at) in rows.iter().zip(requested) {
                same(&row["address"], at)?;
                if op == "batch_decompile" {
                    decompiled(row, true)?;
                } else {
                    boolean(row, "truncated")?;
                    let refs = array(row, "refs")?;
                    if refs.len() as u64 > params["limit_per_address"].as_u64().unwrap() {
                        return Err("batch reference limit exceeded".into());
                    }
                    for r in refs {
                        addr(r, "from")?;
                        addr(r, "to")?;
                        same(
                            &r[if params["direction"] == "from" {
                                "from"
                            } else {
                                "to"
                            }],
                            at,
                        )?;
                        string(r, "type", 128)?;
                        if r["operand_index"]
                            .as_i64()
                            .is_none_or(|i| !(-1..=255).contains(&i))
                        {
                            return Err("invalid reference operand".into());
                        }
                    }
                }
            }
        }
        "search_decompiled_code" => {
            if v.get("text") != params.get("text")
                || !boolean(v, "case_sensitive")?
                || !boolean(v, "literal")?
            {
                return Err("search semantics mismatch".into());
            }
            let rows = array(v, "results")?;
            let scanned = n(v, "scanned", params["function_limit"].as_u64().unwrap())?;
            if rows.len() as u64 != scanned {
                return Err("search scan count mismatch".into());
            }
            cursor(v, scanned)?;
            let mut previous = params.get("start_after").filter(|v| !v.is_null());
            let mut seen = HashSet::new();
            for row in rows {
                decompiled(row, false)?;
                if let Some(prior) = previous {
                    advances(prior, &row["address"])?;
                }
                let parsed = domain::address(row["address"].as_str().unwrap())?;
                if !seen.insert(parsed) {
                    return Err("duplicate search function".into());
                }
                previous = Some(&row["address"]);
                boolean(row, "matches_truncated")?;
                let matches = array(row, "matches")?;
                if matches.len() > 20 || (!row["ok"].as_bool().unwrap() && !matches.is_empty()) {
                    return Err("invalid search matches".into());
                }
                for m in matches {
                    n(m, "offset", 65536)?;
                    if n(m, "line", 65537)? == 0 {
                        return Err("invalid source line".into());
                    }
                    nullable(m, "snippet", 512)?;
                    if !m["snippet"].is_string() {
                        return Err("missing search snippet".into());
                    }
                }
            }
            if let Some(last) = rows.last() {
                same(&v["next_cursor"], &last["address"])?;
            }
        }
        "get_function_fingerprint" => {
            same_address(v, params)?;
            fingerprint(v, params["max_instructions"].as_u64().unwrap())?;
        }
        "compare_functions" => {
            same_address(v, params)?;
            same(&v["other_address"], &params["other_address"])?;
            let max = params["max_instructions"].as_u64().unwrap();
            fingerprint(&v["left"], max)?;
            fingerprint(&v["right"], max)?;
            score(v)?;
            negative(v, "semantic_equivalence")?;
            if string(v, "score_kind", 64)? != "normalized_token_multiset_jaccard" {
                return Err("unknown score kind".into());
            }
            let equal = boolean(v, "equal_normalized_sequence")?;
            let expected = !v["left"]["truncated"].as_bool().unwrap()
                && !v["right"]["truncated"].as_bool().unwrap()
                && v["left"]["sha256"] == v["right"]["sha256"];
            if equal != expected {
                return Err("inconsistent normalized equality".into());
            }
        }
        "find_similar_functions" => {
            same_address(v, params)?;
            fingerprint(&v["query"], params["max_instructions"].as_u64().unwrap())?;
            negative(v, "semantic_equivalence")?;
            if string(v, "score_kind", 64)? != "normalized_token_multiset_jaccard"
                || string(v, "ranking_scope", 32)? != "scanned_window"
            {
                return Err("unexpected ranking semantics".into());
            }
            let scanned = n(v, "scanned", params["function_limit"].as_u64().unwrap())?;
            cursor(v, scanned)?;
            if scanned > 0 {
                if let Some(prior) = params.get("start_after").filter(|v| !v.is_null()) {
                    advances(prior, &v["next_cursor"])?;
                }
            }
            let rows = array(v, "matches")?;
            let failures = array(v, "failures")?;
            if rows.len() as u64 > params["result_limit"].as_u64().unwrap()
                || rows.len() + failures.len() > scanned as usize
            {
                return Err("similarity scan bounds exceeded".into());
            }
            let mut previous = 1.0;
            for row in rows {
                fingerprint(row, params["max_instructions"].as_u64().unwrap())?;
                score(row)?;
                let current = row["score"].as_f64().unwrap();
                if current > previous {
                    return Err("similarity results are unsorted".into());
                }
                previous = current;
            }
            for failure in failures {
                addr(failure, "function_address")?;
                nullable(failure, "error", 1024)?;
                if !failure["error"].is_string() {
                    return Err("missing scan error".into());
                }
            }
        }
        "emulate_function" => {
            same_address(v, params)?;
            same(&v["stop_address"], &params["stop_address"])?;
            addr(v, "execution_address")?;
            n(v, "steps", params["max_steps"].as_u64().unwrap())?;
            nullable(v, "error", 2048)?;
            if !boolean(v, "isolated")? {
                return Err("emulator is not isolated".into());
            }
            negative(v, "program_writes_committed")?;
            string(v, "assumptions", 1024)?;
            let outcome = string(v, "outcome", 32)?;
            if !matches!(
                outcome,
                "stop_address" | "step_limit" | "time_limit" | "emulator_error"
            ) {
                return Err("invalid emulator outcome".into());
            }
            if boolean(v, "reached_stop")? != (outcome == "stop_address") {
                return Err("inconsistent emulator stop claim".into());
            }
            if outcome == "stop_address" {
                same(&v["execution_address"], &params["stop_address"])?;
            }
            if outcome != "emulator_error" && !v["error"].is_null() {
                return Err("successful emulator outcome has error".into());
            }
            let registers = array(v, "registers")?;
            let requested = params["output_registers"].as_array().unwrap();
            if registers.len() != requested.len() {
                return Err("emulator register count mismatch".into());
            }
            for (row, name) in registers.iter().zip(requested) {
                let returned = string(row, "name", 64)?;
                if !returned.eq_ignore_ascii_case(name.as_str().unwrap()) {
                    return Err("emulator register mismatch".into());
                }
                let bits = n(row, "bit_length", 64)?;
                nullable(row, "error", 1024)?;
                if bits == 0 {
                    return Err("invalid emulator register width".into());
                }
                if row["value"].is_null() {
                    if outcome != "emulator_error" || !row["error"].is_string() {
                        return Err("unavailable emulator register lacks error".into());
                    }
                    continue;
                }
                if !row["error"].is_null() {
                    return Err("available emulator register has error".into());
                }
                let value = domain::hex(string(row, "value", 16)?, "register value")?;
                if bits < 64 && value >= (1u64 << bits) {
                    return Err("emulator register value exceeds width".into());
                }
            }
            let memory = array(v, "memory")?;
            let requested = params["output_memory"].as_array().unwrap();
            if memory.len() != requested.len() {
                return Err("emulator memory count mismatch".into());
            }
            for (row, wanted) in memory.iter().zip(requested) {
                same(&row["address"], &wanted["address"])?;
                nullable(row, "error", 1024)?;
                if row["bytes"].is_null() {
                    if outcome != "emulator_error" || !row["error"].is_string() {
                        return Err("unavailable emulator memory lacks error".into());
                    }
                    continue;
                }
                if !row["error"].is_null() {
                    return Err("available emulator memory has error".into());
                }
                let bytes = array(row, "bytes")?;
                if bytes.len() as u64 != wanted["count"].as_u64().unwrap()
                    || bytes.iter().any(|b| b.as_u64().is_none_or(|x| x > 255))
                {
                    return Err("invalid emulator output memory".into());
                }
            }
        }
        _ => return Err("unsupported flow result".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fp(at: &str) -> Value {
        json!({"function_address":at,"name":"synthetic","algorithm":"mnemonic-operand-kinds-registers-v1",
        "sha256":"a".repeat(64),"instruction_count":2,"truncated":false,"semantic_equivalence":false})
    }

    #[test]
    fn comparison_rejects_equivalence_claim_and_truncated_sequence_equality() {
        let params =
            json!({"address":"ram:400000","other_address":"ram:400010","max_instructions":10});
        let good = json!({"address":"ram:00400000","other_address":"ram:00400010","left":fp("ram:400000"),"right":fp("ram:400010"),
            "score":1.0,"score_kind":"normalized_token_multiset_jaccard","equal_normalized_sequence":true,"semantic_equivalence":false});
        validate("compare_functions", &params, &good).unwrap();
        let mut bad = good.clone();
        bad["left"]["truncated"] = json!(true);
        assert!(validate("compare_functions", &params, &bad).is_err());
        let mut bad = good.clone();
        bad["semantic_equivalence"] = json!(true);
        assert!(validate("compare_functions", &params, &bad).is_err());
        let mut bad = good;
        bad["score"] = json!(1.1);
        assert!(validate("compare_functions", &params, &bad).is_err());
    }

    #[test]
    fn trace_rejects_changed_snapshot_and_dangling_edges() {
        let params = json!({"address":"ram:400000","expected_snapshot_id":"a".repeat(64),"direction":"backward","max_nodes":1,"max_depth":2});
        let node = json!({"id":"v0","space":"register","offset":"0","size":4,"input":true,"constant":false,"register":true,"high_name":null,"high_type":null,"definition":null,"depth":0});
        let good = json!({"address":"ram:400000","function_address":"ram:400000","snapshot_id":"a".repeat(64),"direction":"backward",
            "interprocedural":false,"memory_alias_analysis":false,"truncated":false,"root_node":"v0","nodes":[node],"edges":[],"terminals":[]});
        validate("trace_data_flow", &params, &good).unwrap();
        let mut bad = good.clone();
        bad["snapshot_id"] = json!("b".repeat(64));
        assert!(validate("trace_data_flow", &params, &bad).is_err());
        let mut bad = good;
        bad["edges"] = json!([{"from":"v0","to":"v1","operation":{"address":"ram:400000","time":0,"opcode":"COPY"}}]);
        assert!(validate("trace_data_flow", &params, &bad).is_err());
    }

    #[test]
    fn emulator_unavailable_output_is_an_error_not_zero_filled_success() {
        let params = json!({"address":"ram:400000","stop_address":"ram:400005","max_steps":4,"output_registers":["EAX"],"output_memory":[]});
        let good = json!({"address":"ram:400000","stop_address":"ram:400005","execution_address":"ram:400000","steps":1,
            "outcome":"emulator_error","reached_stop":false,"error":"Uninitialized input","isolated":true,"program_writes_committed":false,
            "assumptions":"Explicit fixture inputs only","registers":[{"name":"EAX","value":null,"bit_length":32,"error":"Unavailable register"}],"memory":[]});
        validate("emulate_function", &params, &good).unwrap();
        let mut bad = good;
        bad["outcome"] = json!("step_limit");
        bad["error"] = Value::Null;
        assert!(validate("emulate_function", &params, &bad).is_err());
    }
}
