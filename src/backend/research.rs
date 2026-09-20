//! Fail closed on malformed, oversized or request-inconsistent native research replies.
use super::{array, boolean, same_address, string};
use crate::domain;
use serde_json::Value;
use std::collections::HashSet;

pub(super) fn supports(operation: &str) -> bool {
    matches!(
        operation,
        "get_function_details"
            | "get_control_flow"
            | "get_call_graph"
            | "find_call_paths"
            | "search_constants"
            | "search_instructions"
            | "search_pcode"
            | "get_references_range"
    )
}
fn count(v: &Value, key: &str, max: u64) -> Result<u64, String> {
    v[key]
        .as_u64()
        .filter(|n| *n <= max)
        .ok_or_else(|| format!("invalid {key}"))
}
fn signed(v: &Value, key: &str) -> Result<i64, String> {
    v[key]
        .as_i64()
        .ok_or_else(|| format!("invalid signed {key}"))
}
fn setting(p: &Value, key: &str, default: u64) -> usize {
    p[key].as_u64().unwrap_or(default) as usize
}
fn addr<'a>(v: &'a Value, key: &str) -> Result<(&'a str, u64), String> {
    domain::address(string(v, key, 512)?)
}
fn short(v: &Value, key: &str, max: usize, nullable: bool) -> Result<(), String> {
    if nullable && v.get(key).is_some_and(Value::is_null) {
        return Ok(());
    }
    let s = v[key].as_str().ok_or_else(|| format!("invalid {key}"))?;
    if s.chars().count() > max {
        return Err(format!("oversized {key}"));
    }
    Ok(())
}
fn status(v: &Value, allowed: &[&str]) -> Result<bool, String> {
    if count(v, "time_limit_ms", 5000)? != 5000 {
        return Err("unexpected research time budget".into());
    }
    let truncated = boolean(v, "truncated")?;
    if truncated {
        let reason = string(v, "truncation_reason", 128)?;
        if !allowed.contains(&reason) || !v["continuation"].is_object() {
            return Err("invalid truncation/continuation".into());
        }
    } else if !v.get("truncation_reason").is_some_and(Value::is_null)
        || !v.get("continuation").is_some_and(Value::is_null)
    {
        return Err("complete result carries continuation".into());
    }
    Ok(truncated)
}
fn restart(v: &Value) -> Result<(), String> {
    if v["truncated"] == true
        && string(&v["continuation"], "strategy", 128)?
            != "restart_with_larger_limits_or_narrower_scope"
    {
        return Err("invalid graph/metadata continuation".into());
    }
    Ok(())
}
fn function(v: &Value) -> Result<(), String> {
    addr(v, "address")?;
    string(v, "name", 1024)?;
    boolean(v, "external")?;
    boolean(v, "thunk")?;
    Ok(())
}
fn ranges(v: &Value, max: usize) -> Result<u64, String> {
    let rows = v.as_array().ok_or("missing range array")?;
    if rows.len() > max {
        return Err("too many ranges".into());
    }
    let mut sum = 0u64;
    let mut previous = None;
    for r in rows {
        let (s, a) = addr(r, "start")?;
        let (e, b) = addr(r, "end")?;
        if s != e
            || a > b
            || b.checked_sub(a).and_then(|n| n.checked_add(1)) != Some(count(r, "size", u64::MAX)?)
        {
            return Err("invalid range span".into());
        }
        if let Some((ps, pb)) = previous {
            if ps == s && pb >= a {
                return Err("unordered/overlapping range".into());
            }
        }
        previous = Some((s, b));
        sum = sum.checked_add(b - a + 1).ok_or("range size overflow")?;
    }
    Ok(sum)
}
fn variable(v: &Value) -> Result<(), String> {
    short(v, "name", 1024, false)?;
    string(v, "data_type", 4096)?;
    signed(v, "length")?;
    signed(v, "first_use_offset")?;
    let s = &v["storage"];
    short(s, "display", 4096, false)?;
    count(s, "size", u32::MAX.into())?;
    for flag in ["unassigned", "bad", "void", "auto", "forced_indirect"] {
        boolean(s, flag)?;
    }
    let pieces = array(s, "pieces")?;
    if pieces.len() > 32 {
        return Err("too many storage pieces".into());
    }
    for piece in pieces {
        string(piece, "space", 256)?;
        domain::hex(string(piece, "offset", 16)?, "storage offset")?;
        if count(piece, "size", u32::MAX.into())? == 0 {
            return Err("empty storage piece".into());
        }
        short(piece, "register", 256, true)?;
        if piece.get("stack_offset").is_some() {
            signed(piece, "stack_offset")?;
        }
    }
    Ok(())
}
fn within(a: (&str, u64), p: &Value) -> Result<(), String> {
    if p["start"].is_string() {
        let s = addr(p, "start")?;
        let e = addr(p, "end")?;
        if a.0 != s.0 || a.1 < s.1 || a.1 > e.1 {
            return Err("result outside requested range".into());
        }
    }
    if p["cursor"].is_string() {
        let c = addr(p, "cursor")?;
        if a.0 == c.0 && a.1 < c.1 {
            return Err("result precedes cursor".into());
        }
    }
    Ok(())
}
fn instruction(v: &Value, p: &Value) -> Result<(), String> {
    within(addr(v, "address")?, p)?;
    string(v, "mnemonic", 256)?;
    if count(v, "length", 65536)? == 0 {
        return Err("empty instruction".into());
    }
    let operands = array(v, "operands")?;
    if operands.len() > 32 {
        return Err("too many operands".into());
    }
    if operands
        .iter()
        .any(|o| o.as_str().is_none_or(|s| s.chars().count() > 1024))
    {
        return Err("invalid operand".into());
    }
    Ok(())
}
fn search(operation: &str, p: &Value, v: &Value) -> Result<(), String> {
    let truncated = status(v, &["scan_limit", "result_limit", "time_limit"])?;
    let scanned = count(v, "scanned", setting(p, "scan_limit", 20000) as u64)?;
    if string(v, "scan_unit", 64)? != "instructions" {
        return Err("invalid search scan unit".into());
    }
    let matches = array(v, "matches")?;
    if matches.len() > setting(p, "limit", 100) || matches.len() as u64 > scanned {
        return Err("search result exceeds request".into());
    }
    let mut previous = None;
    let mut seen = HashSet::new();
    for row in matches {
        instruction(row, p)?;
        let current = addr(row, "address")?;
        if !seen.insert(current) {
            return Err("duplicate search address".into());
        }
        if let Some(last) = previous {
            let (ls, lo): (&str, u64) = last;
            if ls == current.0 && lo >= current.1 {
                return Err("search results out of order".into());
            }
        }
        previous = Some(current);
        match operation {
            "search_constants" => {
                let found = array(row, "scalars")?;
                if found.is_empty() || found.len() > 128 {
                    return Err("invalid scalar matches".into());
                }
                for scalar in found {
                    if count(scalar, "operand_index", 31)? as usize >= array(row, "operands")?.len()
                    {
                        return Err("scalar operand index exceeds instruction".into());
                    }
                    let bits = count(scalar, "bits", 64)?;
                    let raw = domain::hex(string(scalar, "unsigned_hex", 16)?, "scalar")?;
                    if bits == 0
                        || (bits < 64 && raw >= (1u64 << bits))
                        || raw != domain::hex(string(p, "value", 18)?, "value")?
                        || p["scalar_bits"].as_u64().is_some_and(|n| n != bits)
                    {
                        return Err("scalar result does not match requested bit pattern".into());
                    }
                    let signed_text = string(scalar, "signed_decimal", 21)?;
                    let signed_value = signed_text
                        .parse::<i64>()
                        .map_err(|_| "invalid signed scalar")?;
                    let expected = if bits == 64 {
                        raw as i64
                    } else {
                        ((raw << (64 - bits)) as i64) >> (64 - bits)
                    };
                    if signed_value != expected {
                        return Err("inconsistent signed scalar representation".into());
                    }
                }
            }
            "search_instructions" => {
                if p["mnemonic"].as_str().is_some_and(|m| {
                    !row["mnemonic"]
                        .as_str()
                        .unwrap_or_default()
                        .eq_ignore_ascii_case(m)
                }) {
                    return Err("mnemonic filter mismatch".into());
                }
                if let Some(needle) = p["operand_contains"].as_str() {
                    if !array(row, "operands")?
                        .iter()
                        .any(|o| o.as_str().is_some_and(|s| s.contains(needle)))
                    {
                        return Err("operand filter mismatch".into());
                    }
                }
            }
            "search_pcode" => {
                let total = count(row, "operation_count", 1024)?;
                let indices = array(row, "operation_indices")?;
                if indices.is_empty() || indices.len() > 1024 {
                    return Err("invalid P-code matches".into());
                }
                let mut prior = None;
                for index in indices {
                    let n = index.as_u64().ok_or("invalid operation index")?;
                    if n >= total || prior.is_some_and(|p| p >= n) {
                        return Err("invalid P-code operation order".into());
                    }
                    prior = Some(n);
                }
            }
            _ => return Err("unsupported search".into()),
        }
    }
    if operation == "search_pcode"
        && (string(v, "pcode_kind", 32)? != "raw"
            || boolean(v, "includes_flow_overrides")?
            || v["opcode"] != p["opcode"])
    {
        return Err("wrong P-code semantics".into());
    }
    if truncated {
        let next = addr(&v["continuation"], "cursor")?;
        within(next, p)?;
        if previous.is_some_and(|last| last.0 == next.0 && last.1 >= next.1) {
            return Err("nonadvancing search continuation".into());
        }
    }
    Ok(())
}
fn graph(operation: &str, p: &Value, v: &Value) -> Result<(), String> {
    status(
        v,
        &[
            "scan_limit",
            "time_limit",
            "node_limit",
            "edge_limit",
            "path_limit",
        ],
    )?;
    restart(v)?;
    count(v, "scanned", 100000)?;
    let paths = operation == "find_call_paths";
    if paths {
        if addr(v, "source")? != addr(p, "source")? || addr(v, "target")? != addr(p, "target")? {
            return Err("path endpoints differ from request".into());
        }
        function(&v["target_function"])?;
    } else {
        same_address(v, p)?;
    }
    function(&v["root"])?;
    if string(v, "direction", 32)?
        != if paths {
            "callees"
        } else {
            p["direction"].as_str().unwrap_or("callees")
        }
        || string(v, "scope", 128)? != "existing_call_references_to_function_entries"
    {
        return Err("unexpected graph scope".into());
    }
    boolean(v, "depth_limit_reached")?;
    count(v, "unresolved_call_references", 100000)?;
    let max_depth = setting(p, "max_depth", if paths { 8 } else { 2 });
    let nodes = array(v, "nodes")?;
    let edges = array(v, "edges")?;
    if nodes.is_empty()
        || nodes.len() > setting(p, "max_nodes", 128)
        || edges.len() > setting(p, "max_edges", 512)
    {
        return Err("graph size exceeds bounds".into());
    }
    let mut known = HashSet::new();
    for node in nodes {
        function(node)?;
        count(node, "depth", max_depth as u64)?;
        if !known.insert(addr(node, "address")?) {
            return Err("duplicate graph node".into());
        }
    }
    if !known.contains(&addr(&v["root"], "address")?) {
        return Err("root missing from graph".into());
    }
    let mut links = HashSet::new();
    for edge in edges {
        let from = addr(edge, "source")?;
        let to = addr(edge, "target")?;
        addr(edge, "site")?;
        string(edge, "type", 128)?;
        if !known.contains(&from) || !known.contains(&to) {
            return Err("graph edge has absent endpoint".into());
        }
        links.insert((from, to));
    }
    let frontier = array(v, "frontier")?;
    if frontier.len() > nodes.len() {
        return Err("oversized frontier".into());
    }
    for item in frontier {
        if !known.contains(&domain::address(
            item.as_str().ok_or("invalid frontier address")?,
        )?) {
            return Err("unknown frontier node".into());
        }
    }
    if paths {
        if string(v, "path_kind", 64)? != "simple_function_paths" {
            return Err("unsupported path kind".into());
        }
        let results = array(v, "paths")?;
        if results.len() > setting(p, "max_paths", 10) {
            return Err("too many paths".into());
        }
        for path in results {
            let entries = path.as_array().ok_or("invalid path")?;
            if entries.is_empty() || entries.len() > max_depth + 1 {
                return Err("path depth exceeds request".into());
            }
            let mut seen = HashSet::new();
            let mut previous = None;
            for a in entries {
                let point = domain::address(a.as_str().ok_or("invalid path address")?)?;
                if !known.contains(&point) || !seen.insert(point) {
                    return Err("non-simple path".into());
                }
                if previous.is_some_and(|p| !links.contains(&(p, point))) {
                    return Err("path traverses absent edge".into());
                }
                previous = Some(point);
            }
            if domain::address(entries[0].as_str().unwrap_or_default())?
                != addr(&v["root"], "address")?
                || previous != Some(addr(&v["target_function"], "address")?)
            {
                return Err("wrong path endpoints".into());
            }
        }
    }
    Ok(())
}

pub(super) fn validate(operation: &str, p: &Value, v: &Value) -> Result<(), String> {
    match operation {
        "search_constants" | "search_instructions" | "search_pcode" => search(operation, p, v),
        "get_call_graph" | "find_call_paths" => graph(operation, p, v),
        "get_function_details" => {
            same_address(v, p)?;
            status(v, &["item_limit", "time_limit", "scan_limit"])?;
            restart(v)?;
            function(&v["function"])?;
            short(v, "calling_convention", 256, false)?;
            string(v, "signature", 4096)?;
            for flag in ["custom_variable_storage", "variadic", "no_return"] {
                boolean(v, flag)?;
            }
            let max = setting(p, "limit", 128);
            let size = ranges(&v["body_ranges"], max)?;
            let body = count(v, "body_size", u64::MAX)?;
            let nr = count(v, "body_range_count", i32::MAX as u64)?;
            if size > body || array(v, "body_ranges")?.len() as u64 > nr {
                return Err("invalid function range totals".into());
            }
            if v["truncated"] == false
                && (size != body || array(v, "body_ranges")?.len() as u64 != nr)
            {
                return Err("complete function details omitted body ranges".into());
            }
            variable(&v["return"])?;
            for (field, total) in [("parameters", "parameter_count"), ("locals", "local_count")] {
                let entries = array(v, field)?;
                let count = count(v, total, i32::MAX as u64)?;
                if entries.len() > max
                    || entries.len() as u64 > count
                    || (v["truncated"] == false && entries.len() as u64 != count)
                {
                    return Err("invalid variable totals".into());
                }
                for row in entries {
                    variable(row)?;
                    if field == "parameters" {
                        signed(row, "ordinal")?;
                    }
                }
            }
            for key in [
                "frame_size",
                "local_size",
                "parameter_size",
                "parameter_offset",
                "return_address_offset",
            ] {
                signed(&v["stack"], key)?;
            }
            boolean(&v["stack"], "grows_negative")?;
            Ok(())
        }
        "get_control_flow" => {
            same_address(v, p)?;
            status(
                v,
                &[
                    "scan_limit",
                    "time_limit",
                    "block_limit",
                    "edge_limit",
                    "block_range_limit",
                ],
            )?;
            restart(v)?;
            function(&v["function"])?;
            count(v, "scanned", 100000)?;
            if string(v, "model", 64)? != "ghidra_basic_block" {
                return Err("unexpected block model".into());
            }
            let blocks = array(v, "blocks")?;
            let edges = array(v, "edges")?;
            if blocks.len() > setting(p, "max_blocks", 128)
                || edges.len() > setting(p, "max_edges", 512)
            {
                return Err("control flow exceeds request".into());
            }
            let mut known = HashSet::new();
            for block in blocks {
                let a = addr(block, "address")?;
                if !known.insert(a) {
                    return Err("duplicate block".into());
                }
                ranges(&block["ranges"], 128)?;
                boolean(block, "wholly_in_function")?;
                flow(&block["flow"])?;
            }
            for edge in edges {
                if !known.contains(&addr(edge, "source")?) {
                    return Err("absent source block".into());
                }
                addr(edge, "target")?;
                addr(edge, "site")?;
                addr(edge, "reference_target")?;
                boolean(edge, "target_is_block")?;
                boolean(edge, "target_in_function")?;
                flow(edge)?;
            }
            Ok(())
        }
        "get_references_range" => {
            if addr(v, "start")? != addr(p, "start")?
                || addr(v, "end")? != addr(p, "end")?
                || string(v, "direction", 16)? != p["direction"].as_str().unwrap_or("from")
            {
                return Err("reference scope mismatch".into());
            }
            let truncated = status(v, &["scan_limit", "time_limit", "result_limit"])?;
            let scanned = count(v, "scanned", setting(p, "scan_limit", 20000) as u64)?;
            if string(v, "scan_unit", 64)? != "references" {
                return Err("unexpected reference scan unit".into());
            }
            count(v, "cursor_skipped", 100000)?;
            let refs = array(v, "references")?;
            if refs.len() > setting(p, "limit", 100) || refs.len() as u64 > scanned {
                return Err("reference count exceeds request".into());
            }
            let key = if v["direction"] == "from" {
                "from"
            } else {
                "to"
            };
            let mut last = None;
            for r in refs {
                addr(r, "from")?;
                addr(r, "to")?;
                let point = addr(r, key)?;
                within(point, p)?;
                if last.is_some_and(|a: (&str, u64)| a.0 == point.0 && a.1 > point.1) {
                    return Err("unordered reference result".into());
                }
                last = Some(point);
                string(r, "type", 128)?;
                string(r, "source", 128)?;
                boolean(r, "primary")?;
                let index = signed(r, "operand_index")?;
                if !(-1..=65535).contains(&index) {
                    return Err("invalid reference operand index".into());
                }
            }
            if truncated {
                let c = &v["continuation"];
                let point = addr(c, "cursor")?;
                within(point, p)?;
                count(c, "cursor_offset", 100000)?;
                if last.is_some_and(|a| a.0 == point.0 && a.1 > point.1) {
                    return Err("reference continuation moved backwards".into());
                }
            }
            Ok(())
        }
        _ => Err("unsupported research result".into()),
    }
}
fn flow(v: &Value) -> Result<(), String> {
    string(v, "type", 128)?;
    for flag in [
        "call",
        "jump",
        "conditional",
        "computed",
        "terminal",
        "fallthrough",
    ] {
        boolean(v, flag)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn search_requires_matching_filter_and_advancing_cursor() {
        let p = json!({"expected_program_id":"p","value":"2a","start":"ram:100","end":"ram:200","limit":1});
        let mut v = json!({"matches":[{"address":"ram:100","mnemonic":"MOV","length":5,"operands":["EAX","0x2a"],"scalars":[{"operand_index":1,"bits":32,"unsigned_hex":"2a","signed_decimal":"42"}]}],"scanned":1,"scan_unit":"instructions","time_limit_ms":5000,"truncated":true,"truncation_reason":"result_limit","continuation":{"cursor":"ram:105"}});
        assert!(validate("search_constants", &p, &v).is_ok());
        v["continuation"]["cursor"] = json!("ram:100");
        assert!(validate("search_constants", &p, &v).is_err());
        v["continuation"]["cursor"] = json!("ram:105");
        v["matches"][0]["scalars"][0]["unsigned_hex"] = json!("2b");
        assert!(validate("search_constants", &p, &v).is_err());
    }
    #[test]
    fn rejects_unknown_or_unbounded_replies() {
        assert!(!supports("execute_script"));
        assert!(supports("find_call_paths"));
        assert!(validate("search_pcode", &json!({}), &json!({})).is_err());
        assert!(
            validate(
                "get_control_flow",
                &json!({"address":"ram:10"}),
                &json!({"address":"ram:20"})
            )
            .is_err()
        );
    }
    #[test]
    fn graph_paths_require_real_edges_and_known_nodes() {
        let p =
            json!({"expected_program_id":"p","source":"ram:100","target":"ram:200","max_depth":2});
        let mut v = json!({
            "source":"ram:100","target":"ram:200","direction":"callees",
            "root":{"address":"ram:100","name":"caller","external":false,"thunk":false},
            "target_function":{"address":"ram:200","name":"callee","external":false,"thunk":false},
            "nodes":[{"address":"ram:100","name":"caller","external":false,"thunk":false,"depth":0},{"address":"ram:200","name":"callee","external":false,"thunk":false,"depth":1}],
            "edges":[{"source":"ram:100","target":"ram:200","site":"ram:105","type":"UNCONDITIONAL_CALL"}],
            "frontier":[],"depth_limit_reached":false,"unresolved_call_references":0,
            "scope":"existing_call_references_to_function_entries","scanned":4,
            "paths":[["ram:100","ram:200"]],"path_kind":"simple_function_paths",
            "truncated":false,"truncation_reason":null,"continuation":null,"time_limit_ms":5000
        });
        assert!(validate("find_call_paths", &p, &v).is_ok());
        v["edges"][0]["target"] = json!("ram:300");
        assert!(validate("find_call_paths", &p, &v).is_err());
        v["edges"] = json!([]);
        assert!(validate("find_call_paths", &p, &v).is_err());
        v["paths"] = json!([]);
        assert!(validate("find_call_paths", &p, &v).is_ok());
    }
    #[test]
    fn references_keep_non_cpu_endpoint_spaces_and_range_contract() {
        let p =
            json!({"expected_program_id":"p","start":"ram:100","end":"ram:110","direction":"from"});
        let mut v = json!({"start":"ram:100","end":"ram:110","direction":"from",
            "references":[{"from":"ram:105","to":"Stack:fffffffffffffffc","type":"READ","operand_index":1,"primary":true,"source":"ANALYSIS"}],
            "scanned":1,"cursor_skipped":0,"scan_unit":"references","time_limit_ms":5000,
            "truncated":false,"truncation_reason":null,"continuation":null});
        assert!(validate("get_references_range", &p, &v).is_ok());
        v["references"][0]["from"] = json!("ram:111");
        assert!(validate("get_references_range", &p, &v).is_err());
        v["references"][0]["from"] = json!("ram:105");
        v["truncated"] = json!(true);
        v["truncation_reason"] = json!("result_limit");
        v["continuation"] = json!({"cursor":"ram:104","cursor_offset":0});
        assert!(validate("get_references_range", &p, &v).is_err());
    }
}
