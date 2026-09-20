use super::{array, boolean, same_address, string};
use crate::domain;
use serde_json::Value;

pub(super) fn supports(op: &str) -> bool {
    matches!(
        op,
        "get_listing"
            | "hash_memory"
            | "preview_instructions"
            | "get_processor_context"
            | "set_processor_context"
            | "clear_listing"
            | "list_bookmarks"
            | "set_bookmark"
            | "delete_bookmark"
            | "list_comments"
            | "batch_set_comments"
            | "get_function_tags"
            | "update_function_tags"
            | "batch_rename"
            | "compare_program_memory"
    )
}
fn count(v: &Value, key: &str, max: u64) -> Result<u64, String> {
    v[key]
        .as_u64()
        .filter(|n| *n <= max)
        .ok_or_else(|| format!("invalid {key}"))
}
fn hash(v: &Value, key: &str) -> Result<(), String> {
    let s = string(v, key, 64)?;
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("invalid {key}"));
    }
    Ok(())
}
fn optional_text(v: &Value, key: &str, max: usize) -> Result<(), String> {
    match v.get(key) {
        Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s.chars().count() <= max => Ok(()),
        _ => Err(format!("invalid {key}")),
    }
}
fn at(v: &Value) -> Result<(), String> {
    domain::address(string(v, "address", 512)?)?;
    Ok(())
}
fn bounded<'a>(v: &'a Value, key: &str, max: usize) -> Result<&'a Vec<Value>, String> {
    let a = array(v, key)?;
    if a.len() > max {
        return Err(format!("too many {key}"));
    }
    Ok(a)
}
fn next(v: &Value) -> Result<(), String> {
    match v.get("next_address") {
        Some(Value::Null) => Ok(()),
        Some(Value::String(s)) => {
            domain::address(s)?;
            Ok(())
        }
        _ => Err("invalid next_address".into()),
    }
}
fn bookmark(v: &Value) -> Result<(), String> {
    at(v)?;
    string(v, "bookmark_type", 64)?;
    string(v, "category", 128)?;
    optional_text(v, "comment", 8192)?;
    boolean(v, "comment_truncated")?;
    Ok(())
}
fn requested_end(p: &Value, v: &Value) -> Result<(), String> {
    let (space, start) =
        domain::address(p["address"].as_str().ok_or("missing requested address")?)?;
    let length = p["length"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("invalid requested length")?;
    let expected = start.checked_add(length - 1).ok_or("range overflow")?;
    if domain::address(string(v, "end", 512)?)? != (space, expected) {
        return Err("returned end does not match requested range".into());
    }
    Ok(())
}
pub(super) fn validate(op: &str, p: &Value, v: &Value) -> Result<(), String> {
    if !v.is_object() {
        return Err("result must be object".into());
    }
    if p.get("address").is_some() {
        same_address(v, p)?;
    }
    if matches!(
        op,
        "get_listing" | "set_processor_context" | "clear_listing" | "list_comments"
    ) {
        requested_end(p, v)?;
    }
    match op {
        "get_listing" => {
            let (space, start) = domain::address(p["address"].as_str().ok_or("address")?)?;
            let end = start
                .checked_add(p["length"].as_u64().ok_or("length")? - 1)
                .ok_or("range overflow")?;
            let mut previous = None;
            for item in bounded(v, "items", p["limit"].as_u64().unwrap_or(128) as usize)? {
                let (s, a) = domain::address(string(item, "address", 512)?)?;
                let (es, e) = domain::address(string(item, "end", 512)?)?;
                if s != space
                    || es != space
                    || a > end
                    || e < start
                    || a > e
                    || previous.is_some_and(|prev| a <= prev)
                {
                    return Err("listing order/range mismatch".into());
                }
                previous = Some(e);
                if count(item, "length", i32::MAX as u64)? != e - a + 1 {
                    return Err("listing length mismatch".into());
                }
                if !matches!(
                    string(item, "kind", 16)?,
                    "data" | "instruction" | "undefined"
                ) {
                    return Err("unknown unit kind".into());
                }
                string(item, "display", 512)?;
                boolean(item, "display_truncated")?;
            }
            boolean(v, "truncated")?;
            next(v)?;
        }
        "hash_memory" => {
            if v["length"] != p["length"] || v["source"] != "current_program_memory" {
                return Err("hash range/source mismatch".into());
            }
            hash(v, "sha256")?;
        }
        "preview_instructions" => {
            let mut cursor = domain::address(p["address"].as_str().ok_or("address")?)?;
            for item in bounded(v, "instructions", p["count"].as_u64().unwrap_or(0) as usize)? {
                let actual = domain::address(string(item, "address", 512)?)?;
                if actual != cursor {
                    return Err("preview instructions not contiguous".into());
                }
                let n = count(item, "length", 65536)?;
                if n == 0 {
                    return Err("zero-length preview".into());
                }
                cursor.1 = cursor.1.checked_add(n).ok_or("preview overflow")?;
                string(item, "mnemonic", 256)?;
                string(item, "display", 1024)?;
                count(item, "delay_slots", 256)?;
            }
            if boolean(v, "writes_listing")? {
                return Err("preview changed listing".into());
            }
            string(v, "stop_reason", 128)?;
            next(v)?;
        }
        "get_processor_context" => {
            if v["offset"] != p["offset"] {
                return Err("context offset mismatch".into());
            }
            let total = count(v, "total", 65536)?;
            let offset = p["offset"].as_u64().unwrap_or(0);
            let limit = p["limit"].as_u64().unwrap_or(128);
            let registers = bounded(v, "registers", limit as usize)?;
            if registers.len() as u64 != total.saturating_sub(offset).min(limit)
                || boolean(v, "has_more")? != (offset + (registers.len() as u64) < total)
            {
                return Err("context pagination mismatch".into());
            }
            if let Some(name) = p["register"].as_str() {
                if total != 1 || registers.iter().any(|r| r["name"] != name) {
                    return Err("requested register mismatch".into());
                }
            }
            for r in registers {
                register(r)?;
            }
        }
        "set_processor_context" => {
            if v["length"] != p["length"] || v["register"]["name"] != p["register"] {
                return Err("context readback mismatch".into());
            }
            register(&v["register"])?;
            let wanted = p["value"]
                .as_str()
                .ok_or("value")?
                .trim_start_matches('0')
                .to_ascii_lowercase();
            let actual = v["register"]["value"]
                .as_str()
                .ok_or("missing register value")?
                .trim_start_matches('0')
                .to_ascii_lowercase();
            if wanted != actual {
                return Err("register value mismatch".into());
            }
        }
        "clear_listing" => {
            if v["length"] != p["length"] || !boolean(v, "undefined")? {
                return Err("clear readback mismatch".into());
            }
            count(v, "cleared_units", 65536)?;
            hash(v, "bytes_sha256")?;
            domain::address(string(v, "end", 512)?)?;
        }
        "list_bookmarks" => {
            if v["offset"] != p["offset"] {
                return Err("bookmark offset mismatch".into());
            }
            let rows = bounded(v, "bookmarks", p["limit"].as_u64().unwrap_or(128) as usize)?;
            for b in rows {
                bookmark(b)?;
            }
            if boolean(v, "has_more")? {
                if v["next_offset"].as_u64()
                    != Some(p["offset"].as_u64().unwrap_or(0) + rows.len() as u64)
                {
                    return Err("bookmark continuation mismatch".into());
                }
            } else if !v["next_offset"].is_null() {
                return Err("unexpected bookmark continuation".into());
            }
        }
        "set_bookmark" => {
            bookmark(v)?;
            for key in ["bookmark_type", "category", "comment"] {
                if v[key] != p[key] {
                    return Err("bookmark readback mismatch".into());
                }
            }
            if boolean(v, "comment_truncated")? {
                return Err("bookmark readback truncated".into());
            }
        }
        "delete_bookmark" => {
            if !boolean(v, "deleted")?
                || v["bookmark_type"] != p["bookmark_type"]
                || v["category"] != p["category"]
            {
                return Err("bookmark deletion mismatch".into());
            }
        }
        "list_comments" => {
            if v["comment_type"] != p["comment_type"] {
                return Err("comment type mismatch".into());
            }
            for c in bounded(v, "comments", p["limit"].as_u64().unwrap_or(128) as usize)? {
                at(c)?;
                optional_text(c, "comment", 8192)?;
                boolean(c, "truncated")?;
            }
            count(v, "scanned", 10000)?;
            boolean(v, "truncated")?;
            next(v)?;
        }
        "batch_set_comments" | "batch_rename" => {
            if !boolean(v, "committed")? {
                return Err("batch not committed".into());
            }
            let rows = bounded(v, "updates", 64)?;
            let requested = array(p, "updates")?;
            if rows.len() != requested.len() {
                return Err("batch length mismatch".into());
            }
            for (row, expected) in rows.iter().zip(requested) {
                same_address(row, expected)?;
                let keys = if op == "batch_rename" {
                    ["kind", "name"]
                } else {
                    ["comment_type", "comment"]
                };
                for key in keys {
                    if row[key] != expected[key] {
                        return Err("batch readback mismatch".into());
                    }
                }
            }
        }
        "get_function_tags" | "update_function_tags" => {
            at(v)?;
            let tags = bounded(v, "tags", 256)?;
            let mut seen = std::collections::HashSet::new();
            for t in tags {
                let s = t.as_str().ok_or("invalid tag")?;
                domain::text(s, "tag", 128)?;
                if !seen.insert(s) {
                    return Err("duplicate tag".into());
                }
            }
            if op == "update_function_tags" {
                for t in array(p, "add")? {
                    if !tags.contains(t) {
                        return Err("missing added tag".into());
                    }
                }
                for t in array(p, "remove")? {
                    if tags.contains(t) {
                        return Err("tag not removed".into());
                    }
                }
            }
        }
        "compare_program_memory" => {
            if v["length"] != p["length"]
                || v["other_program_path"] != p["other_program_path"]
                || v["other_version"] != "saved_copy"
                || !string(v, "other_source_sha256", 64)?.eq_ignore_ascii_case(
                    p["expected_other_source_sha256"]
                        .as_str()
                        .ok_or("source hash")?,
                )
            {
                return Err("comparison identity/range mismatch".into());
            }
            if domain::address(string(v, "other_address", 512)?)?
                != domain::address(p["other_address"].as_str().ok_or("other_address")?)?
            {
                return Err("other address mismatch".into());
            }
            hash(v, "sha256")?;
            hash(v, "other_sha256")?;
            boolean(v, "active_changed")?;
            let len = p["length"].as_u64().ok_or("length")?;
            let changed = count(v, "changed_bytes", len)?;
            let total = count(v, "total_changed_ranges", len)?;
            let rows = bounded(
                v,
                "changed_ranges",
                p["limit"].as_u64().unwrap_or(128) as usize,
            )?;
            if total < rows.len() as u64 || boolean(v, "truncated")? != (total > rows.len() as u64)
            {
                return Err("comparison truncation mismatch".into());
            }
            let mut end = 0;
            let mut sum = 0;
            for r in rows {
                let offset = count(r, "offset", len)?;
                let n = count(r, "length", len)?;
                if n == 0 || offset < end || offset + n > len {
                    return Err("invalid changed range".into());
                }
                end = offset + n;
                sum += n;
                at(r)?;
                for key in ["address", "other_address"] {
                    let (space, base) =
                        domain::address(p[key].as_str().ok_or("missing comparison base")?)?;
                    if domain::address(string(r, key, 512)?)?
                        != (
                            space,
                            base.checked_add(offset)
                                .ok_or("comparison address overflow")?,
                        )
                    {
                        return Err("changed range address does not match offset".into());
                    }
                }
            }
            if changed < sum || total == rows.len() as u64 && changed != sum {
                return Err("comparison counts mismatch".into());
            }
        }
        _ => return Err("unsupported utility result".into()),
    }
    Ok(())
}
fn register(r: &Value) -> Result<(), String> {
    string(r, "name", 256)?;
    if count(r, "bits", 65536)? == 0 {
        return Err("zero-sized register".into());
    }
    at(r)?;
    boolean(r, "processor_context")?;
    for key in ["value", "mask"] {
        optional_text(r, key, 16384)?;
        if let Some(s) = r[key].as_str() {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid register hex".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rejects_mismatched_mutation_readbacks() {
        let p = json!({"address":"ram:0","length":1,"register":"EAX","value":"000f"});
        let mut v = json!({"address":"ram:0","end":"ram:0","length":1,"register":{"name":"EAX","address":"register:0","bits":32,"processor_context":false,"value":"f","mask":"ffffffff"}});
        validate("set_processor_context", &p, &v).unwrap();
        v["register"]["value"] = json!("10");
        assert!(validate("set_processor_context", &p, &v).is_err());
        let p =
            json!({"updates":[{"address":"ram:0","comment_type":"plate","comment":"evidence"}]});
        let v = json!({"committed":true,"updates":[{"address":"ram:0","comment_type":"eol","comment":"evidence"}]});
        assert!(validate("batch_set_comments", &p, &v).is_err());
    }
    #[test]
    fn binds_context_pages_and_memory_difference_addresses() {
        let p = json!({"address":"ram:0","register":"EAX","offset":0,"limit":128});
        let mut v = json!({"address":"ram:0","offset":0,"total":1,"has_more":false,"registers":[{"name":"EAX","address":"register:0","bits":32,"processor_context":false,"value":null,"mask":null}]});
        validate("get_processor_context", &p, &v).unwrap();
        v["registers"][0]["name"] = json!("EBX");
        assert!(validate("get_processor_context", &p, &v).is_err());
        let p = json!({"address":"ram:100","other_address":"ram:200","length":4,"other_program_path":"/Saved","expected_other_source_sha256":"a".repeat(64),"limit":128});
        let mut v = json!({"address":"ram:100","other_address":"ram:200","length":4,"other_program_path":"/Saved","other_source_sha256":"a".repeat(64),"other_version":"saved_copy","active_changed":false,"sha256":"b".repeat(64),"other_sha256":"c".repeat(64),"changed_bytes":1,"total_changed_ranges":1,"changed_ranges":[{"offset":1,"length":1,"address":"ram:101","other_address":"ram:201"}],"truncated":false});
        validate("compare_program_memory", &p, &v).unwrap();
        v["changed_ranges"][0]["other_address"] = json!("ram:999");
        assert!(validate("compare_program_memory", &p, &v).is_err());
    }
}
