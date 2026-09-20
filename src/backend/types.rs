//! Checks native type-edit readback before returning it to an MCP caller.
use super::{array, boolean, same_address, string};
use crate::domain;
use serde_json::Value;
use std::collections::HashSet;

pub(super) fn supports(op: &str) -> bool {
    matches!(
        op,
        "get_function_variables"
            | "rename_variable"
            | "set_variable_type"
            | "set_function_signature"
            | "list_data_types"
            | "get_data_type"
            | "create_structure"
            | "set_structure_field"
            | "create_enum"
            | "create_union"
            | "create_typedef"
            | "apply_data_type"
            | "get_structure_field_references"
    )
}
fn keys(v: &Value, allowed: &[&str]) -> Result<(), String> {
    let obj = v.as_object().ok_or("expected object")?;
    if obj.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err("unexpected native type response field".into());
    }
    Ok(())
}
fn num(v: &Value, k: &str, max: u64) -> Result<u64, String> {
    v.get(k)
        .and_then(Value::as_u64)
        .filter(|n| *n <= max)
        .ok_or_else(|| format!("invalid {k}"))
}
fn signed(v: &Value, k: &str, min: i64, max: i64) -> Result<i64, String> {
    v.get(k)
        .and_then(Value::as_i64)
        .filter(|n| *n >= min && *n <= max)
        .ok_or_else(|| format!("invalid {k}"))
}
fn path<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    let s = string(v, k, 4096)?;
    domain::types::type_path(s)?;
    Ok(s)
}
fn nullable(v: &Value, k: &str, max: usize) -> Result<(), String> {
    match v.get(k) {
        Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s.len() <= max && !s.contains('\0') => Ok(()),
        _ => Err(format!("invalid {k}")),
    }
}
fn brief(v: &Value) -> Result<(), String> {
    path(v, "path")?;
    string(v, "name", 4096)?;
    signed(v, "length", -1, i32::MAX as i64)?;
    let kind = string(v, "kind", 16)?;
    if ![
        "structure",
        "union",
        "enum",
        "typedef",
        "pointer",
        "array",
        "other",
    ]
    .contains(&kind)
    {
        return Err("unknown type kind".into());
    }
    Ok(())
}
fn type_info(v: &Value) -> Result<(), String> {
    keys(
        v,
        &[
            "path",
            "name",
            "length",
            "kind",
            "components",
            "component_count",
            "components_truncated",
            "target_path",
            "count",
        ],
    )?;
    brief(v)?;
    let kind = v["kind"].as_str().unwrap();
    let components = array(v, "components")?;
    let count = num(v, "component_count", i32::MAX as u64)?;
    if components.len() != count.min(256) as usize
        || boolean(v, "components_truncated")? != (count > 256)
    {
        return Err("invalid type component bounds".into());
    }
    if !["structure", "union", "enum"].contains(&kind) && count != 0 {
        return Err("non-composite type has components".into());
    }
    let mut names = HashSet::new();
    let mut offsets = HashSet::new();
    for c in components {
        if kind == "enum" {
            keys(c, &["name", "value"])?;
            let n = string(c, "name", 4096)?;
            if !names.insert(n) || c["value"].as_i64().is_none() {
                return Err("invalid enum member".into());
            }
        } else {
            keys(
                c,
                &[
                    "offset",
                    "ordinal",
                    "name",
                    "type_path",
                    "length",
                    "comment",
                    "comment_truncated",
                ],
            )?;
            let at = num(c, "offset", i32::MAX as u64)?;
            num(c, "ordinal", i32::MAX as u64)?;
            let len = num(c, "length", i32::MAX as u64)?;
            path(c, "type_path")?;
            nullable(c, "name", 4096)?;
            nullable(c, "comment", 16384)?;
            if boolean(c, "comment_truncated")? && c["comment"].is_null() {
                return Err("null field comment marked truncated".into());
            }
            if let Some(n) = c["name"].as_str() {
                if !names.insert(n) {
                    return Err("duplicate field name".into());
                }
            }
            if kind == "union" && at != 0 {
                return Err("union field offset is nonzero".into());
            }
            if at + len > v["length"].as_u64().unwrap_or_default() {
                return Err("field exceeds type size".into());
            }
            // Bitfields may share an offset in existing types; inspection preserves that native layout.
            offsets.insert(at);
        }
    }
    if ["typedef", "array"].contains(&kind) {
        path(v, "target_path")?;
    }
    if kind == "pointer" && !v["target_path"].is_null() {
        path(v, "target_path")?;
    }
    if kind == "array" && num(v, "count", i32::MAX as u64)? == 0 {
        return Err("empty array".into());
    }
    Ok(())
}
fn descriptor_path(d: &Value) -> Result<String, String> {
    match d["kind"].as_str() {
        Some("path") => Ok(string(d, "path", 1024)?.into()),
        Some("builtin") => Ok(format!(
            "/{}",
            match d["name"].as_str() {
                Some("u8") => "byte",
                Some("s8") => "sbyte",
                Some("u16") => "word",
                Some("s16") => "sword",
                Some("u32") => "dword",
                Some("s32") => "sdword",
                Some("u64") => "qword",
                Some("s64") => "sqword",
                Some("f32") => "float4",
                Some("f64") => "float8",
                Some("void") => "void",
                _ => return Err("unknown builtin descriptor".into()),
            }
        )),
        Some("pointer") => Ok(format!("{} *", descriptor_path(&d["to"])?)),
        Some("array") => {
            let mut element = d;
            let mut dimensions = String::new();
            while element["kind"] == "array" {
                dimensions.push_str(&format!(
                    "[{}]",
                    element["count"].as_u64().ok_or("array count missing")?
                ));
                element = &element["element"];
            }
            Ok(format!("{}{dimensions}", descriptor_path(element)?))
        }
        _ => Err("invalid descriptor".into()),
    }
}
fn same_type(actual: &str, d: &Value) -> Result<(), String> {
    if actual != descriptor_path(d)? {
        return Err("native type path differs from typed request".into());
    }
    Ok(())
}
fn signature(v: &Value, p: &Value) -> Result<(), String> {
    same_address(v, p)?;
    string(v, "signature", 8192)?;
    path(v, "return_type_path")?;
    string(v, "calling_convention", 200)?;
    boolean(v, "varargs")?;
    let parameters = array(v, "parameters")?;
    let count = num(v, "parameter_count", i32::MAX as u64)?;
    if parameters.len() != count.min(64) as usize {
        return Err("parameter count mismatch".into());
    }
    let mut names = HashSet::new();
    for param in parameters {
        keys(param, &["name", "type_path", "storage"])?;
        let name = string(param, "name", 1024)?;
        if !names.insert(name) {
            return Err("duplicate function parameter".into());
        }
        path(param, "type_path")?;
        string(param, "storage", 2048)?;
    }
    Ok(())
}
pub(super) fn validate(operation: &str, params: &Value, value: &Value) -> Result<(), String> {
    match operation {
        "list_data_types" => {
            keys(value, &["data_types", "offset", "has_more"])?;
            let entries = array(value, "data_types")?;
            if num(value, "offset", 1000000)? != params["offset"].as_u64().unwrap_or(0)
                || entries.len() as u64 > params["limit"].as_u64().unwrap_or(100)
            {
                return Err("type list pagination mismatch".into());
            }
            let more = boolean(value, "has_more")?;
            if more && entries.len() as u64 != params["limit"].as_u64().unwrap_or(100) {
                return Err("truncated page is not full".into());
            }
            let query = params["query"].as_str().unwrap_or("").to_lowercase();
            for e in entries {
                keys(e, &["path", "name", "length", "kind"])?;
                brief(e)?;
                if !e["path"].as_str().unwrap().to_lowercase().contains(&query) {
                    return Err("type does not match query".into());
                }
            }
        }
        "get_data_type"
        | "create_structure"
        | "set_structure_field"
        | "create_enum"
        | "create_union"
        | "create_typedef"
        | "apply_data_type" => {
            keys(
                value,
                if operation == "apply_data_type" {
                    &["address", "length", "data_type"]
                } else {
                    &["data_type"]
                },
            )?;
            let t = value.get("data_type").ok_or("missing type readback")?;
            type_info(t)?;
            if operation == "apply_data_type" {
                same_address(value, params)?;
                if num(value, "length", 1048576)? == 0 || value["length"] != t["length"] {
                    return Err("applied data size mismatch".into());
                }
                same_type(t["path"].as_str().unwrap(), &params["data_type"])?;
            } else if t["path"] != params["path"] {
                return Err("returned type path mismatch".into());
            }
            let components = array(t, "components")?;
            match operation {
                "create_structure" | "create_union" => {
                    let fields = array(params, "fields")?;
                    if t["kind"]
                        != if operation == "create_structure" {
                            "structure"
                        } else {
                            "union"
                        }
                        || components.len() != fields.len()
                        || t["components_truncated"] != false
                    {
                        return Err("created composite layout mismatch".into());
                    }
                    if operation == "create_structure" && t["length"] != params["size"] {
                        return Err("structure length mismatch".into());
                    }
                    for f in fields {
                        let actual = components
                            .iter()
                            .find(|c| c["name"] == f["name"])
                            .ok_or("missing created field")?;
                        same_type(actual["type_path"].as_str().unwrap(), &f["data_type"])?;
                        if operation == "create_structure" && actual["offset"] != f["offset"] {
                            return Err("field offset mismatch".into());
                        }
                        if actual["comment"] != f.get("comment").cloned().unwrap_or(Value::Null) {
                            return Err("field comment mismatch".into());
                        }
                    }
                }
                "set_structure_field" => {
                    if t["kind"] != "structure" {
                        return Err("edited type is not a structure".into());
                    }
                    let actual = components
                        .iter()
                        .find(|c| c["offset"] == params["offset"])
                        .ok_or("edited field missing from bounded readback")?;
                    if actual["name"] != params["name"] {
                        return Err("field name mismatch".into());
                    }
                    same_type(actual["type_path"].as_str().unwrap(), &params["data_type"])?;
                    if let Some(c) = params.get("comment") {
                        if actual["comment"] != *c {
                            return Err("field comment mismatch".into());
                        }
                    }
                }
                "create_enum" => {
                    if t["kind"] != "enum"
                        || t["length"] != params["size"]
                        || components.len() != array(params, "members")?.len()
                    {
                        return Err("enum layout mismatch".into());
                    }
                    for m in array(params, "members")? {
                        if !components
                            .iter()
                            .any(|c| c["name"] == m["name"] && c["value"] == m["value"])
                        {
                            return Err("enum readback mismatch".into());
                        }
                    }
                }
                "create_typedef" => {
                    if t["kind"] != "typedef" {
                        return Err("created type is not typedef".into());
                    }
                    same_type(path(t, "target_path")?, &params["data_type"])?;
                }
                _ => {}
            }
        }
        "get_function_variables" => {
            keys(
                value,
                &[
                    "address",
                    "signature",
                    "return_type_path",
                    "calling_convention",
                    "varargs",
                    "parameters",
                    "parameter_count",
                    "variables",
                    "offset",
                    "total",
                    "has_more",
                    "calling_conventions",
                ],
            )?;
            signature(value, params)?;
            let vars = array(value, "variables")?;
            let offset = num(value, "offset", 1000000)?;
            let total = num(value, "total", 100000)?;
            let limit = params["limit"].as_u64().unwrap_or(100);
            if offset != params["offset"].as_u64().unwrap_or(0)
                || vars.len() as u64 != total.saturating_sub(offset).min(limit)
                || boolean(value, "has_more")? != (offset + (vars.len() as u64) < total)
            {
                return Err("variable pagination mismatch".into());
            }
            let mut ids = HashSet::new();
            for v in vars {
                keys(
                    v,
                    &[
                        "selector",
                        "type_path",
                        "length",
                        "parameter",
                        "parameter_index",
                        "editable",
                    ],
                )?;
                let s = &v["selector"];
                keys(s, &["symbol_id", "name", "storage"])?;
                let id = domain::hex(string(s, "symbol_id", 16)?, "symbol_id")?;
                if !ids.insert(id) {
                    return Err("duplicate variable symbol ID".into());
                }
                string(s, "name", 1024)?;
                string(s, "storage", 2048)?;
                path(v, "type_path")?;
                signed(v, "length", -1, 1048576)?;
                let parameter = boolean(v, "parameter")?;
                let index = signed(v, "parameter_index", -1, i32::MAX as i64)?;
                if parameter != (index >= 0) {
                    return Err("invalid parameter index".into());
                }
                boolean(v, "editable")?;
            }
            let conventions = array(value, "calling_conventions")?;
            if conventions.len() > 256
                || conventions
                    .iter()
                    .any(|c| c.as_str().is_none_or(|s| s.is_empty() || s.len() > 200))
            {
                return Err("invalid calling conventions".into());
            }
        }
        "rename_variable" | "set_variable_type" => {
            keys(
                value,
                &[
                    "address",
                    "committed",
                    "variable",
                    "signature_source_before",
                    "signature_source_after",
                ],
            )?;
            same_address(value, params)?;
            for key in ["signature_source_before", "signature_source_after"] {
                if !["DEFAULT", "ANALYSIS", "IMPORTED", "USER_DEFINED"]
                    .contains(&string(value, key, 16)?)
                {
                    return Err("invalid signature source".into());
                }
            }
            if value["signature_source_before"] != value["signature_source_after"]
                && value["signature_source_after"] != "USER_DEFINED"
            {
                return Err("unexpected signature source change".into());
            }
            if !boolean(value, "committed")? {
                return Err("variable was not committed".into());
            }
            let v = &value["variable"];
            keys(v, &["name", "storage", "type_path", "length"])?;
            string(v, "name", 1024)?;
            string(v, "storage", 2048)?;
            path(v, "type_path")?;
            if num(v, "length", 1048576)? == 0 || v["storage"] != params["selector"]["storage"] {
                return Err("variable storage readback mismatch".into());
            }
            if operation == "rename_variable" {
                if v["name"] != params["name"] {
                    return Err("variable rename mismatch".into());
                }
            } else {
                if v["name"] != params["selector"]["name"] {
                    return Err("variable name changed during type edit".into());
                }
                same_type(v["type_path"].as_str().unwrap(), &params["data_type"])?;
            }
        }
        "set_function_signature" => {
            keys(
                value,
                &[
                    "address",
                    "signature",
                    "return_type_path",
                    "calling_convention",
                    "varargs",
                    "parameters",
                    "parameter_count",
                ],
            )?;
            signature(value, params)?;
            same_type(path(value, "return_type_path")?, &params["return_type"])?;
            let actual = array(value, "parameters")?;
            let expected = array(params, "parameters")?;
            if value["calling_convention"] != params["calling_convention"]
                || value["varargs"] != params["varargs"]
                || actual.len() != expected.len()
            {
                return Err("function signature readback mismatch".into());
            }
            for (a, e) in actual.iter().zip(expected) {
                if a["name"] != e["name"] {
                    return Err("parameter name mismatch".into());
                }
                same_type(path(a, "type_path")?, &e["data_type"])?;
            }
        }
        "get_structure_field_references" => {
            keys(
                value,
                &[
                    "address",
                    "path",
                    "field_offset",
                    "coverage",
                    "exhaustive",
                    "references",
                    "truncated",
                ],
            )?;
            same_address(value, params)?;
            if value["path"] != params["path"]
                || value["field_offset"] != params["field_offset"]
                || value["coverage"] != "single_function_typed_ptrsub_only"
                || boolean(value, "exhaustive")?
            {
                return Err("incorrect field-reference semantics".into());
            }
            let refs = array(value, "references")?;
            if refs.len() as u64 > params["limit"].as_u64().unwrap_or(100) {
                return Err("too many field references".into());
            }
            boolean(value, "truncated")?;
            let mut seen = HashSet::new();
            for r in refs {
                keys(r, &["address", "sequence", "operation", "kind"])?;
                let at = domain::address(string(r, "address", 512)?)?;
                let seq = num(r, "sequence", u32::MAX as u64)?;
                if !seen.insert((at, seq))
                    || r["operation"] != "PTRSUB"
                    || r["kind"] != "field_pointer_derivation"
                {
                    return Err("invalid field reference".into());
                }
            }
        }
        _ => return Err("unsupported type response".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rejects_wrong_variable_commit() {
        let p =
            json!({"address":"ram:00400180","name":"count","selector":{"storage":"Stack[4]:4"}});
        let mut v = json!({"address":"ram:00400180","committed":true,"signature_source_before":"ANALYSIS","signature_source_after":"USER_DEFINED","variable":{"name":"count","storage":"Stack[4]:4","type_path":"/dword","length":4}});
        assert!(validate("rename_variable", &p, &v).is_ok());
        v["variable"]["name"] = json!("wrong");
        assert!(validate("rename_variable", &p, &v).is_err());
    }
    #[test]
    fn rejects_unproven_exhaustiveness() {
        let p = json!({"address":"ram:00400180","path":"/T/Packet","field_offset":4,"limit":10});
        let mut v = json!({"address":"ram:00400180","path":"/T/Packet","field_offset":4,"coverage":"single_function_typed_ptrsub_only","exhaustive":false,"references":[],"truncated":false});
        assert!(validate("get_structure_field_references", &p, &v).is_ok());
        v["exhaustive"] = json!(true);
        assert!(validate("get_structure_field_references", &p, &v).is_err());
    }
    #[test]
    fn nested_arrays_use_native_outer_first_names() {
        let d = json!({"kind":"array","count":2,"element":{"kind":"array","count":4,"element":{"kind":"builtin","name":"u16"}}});
        assert_eq!(descriptor_path(&d).unwrap(), "/word[2][4]");
        assert_eq!(
            descriptor_path(&json!({"kind":"pointer","to":d})).unwrap(),
            "/word[2][4] *"
        );
    }
}
