use super::{array, boolean, same_address, string};
use crate::domain;
use serde_json::Value;

fn number(value: &Value, name: &str, max: u64) -> Result<u64, String> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .filter(|n| *n <= max)
        .ok_or_else(|| format!("invalid {name}"))
}

fn nullable_text(value: &Value, name: &str, max: usize) -> Result<(), String> {
    match value.get(name) {
        Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s.chars().count() <= max => Ok(()),
        _ => Err(format!("invalid or oversized {name}")),
    }
}

fn data_info(value: &Value) -> Result<(), String> {
    domain::address(string(value, "address", 512)?)?;
    string(value, "data_type", 1024)?;
    string(value, "type_path", 4096)?;
    number(value, "length", i32::MAX as u64)?;
    number(value, "num_components", i32::MAX as u64)?;
    nullable_text(value, "value", 4096)?;
    let omitted = boolean(value, "value_omitted")?;
    let truncated = boolean(value, "value_truncated")?;
    if (omitted && (!value["value"].is_null() || truncated))
        || (truncated && !value["value"].is_string())
    {
        return Err("inconsistent data representation flags".into());
    }
    Ok(())
}

fn varnode(value: &Value) -> Result<(), String> {
    string(value, "space", 256)?;
    domain::hex(string(value, "offset", 16)?, "varnode offset")?;
    if number(value, "size", 65536)? == 0 {
        return Err("zero-sized P-code varnode".into());
    }
    Ok(())
}

pub(super) fn validate(operation: &str, params: &Value, value: &Value) -> Result<(), String> {
    same_address(value, params)?;
    match operation {
        "get_comments" => {
            let names = ["eol", "pre", "post", "plate", "repeatable"];
            let comments = value
                .get("comments")
                .filter(|v| v.is_object())
                .ok_or("missing comments")?;
            for name in names {
                nullable_text(comments, name, 8192)?;
            }
            let truncated = array(value, "truncated_types")?;
            let mut seen = std::collections::HashSet::new();
            for item in truncated {
                let name = item.as_str().ok_or("invalid truncated comment type")?;
                if !names.contains(&name) || !seen.insert(name) || !comments[name].is_string() {
                    return Err("inconsistent truncated comment types".into());
                }
            }
        }
        "get_data" => {
            let found = boolean(value, "found")?;
            let components = array(value, "components")?;
            let offset = number(value, "component_offset", i32::MAX as u64)?;
            if value.get("component_offset") != params.get("component_offset")
                || components.len() as u64 > params["component_limit"].as_u64().unwrap_or_default()
            {
                return Err("data page does not match request".into());
            }
            let total = if found {
                let data = value.get("data").ok_or("missing defined data")?;
                data_info(data)?;
                let (space, start) = domain::address(data["address"].as_str().unwrap())?;
                let (requested_space, requested) =
                    domain::address(params["address"].as_str().unwrap())?;
                if space != requested_space
                    || requested < start
                    || requested - start >= data["length"].as_u64().unwrap().max(1)
                {
                    return Err("data definition does not contain requested address".into());
                }
                data["num_components"].as_u64().unwrap()
            } else {
                if value.get("data") != Some(&Value::Null) || !components.is_empty() {
                    return Err("undefined address has data/components".into());
                }
                0
            };
            let expected_count = total
                .saturating_sub(offset)
                .min(params["component_limit"].as_u64().unwrap());
            if components.len() as u64 != expected_count
                || boolean(value, "has_more")? != (offset + (components.len() as u64) < total)
            {
                return Err("inconsistent data component pagination".into());
            }
            for (index, component) in components.iter().enumerate() {
                data_info(component)?;
                if component["index"].as_u64() != Some(offset + index as u64) {
                    return Err("incorrect data component index".into());
                }
            }
        }
        "get_pcode" => {
            if string(value, "pcode_kind", 16)? != "raw"
                || boolean(value, "includes_flow_overrides")?
            {
                return Err("unexpected P-code semantics".into());
            }
            let instructions = array(value, "instructions")?;
            if instructions.len() as u64 > params["count"].as_u64().unwrap_or_default() {
                return Err("P-code instruction count exceeds request".into());
            }
            let mut operations = 0;
            let mut nodes = 0;
            let (space, mut next) = domain::address(params["address"].as_str().unwrap())?;
            for (index, instruction) in instructions.iter().enumerate() {
                let actual = domain::address(string(instruction, "address", 512)?)?;
                if actual != (space, next) {
                    return Err(
                        "P-code instructions are not contiguous from requested address".into(),
                    );
                }
                let length = number(instruction, "length", i32::MAX as u64)?;
                if length == 0 {
                    return Err("zero-length P-code instruction".into());
                }
                if index + 1 < instructions.len() {
                    next = next.checked_add(length).ok_or("P-code address overflow")?;
                }
                string(instruction, "mnemonic", 256)?;
                for (op_index, op) in array(instruction, "operations")?.iter().enumerate() {
                    operations += 1;
                    if op["index"].as_u64() != Some(op_index as u64) {
                        return Err("P-code operation index mismatch".into());
                    }
                    string(op, "opcode", 128)?;
                    let inputs = array(op, "inputs")?;
                    if inputs.len() > 32 {
                        return Err("too many P-code inputs".into());
                    }
                    for node in inputs {
                        varnode(node)?;
                        nodes += 1;
                    }
                    let output = op.get("output").ok_or("missing P-code output")?;
                    if !output.is_null() {
                        varnode(output)?;
                        nodes += 1;
                    }
                }
            }
            if number(value, "operation_count", 2048)? != operations
                || number(value, "varnode_count", 8192)? != nodes
            {
                return Err("P-code totals mismatch or exceed limits".into());
            }
            let truncated = boolean(value, "truncated")?;
            match value.get("truncation_reason") {
                Some(Value::Null) if !truncated && !instructions.is_empty() => {}
                Some(Value::String(reason))
                    if truncated && reason == "operation_or_varnode_limit" => {}
                Some(Value::String(reason))
                    if truncated
                        && reason == "instruction_count"
                        && instructions.len() as u64
                            == params["count"].as_u64().unwrap_or_default() => {}
                _ => return Err("inconsistent P-code truncation".into()),
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn comments_preserve_multiline_text_and_reject_oversized_or_inconsistent_results() {
        let params = json!({"address":"ram:400080"});
        let good = json!({"address":"ram:00400080","comments":{"eol":"one\ntwo\tthree","pre":null,"post":null,"plate":"","repeatable":null},"truncated_types":[]});
        validate("get_comments", &params, &good).unwrap();
        for (key, bad) in [("eol", json!("x".repeat(8193))), ("pre", json!(42))] {
            let mut value = good.clone();
            value["comments"][key] = bad;
            assert!(validate("get_comments", &params, &value).is_err());
        }
        let mut bad = good;
        bad["truncated_types"] = json!(["repeatable"]);
        assert!(validate("get_comments", &params, &bad).is_err());
    }

    #[test]
    fn data_pages_validate_containment_and_pagination() {
        let params = json!({"address":"ram:400081","component_offset":1,"component_limit":1});
        let scalar = json!({"address":"ram:400082","data_type":"word","type_path":"/word","length":2,"num_components":0,"value":"6Eh","value_omitted":false,"value_truncated":false,"index":1});
        let good = json!({"address":"ram:400081","found":true,"data":{"address":"ram:400080","data_type":"word[8]","type_path":"/word[8]","length":16,"num_components":8,"value":null,"value_omitted":true,"value_truncated":false},"components":[scalar],"component_offset":1,"has_more":true});
        validate("get_data", &params, &good).unwrap();
        for (pointer, replacement) in [
            ("/data/address", json!("ram:400090")),
            ("/components/0/index", json!(2)),
            ("/has_more", json!(false)),
            ("/data/value", json!("unexpected composite value")),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = replacement;
            assert!(validate("get_data", &params, &bad).is_err(), "{pointer}");
        }
    }

    #[test]
    fn pcode_keeps_unsigned_offsets_and_checks_semantics_totals_and_contiguity() {
        let params = json!({"address":"ram:400000","count":2});
        let node = json!({"space":"const","offset":"ffffffffffffffff","size":8});
        let good = json!({"address":"ram:400000","pcode_kind":"raw","includes_flow_overrides":false,"instructions":[{"address":"ram:400000","length":5,"mnemonic":"MOV","operations":[{"index":0,"opcode":"COPY","output":{"space":"register","offset":"0","size":8},"inputs":[node]}]},{"address":"ram:400005","length":1,"mnemonic":"RET","operations":[]}],"operation_count":1,"varnode_count":2,"truncated":false,"truncation_reason":null});
        validate("get_pcode", &params, &good).unwrap();
        for (pointer, replacement) in [
            ("/operation_count", json!(0)),
            ("/varnode_count", json!(8193)),
            ("/includes_flow_overrides", json!(true)),
            ("/instructions/1/address", json!("ram:400006")),
            ("/instructions/0/operations/0/inputs/0/offset", json!(42)),
            ("/truncated", json!(true)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = replacement;
            assert!(validate("get_pcode", &params, &bad).is_err(), "{pointer}");
        }
    }
}
