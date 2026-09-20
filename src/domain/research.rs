//! Bounded inputs for read-only inspection of existing native analysis.
use super::{Validate, address, hex, identity, text};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn limit(value: u32, max: u32, name: &str) -> Result<(), String> {
    if !(1..=max).contains(&value) {
        return Err(format!("{name} must be between 1 and {max}"));
    }
    Ok(())
}
fn d128() -> u32 {
    128
}
fn d512() -> u32 {
    512
}
fn d2() -> u32 {
    2
}
fn d8() -> u32 {
    8
}
fn d10() -> u32 {
    10
}
fn d100() -> u32 {
    100
}
fn d20000() -> u32 {
    20000
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionDetailsParams {
    pub expected_program_id: String,
    pub address: String,
    /// Maximum entries in each of body ranges, parameters, and local variables.
    #[serde(default = "d128")]
    #[schemars(range(min = 1, max = 256))]
    pub limit: u32,
}
impl Validate for FunctionDetailsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        limit(self.limit, 256, "limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControlFlowParams {
    pub expected_program_id: String,
    pub address: String,
    #[serde(default = "d128")]
    #[schemars(range(min = 1, max = 256))]
    pub max_blocks: u32,
    #[serde(default = "d512")]
    #[schemars(range(min = 1, max = 2048))]
    pub max_edges: u32,
}
impl Validate for ControlFlowParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        limit(self.max_blocks, 256, "max_blocks")?;
        limit(self.max_edges, 2048, "max_edges")
    }
}

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CallDirection {
    Callers,
    #[default]
    Callees,
    Both,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallGraphParams {
    pub expected_program_id: String,
    pub address: String,
    #[serde(default)]
    pub direction: CallDirection,
    #[serde(default = "d2")]
    #[schemars(range(min = 1, max = 8))]
    pub max_depth: u32,
    #[serde(default = "d128")]
    #[schemars(range(min = 1, max = 256))]
    pub max_nodes: u32,
    #[serde(default = "d512")]
    #[schemars(range(min = 1, max = 2048))]
    pub max_edges: u32,
}
impl Validate for CallGraphParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        limit(self.max_depth, 8, "max_depth")?;
        limit(self.max_nodes, 256, "max_nodes")?;
        limit(self.max_edges, 2048, "max_edges")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallPathsParams {
    pub expected_program_id: String,
    pub source: String,
    pub target: String,
    #[serde(default = "d8")]
    #[schemars(range(min = 1, max = 16))]
    pub max_depth: u32,
    #[serde(default = "d10")]
    #[schemars(range(min = 1, max = 64))]
    pub max_paths: u32,
    #[serde(default = "d128")]
    #[schemars(range(min = 1, max = 256))]
    pub max_nodes: u32,
    #[serde(default = "d512")]
    #[schemars(range(min = 1, max = 2048))]
    pub max_edges: u32,
}
impl Validate for CallPathsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.source)?;
        address(&self.target)?;
        limit(self.max_depth, 16, "max_depth")?;
        limit(self.max_paths, 64, "max_paths")?;
        limit(self.max_nodes, 256, "max_nodes")?;
        limit(self.max_edges, 2048, "max_edges")
    }
}

fn scan_range(
    start: &Option<String>,
    end: &Option<String>,
    cursor: &Option<String>,
) -> Result<(), String> {
    match (start, end) {
        (Some(s), Some(e)) => {
            let (ss, so) = address(s)?;
            let (es, eo) = address(e)?;
            if ss != es || so > eo {
                return Err(
                    "start/end must be an ordered inclusive range in one address space".into(),
                );
            }
            if let Some(c) = cursor {
                let (cs, co) = address(c)?;
                if cs != ss || co < so || co > eo {
                    return Err("cursor must lie in requested range".into());
                }
            }
        }
        (None, None) => {
            if let Some(c) = cursor {
                address(c)?;
            }
        }
        _ => return Err("provide both start and end or neither".into()),
    }
    Ok(())
}

// Fields are repeated rather than flattened: deny_unknown_fields must apply to the entire input.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchConstantsParams {
    pub expected_program_id: String,
    /// Unsigned scalar bit pattern, in hexadecimal; not an inferred address or signed decimal.
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 64))]
    pub scalar_bits: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default = "d100")]
    #[schemars(range(min = 1, max = 200))]
    pub limit: u32,
    #[serde(default = "d20000")]
    #[schemars(range(min = 1, max = 100000))]
    pub scan_limit: u32,
}
impl Validate for SearchConstantsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        let value = hex(&self.value, "value")?;
        if let Some(bits) = self.scalar_bits {
            limit(bits, 64, "scalar_bits")?;
            if bits < 64 && value >= (1u64 << bits) {
                return Err("value does not fit scalar_bits".into());
            }
        }
        scan_range(&self.start, &self.end, &self.cursor)?;
        limit(self.limit, 200, "limit")?;
        limit(self.scan_limit, 100000, "scan_limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchInstructionsParams {
    pub expected_program_id: String,
    /// Exact mnemonic, compared without ASCII case. At least one filter is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mnemonic: Option<String>,
    /// Case-sensitive literal substring of one rendered operand; never a regular expression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operand_contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default = "d100")]
    #[schemars(range(min = 1, max = 200))]
    pub limit: u32,
    #[serde(default = "d20000")]
    #[schemars(range(min = 1, max = 100000))]
    pub scan_limit: u32,
}
impl Validate for SearchInstructionsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        if self.mnemonic.is_none() && self.operand_contains.is_none() {
            return Err("at least one instruction filter is required".into());
        }
        if let Some(v) = &self.mnemonic {
            text(v, "mnemonic", 128)?;
            if !v.is_ascii() {
                return Err("mnemonic must be ASCII".into());
            }
        }
        if let Some(v) = &self.operand_contains {
            text(v, "operand_contains", 256)?;
        }
        scan_range(&self.start, &self.end, &self.cursor)?;
        limit(self.limit, 200, "limit")?;
        limit(self.scan_limit, 100000, "scan_limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchPcodeParams {
    pub expected_program_id: String,
    /// Exact uppercase native raw P-code opcode, e.g. COPY, CALL, LOAD.
    pub opcode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default = "d100")]
    #[schemars(range(min = 1, max = 200))]
    pub limit: u32,
    #[serde(default = "d20000")]
    #[schemars(range(min = 1, max = 100000))]
    pub scan_limit: u32,
}
impl Validate for SearchPcodeParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        text(&self.opcode, "opcode", 64)?;
        if !self
            .opcode
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
        {
            return Err("opcode must be an uppercase native P-code mnemonic".into());
        }
        scan_range(&self.start, &self.end, &self.cursor)?;
        limit(self.limit, 200, "limit")?;
        limit(self.scan_limit, 100000, "scan_limit")
    }
}

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RangeReferenceDirection {
    #[default]
    From,
    To,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReferencesRangeParams {
    pub expected_program_id: String,
    pub start: String,
    pub end: String,
    #[serde(default)]
    pub direction: RangeReferenceDirection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Index within the reference list at cursor; use the returned continuation unchanged.
    #[serde(default)]
    #[schemars(range(max = 100000))]
    pub cursor_offset: u32,
    #[serde(default = "d100")]
    #[schemars(range(min = 1, max = 500))]
    pub limit: u32,
    #[serde(default = "d20000")]
    #[schemars(range(min = 1, max = 100000))]
    pub scan_limit: u32,
}
impl Validate for ReferencesRangeParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        scan_range(
            &Some(self.start.clone()),
            &Some(self.end.clone()),
            &self.cursor,
        )?;
        if self.cursor_offset > 100000 || (self.cursor_offset != 0 && self.cursor.is_none()) {
            return Err("cursor_offset requires a cursor and must not exceed 100000".into());
        }
        limit(self.limit, 500, "limit")?;
        limit(self.scan_limit, 100000, "scan_limit")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn valid<T: for<'a> Deserialize<'a> + Validate>(v: Value) -> bool {
        serde_json::from_value::<T>(v).is_ok_and(|v| v.validate().is_ok())
    }
    #[test]
    fn strict_research_inputs() {
        let base = json!({"expected_program_id":"p","value":"ffffffffffffffff"});
        assert!(valid::<SearchConstantsParams>(base.clone()));
        for change in [
            json!({"scalar_bits":32}),
            json!({"start":"ram:10"}),
            json!({"scan_limit":100001}),
            json!({"unknown":true}),
        ] {
            let mut v = base.clone();
            v.as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
            assert!(!valid::<SearchConstantsParams>(v));
        }
        assert!(!valid::<SearchInstructionsParams>(
            json!({"expected_program_id":"p"})
        ));
        assert!(!valid::<SearchInstructionsParams>(
            json!({"expected_program_id":"p","mnemonic":"MOV","start":"ram:20","end":"ram:10"})
        ));
        assert!(valid::<SearchPcodeParams>(
            json!({"expected_program_id":"p","opcode":"COPY"})
        ));
        assert!(!valid::<SearchPcodeParams>(
            json!({"expected_program_id":"p","opcode":"copy"})
        ));
        assert!(!valid::<CallGraphParams>(
            json!({"expected_program_id":"p","address":"ram:10","max_depth":9})
        ));
        assert!(!valid::<ReferencesRangeParams>(
            json!({"expected_program_id":"p","start":"ram:10","end":"ram:20","cursor":"ram:21"})
        ));
    }
}
