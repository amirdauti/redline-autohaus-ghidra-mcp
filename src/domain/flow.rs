//! Bounded decompiler, graph, comparison and isolated emulator inputs.
use super::{Validate, address, hex, identity, text};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn default_ops() -> u32 {
    128
}
fn default_depth() -> u32 {
    4
}
fn default_nodes() -> u32 {
    64
}
fn default_refs() -> u32 {
    100
}
fn default_window() -> u32 {
    4
}
fn default_scan() -> u32 {
    25
}
fn default_matches() -> u32 {
    10
}
fn default_instructions() -> u32 {
    1024
}
fn default_steps() -> u32 {
    1000
}
fn bounded(n: u32, min: u32, max: u32, field: &str) -> Result<(), String> {
    if !(min..=max).contains(&n) {
        return Err(format!("{field} must be {min}..{max}"));
    }
    Ok(())
}
fn base(id: &str, at: &str) -> Result<(), String> {
    identity(id)?;
    address(at)?;
    Ok(())
}
fn addresses(values: &[String], max: usize) -> Result<(), String> {
    if values.is_empty() || values.len() > max {
        return Err(format!("addresses requires 1..{max} entries"));
    }
    for at in values {
        address(at)?;
    }
    Ok(())
}
fn cursor(at: &Option<String>) -> Result<(), String> {
    if let Some(at) = at {
        address(at)?;
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HighPcodeParams {
    pub expected_program_id: String,
    pub address: String,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_ops")]
    pub limit: u32,
}
impl Validate for HighPcodeParams {
    fn validate(&self) -> Result<(), String> {
        base(&self.expected_program_id, &self.address)?;
        bounded(self.offset, 0, 20000, "offset")?;
        bounded(self.limit, 1, 512, "limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    Forward,
    Backward,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceDataFlowParams {
    pub expected_program_id: String,
    pub address: String,
    pub expected_snapshot_id: String,
    pub operation_address: String,
    pub operation_time: u32,
    /// -1 selects the operation output; 0..31 selects an input.
    pub operand_index: i32,
    pub direction: FlowDirection,
    #[serde(default = "default_depth")]
    pub max_depth: u32,
    #[serde(default = "default_nodes")]
    pub max_nodes: u32,
}
impl Validate for TraceDataFlowParams {
    fn validate(&self) -> Result<(), String> {
        base(&self.expected_program_id, &self.address)?;
        address(&self.operation_address)?;
        if self.expected_snapshot_id.len() != 64
            || !self
                .expected_snapshot_id
                .bytes()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err("expected_snapshot_id must be a SHA-256 from get_high_pcode".into());
        }
        if !(-1..=31).contains(&self.operand_index) {
            return Err("operand_index must be -1..31".into());
        }
        bounded(self.max_depth, 1, 8, "max_depth")?;
        bounded(self.max_nodes, 1, 128, "max_nodes")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchDecompileParams {
    pub expected_program_id: String,
    pub addresses: Vec<String>,
}
impl Validate for BatchDecompileParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        addresses(&self.addresses, 8)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceDirection {
    To,
    From,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchReferencesParams {
    pub expected_program_id: String,
    pub addresses: Vec<String>,
    pub direction: ReferenceDirection,
    #[serde(default = "default_refs")]
    pub limit_per_address: u32,
}
impl Validate for BatchReferencesParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        addresses(&self.addresses, 32)?;
        bounded(self.limit_per_address, 1, 200, "limit_per_address")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchDecompiledCodeParams {
    pub expected_program_id: String,
    pub text: String,
    #[serde(default)]
    pub start_after: Option<String>,
    #[serde(default = "default_window")]
    pub function_limit: u32,
}
impl Validate for SearchDecompiledCodeParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        text(&self.text, "text", 256)?;
        cursor(&self.start_after)?;
        bounded(self.function_limit, 1, 8, "function_limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionFingerprintParams {
    pub expected_program_id: String,
    pub address: String,
    #[serde(default = "default_instructions")]
    pub max_instructions: u32,
}
impl Validate for FunctionFingerprintParams {
    fn validate(&self) -> Result<(), String> {
        base(&self.expected_program_id, &self.address)?;
        bounded(self.max_instructions, 1, 4096, "max_instructions")
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareFunctionsParams {
    pub expected_program_id: String,
    pub address: String,
    pub other_address: String,
    #[serde(default = "default_instructions")]
    pub max_instructions: u32,
}
impl Validate for CompareFunctionsParams {
    fn validate(&self) -> Result<(), String> {
        base(&self.expected_program_id, &self.address)?;
        address(&self.other_address)?;
        bounded(self.max_instructions, 1, 4096, "max_instructions")
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindSimilarFunctionsParams {
    pub expected_program_id: String,
    pub address: String,
    #[serde(default)]
    pub start_after: Option<String>,
    #[serde(default = "default_scan")]
    pub function_limit: u32,
    #[serde(default = "default_matches")]
    pub result_limit: u32,
    #[serde(default = "default_instructions")]
    pub max_instructions: u32,
}
impl Validate for FindSimilarFunctionsParams {
    fn validate(&self) -> Result<(), String> {
        base(&self.expected_program_id, &self.address)?;
        cursor(&self.start_after)?;
        bounded(self.function_limit, 1, 100, "function_limit")?;
        bounded(self.result_limit, 1, 25, "result_limit")?;
        bounded(self.max_instructions, 1, 4096, "max_instructions")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmulatorRegister {
    pub name: String,
    pub value: String,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmulatorMemory {
    pub address: String,
    pub bytes: Vec<u8>,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmulatorRead {
    pub address: String,
    pub count: u32,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmulateFunctionParams {
    pub expected_program_id: String,
    pub address: String,
    pub stop_address: String,
    #[serde(default)]
    pub registers: Vec<EmulatorRegister>,
    #[serde(default)]
    pub memory: Vec<EmulatorMemory>,
    pub output_registers: Vec<String>,
    #[serde(default)]
    pub output_memory: Vec<EmulatorRead>,
    #[serde(default = "default_steps")]
    pub max_steps: u32,
}
impl Validate for EmulateFunctionParams {
    fn validate(&self) -> Result<(), String> {
        base(&self.expected_program_id, &self.address)?;
        address(&self.stop_address)?;
        if self.registers.len() > 32
            || self.memory.len() > 16
            || self.output_memory.len() > 16
            || self.output_registers.is_empty()
            || self.output_registers.len() > 16
        {
            return Err("emulator input/output list limit exceeded".into());
        }
        for r in &self.registers {
            text(&r.name, "register", 64)?;
            hex(&r.value, "register value")?;
        }
        for r in &self.output_registers {
            text(r, "output register", 64)?;
        }
        let mut total = 0;
        for m in &self.memory {
            address(&m.address)?;
            if m.bytes.is_empty() || m.bytes.len() > 4096 {
                return Err("memory bytes must contain 1..4096 bytes".into());
            }
            total += m.bytes.len();
        }
        if total > 8192 {
            return Err("memory inputs exceed 8192 bytes".into());
        }
        let mut total = 0u32;
        for m in &self.output_memory {
            address(&m.address)?;
            bounded(m.count, 1, 4096, "output memory count")?;
            total += m.count;
        }
        if total > 8192 {
            return Err("memory outputs exceed 8192 bytes".into());
        }
        bounded(self.max_steps, 1, 10000, "max_steps")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flow_inputs_reject_oversized_work_and_unknown_nested_emulator_fields() {
        let params: BatchDecompileParams = serde_json::from_value(json!({
            "expected_program_id":"synthetic", "addresses":vec!["ram:400000";9]
        }))
        .unwrap();
        assert!(params.validate().is_err());
        let trace: TraceDataFlowParams = serde_json::from_value(json!({
            "expected_program_id":"synthetic","address":"ram:400000",
            "expected_snapshot_id":"0".repeat(64),"operation_address":"ram:400000",
            "operation_time":0,"operand_index":32,"direction":"backward"
        }))
        .unwrap();
        assert!(trace.validate().is_err());
        assert!(serde_json::from_value::<EmulateFunctionParams>(json!({
            "expected_program_id":"synthetic","address":"ram:400000","stop_address":"ram:400005",
            "output_registers":["EAX"],"memory":[{"address":"ram:400010","bytes":[0],"write_to_program":true}]
        })).is_err());
    }

    #[test]
    fn emulator_accepts_unsigned_register_bits_but_caps_total_memory() {
        let mut value = json!({"expected_program_id":"synthetic","address":"ram:400000","stop_address":"ram:400005",
            "registers":[{"name":"RAX","value":"ffffffffffffffff"}],"output_registers":["RAX"]});
        serde_json::from_value::<EmulateFunctionParams>(value.clone())
            .unwrap()
            .validate()
            .unwrap();
        value["memory"] = json!([
            {"address":"ram:401000","bytes":vec![0u8;4096]},
            {"address":"ram:402000","bytes":vec![0u8;4096]},
            {"address":"ram:403000","bytes":[0]}
        ]);
        assert!(
            serde_json::from_value::<EmulateFunctionParams>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
