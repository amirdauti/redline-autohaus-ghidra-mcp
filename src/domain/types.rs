//! Bounded native data type and decompiler-variable operations.
use super::{Validate, address, identity, text};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

fn name(value: &str) -> Result<(), String> {
    text(value, "name", 200)?;
    if !value
        .bytes()
        .enumerate()
        .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
    {
        return Err("names must be ASCII identifiers".into());
    }
    Ok(())
}
pub fn type_path(value: &str) -> Result<(), String> {
    text(value, "type path", 1024)?;
    if !value.starts_with('/')
        || value.contains('\\')
        || value[1..]
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err("type path must be an absolute Ghidra category/name path".into());
    }
    Ok(())
}
fn new_path(value: &str) -> Result<(), String> {
    type_path(value)?;
    for part in value[1..].split('/') {
        name(part)?;
    }
    Ok(())
}
fn comment(value: &Option<String>) -> Result<(), String> {
    if value
        .as_ref()
        .is_some_and(|s| s.len() > 4096 || s.contains('\0'))
    {
        return Err("comment must be at most 4096 bytes without NUL".into());
    }
    Ok(())
}
fn identity_address(id: &str, at: &str) -> Result<(), String> {
    identity(id)?;
    address(at)?;
    Ok(())
}
fn page(offset: u32, limit: u32) -> Result<(), String> {
    if offset > 1_000_000 || !(1..=200).contains(&limit) {
        return Err("offset must be <=1000000 and limit 1..200".into());
    }
    Ok(())
}
fn default_limit() -> u32 {
    100
}
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinType {
    U8,
    S8,
    U16,
    S16,
    U32,
    S32,
    U64,
    S64,
    F32,
    F64,
    Void,
}
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypeDescriptor {
    Builtin {
        name: BuiltinType,
    },
    Path {
        path: String,
    },
    Pointer {
        to: Box<TypeDescriptor>,
    },
    Array {
        element: Box<TypeDescriptor>,
        count: u32,
    },
}
impl TypeDescriptor {
    fn check(&self, depth: u8, allow_void: bool) -> Result<(), String> {
        if depth > 4 {
            return Err("type descriptor nesting exceeds 4".into());
        }
        match self {
            Self::Builtin {
                name: BuiltinType::Void,
            } if !allow_void => {
                Err("void is only valid for a return type or pointer target".into())
            }
            Self::Builtin { .. } => Ok(()),
            Self::Path { path } => type_path(path),
            Self::Pointer { to } => to.check(depth + 1, true),
            Self::Array { element, count } => {
                if !(1..=65536).contains(count) {
                    return Err("array count must be 1..65536".into());
                }
                element.check(depth + 1, false)
            }
        }
    }
}
impl Validate for TypeDescriptor {
    fn validate(&self) -> Result<(), String> {
        self.check(0, false)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VariableSelector {
    pub symbol_id: String,
    pub name: String,
    pub storage: String,
}
impl Validate for VariableSelector {
    fn validate(&self) -> Result<(), String> {
        super::hex(&self.symbol_id, "symbol_id")?;
        text(&self.name, "variable name", 1024)?;
        text(&self.storage, "serialized storage", 2048)
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionVariablesParams {
    pub expected_program_id: String,
    pub address: String,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}
impl Validate for FunctionVariablesParams {
    fn validate(&self) -> Result<(), String> {
        identity_address(&self.expected_program_id, &self.address)?;
        page(self.offset, self.limit)
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenameVariableParams {
    pub expected_program_id: String,
    pub address: String,
    pub selector: VariableSelector,
    pub name: String,
}
impl Validate for RenameVariableParams {
    fn validate(&self) -> Result<(), String> {
        identity_address(&self.expected_program_id, &self.address)?;
        self.selector.validate()?;
        name(&self.name)
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetVariableTypeParams {
    pub expected_program_id: String,
    pub address: String,
    pub selector: VariableSelector,
    pub data_type: TypeDescriptor,
}
impl Validate for SetVariableTypeParams {
    fn validate(&self) -> Result<(), String> {
        identity_address(&self.expected_program_id, &self.address)?;
        self.selector.validate()?;
        self.data_type.validate()
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignatureParameter {
    pub name: String,
    pub data_type: TypeDescriptor,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionSignatureParams {
    pub expected_program_id: String,
    pub address: String,
    pub expected_signature: String,
    pub return_type: TypeDescriptor,
    pub parameters: Vec<SignatureParameter>,
    pub calling_convention: String,
    pub varargs: bool,
}
impl Validate for FunctionSignatureParams {
    fn validate(&self) -> Result<(), String> {
        identity_address(&self.expected_program_id, &self.address)?;
        text(&self.expected_signature, "expected_signature", 8192)?;
        self.return_type.check(0, true)?;
        text(&self.calling_convention, "calling_convention", 200)?;
        if self.parameters.len() > 64 {
            return Err("at most 64 parameters are supported".into());
        }
        let mut names = HashSet::new();
        for p in &self.parameters {
            name(&p.name)?;
            p.data_type.validate()?;
            if !names.insert(&p.name) {
                return Err("duplicate parameter name".into());
            }
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListDataTypesParams {
    pub expected_program_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}
impl Validate for ListDataTypesParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        if let Some(q) = &self.query {
            text(q, "query", 1024)?;
        }
        page(self.offset, self.limit)
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetDataTypeParams {
    pub expected_program_id: String,
    pub path: String,
}
impl Validate for GetDataTypeParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        type_path(&self.path)
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructureField {
    pub offset: u32,
    pub name: String,
    pub data_type: TypeDescriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateStructureParams {
    pub expected_program_id: String,
    pub path: String,
    pub size: u32,
    pub fields: Vec<StructureField>,
}
impl Validate for CreateStructureParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        new_path(&self.path)?;
        if !(1..=1_048_576).contains(&self.size) || self.fields.len() > 256 {
            return Err("structure size must be 1..1048576, at most 256 fields".into());
        }
        let mut names = HashSet::new();
        let mut offsets = HashSet::new();
        for f in &self.fields {
            name(&f.name)?;
            f.data_type.validate()?;
            comment(&f.comment)?;
            if f.offset >= self.size || !offsets.insert(f.offset) || !names.insert(&f.name) {
                return Err("field offset/name out of range or duplicated".into());
            }
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetStructureFieldParams {
    pub expected_program_id: String,
    pub path: String,
    pub offset: u32,
    pub expected_name: String,
    pub expected_type_path: String,
    pub name: String,
    pub data_type: TypeDescriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}
impl Validate for SetStructureFieldParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        type_path(&self.path)?;
        name(&self.name)?;
        text(&self.expected_name, "expected_name", 1024)?;
        type_path(&self.expected_type_path)?;
        if self.offset >= 1_048_576 {
            return Err("offset exceeds maximum structure size".into());
        }
        self.data_type.validate()?;
        comment(&self.comment)
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnumMember {
    pub name: String,
    pub value: i64,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateEnumParams {
    pub expected_program_id: String,
    pub path: String,
    pub size: u32,
    pub members: Vec<EnumMember>,
}
impl Validate for CreateEnumParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        new_path(&self.path)?;
        if ![1, 2, 4, 8].contains(&self.size) || self.members.is_empty() || self.members.len() > 256
        {
            return Err("enum needs size 1/2/4/8 and 1..256 members".into());
        }
        let mut names = HashSet::new();
        let negative = self.members.iter().any(|m| m.value < 0);
        for m in &self.members {
            name(&m.name)?;
            if !names.insert(&m.name) {
                return Err("duplicate enum member".into());
            }
            if self.size < 8 {
                let bits = self.size * 8;
                let min = if negative { -(1i64 << (bits - 1)) } else { 0 };
                let max = if negative {
                    (1i64 << (bits - 1)) - 1
                } else {
                    (1i64 << bits) - 1
                };
                if m.value < min || m.value > max {
                    return Err("enum values do not fit consistent signedness and size".into());
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnionField {
    pub name: String,
    pub data_type: TypeDescriptor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateUnionParams {
    pub expected_program_id: String,
    pub path: String,
    pub fields: Vec<UnionField>,
}
impl Validate for CreateUnionParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        new_path(&self.path)?;
        if self.fields.is_empty() || self.fields.len() > 256 {
            return Err("union requires 1..256 fields".into());
        }
        let mut names = HashSet::new();
        for f in &self.fields {
            name(&f.name)?;
            f.data_type.validate()?;
            comment(&f.comment)?;
            if !names.insert(&f.name) {
                return Err("duplicate union member".into());
            }
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateTypedefParams {
    pub expected_program_id: String,
    pub path: String,
    pub data_type: TypeDescriptor,
}
impl Validate for CreateTypedefParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        new_path(&self.path)?;
        self.data_type.validate()
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyDataTypeParams {
    pub expected_program_id: String,
    pub address: String,
    pub data_type: TypeDescriptor,
}
impl Validate for ApplyDataTypeParams {
    fn validate(&self) -> Result<(), String> {
        identity_address(&self.expected_program_id, &self.address)?;
        self.data_type.validate()
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructureFieldReferencesParams {
    pub expected_program_id: String,
    pub address: String,
    pub path: String,
    pub field_offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
}
impl Validate for StructureFieldReferencesParams {
    fn validate(&self) -> Result<(), String> {
        identity_address(&self.expected_program_id, &self.address)?;
        type_path(&self.path)?;
        if self.field_offset >= 1_048_576 {
            return Err("field_offset exceeds maximum structure size".into());
        }
        page(0, self.limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn strict_descriptors_and_guards() {
        assert!(
            serde_json::from_value::<TypeDescriptor>(
                json!({"kind":"builtin","name":"u32","extra":1})
            )
            .is_err()
        );
        let bad: TypeDescriptor = serde_json::from_value(
            json!({"kind":"array","element":{"kind":"builtin","name":"void"},"count":2}),
        )
        .unwrap();
        assert!(bad.validate().is_err());
        let bad:CreateEnumParams=serde_json::from_value(json!({"expected_program_id":"p","path":"/T/E","size":1,"members":[{"name":"Low","value":-1},{"name":"High","value":255}]})).unwrap();
        assert!(bad.validate().is_err());
        assert!(type_path("/Types/../Bad").is_err());
    }
    #[test]
    fn bounded_nesting() {
        let mut value = TypeDescriptor::Builtin {
            name: BuiltinType::U32,
        };
        for _ in 0..5 {
            value = TypeDescriptor::Pointer {
                to: Box::new(value),
            };
        }
        assert!(value.validate().is_err());
    }
}
