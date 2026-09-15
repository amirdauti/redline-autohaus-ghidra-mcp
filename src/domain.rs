//! Strict typed operation inputs. File offsets and CPU addresses are distinct types of input.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

pub trait Validate {
    fn validate(&self) -> Result<(), String>;
}

pub fn text(value: &str, field: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().count() > max || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{field} must be nonempty, at most {max} characters, and contain no control characters"
        ));
    }
    Ok(())
}

pub fn identity(value: &str) -> Result<(), String> {
    text(value, "identity", 512)
}

pub fn hex(value: &str, field: &str) -> Result<u64, String> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "{field} must contain 1 to 16 hexadecimal digits, optionally prefixed with 0x"
        ));
    }
    u64::from_str_radix(digits, 16).map_err(|_| format!("invalid {field}"))
}

pub fn address(value: &str) -> Result<(&str, u64), String> {
    let (space, offset) = value
        .split_once(':')
        .ok_or("address must include its address space, e.g. ram:00400000")?;
    if space.is_empty()
        || space.len() > 256
        || space
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == ':')
        || offset.starts_with("0x")
    {
        return Err("address must have the form space:hexadecimal_offset".into());
    }
    Ok((space, hex(offset, "address offset")?))
}

pub fn simple_name(value: &str) -> Result<(), String> {
    text(value, "name", 255)?;
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if value == "."
        || value == ".."
        || value.ends_with(['.', ' '])
        || value.chars().any(|c| "/\\:*?\"<>|".contains(c))
        || reserved
    {
        return Err(
            "name must be a simple filename without path separators or reserved names".into(),
        );
    }
    Ok(())
}

fn local_path(value: &str, directory: bool) -> Result<(), String> {
    text(value, "path", 4096)?;
    let path = Path::new(value);
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("path must be absolute and contain no parent traversal".into());
    }
    if directory && !path.is_dir() || !directory && !path.is_file() {
        return Err(if directory {
            "path must be an existing directory"
        } else {
            "path must be an existing file"
        }
        .into());
    }
    Ok(())
}

fn domain_path(value: &str) -> Result<(), String> {
    text(value, "program_path", 4096)?;
    if !value.starts_with('/')
        || value.contains('\\')
        || value[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("program_path must be an absolute Ghidra domain path without traversal".into());
    }
    Ok(())
}

fn range(value: u32, max: u32, name: &str) -> Result<(), String> {
    if !(1..=max).contains(&value) {
        return Err(format!("{name} must be between 1 and {max}"));
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyParams {}
impl Validate for EmptyParams {
    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectLocationParams {
    pub path: String,
    pub name: String,
}
impl Validate for ProjectLocationParams {
    fn validate(&self) -> Result<(), String> {
        local_path(&self.path, true)?;
        simple_name(&self.name)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectParams {
    pub expected_project_id: String,
}
impl Validate for ProjectParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_project_id)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProgramParams {
    pub expected_program_id: String,
}
impl Validate for ProgramParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportProgramParams {
    pub expected_project_id: String,
    /// Absolute path to the raw binary, within a bridge-configured import root.
    pub path: String,
    pub name: String,
    /// Exact language ID returned by ghidra_list_languages.
    pub language_id: String,
    /// Exact compiler ID from the selected language's compiler list.
    pub compiler_spec_id: String,
    /// Hexadecimal CPU image base; distinct from a file offset.
    pub image_base: String,
}
impl Validate for ImportProgramParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_project_id)?;
        local_path(&self.path, false)?;
        simple_name(&self.name)?;
        text(&self.language_id, "language_id", 256)?;
        text(&self.compiler_spec_id, "compiler_spec_id", 256)?;
        hex(&self.image_base, "image_base")?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectProgramParams {
    pub expected_project_id: String,
    pub program_path: String,
}
impl Validate for SelectProgramParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_project_id)?;
        domain_path(&self.program_path)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobParams {
    pub job_id: String,
}
impl Validate for JobParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.job_id)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressParams {
    pub expected_program_id: String,
    pub address: String,
}
impl Validate for AddressParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadBytesParams {
    pub expected_program_id: String,
    /// CPU address with explicit address space, e.g. ram:00400000.
    pub address: String,
    #[schemars(range(min = 1, max = 4096))]
    pub count: u32,
}
impl Validate for ReadBytesParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        let (_, offset) = address(&self.address)?;
        range(self.count, 4096, "count")?;
        offset
            .checked_add(u64::from(self.count) - 1)
            .ok_or("read address range overflow")?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MapFileOffsetParams {
    pub expected_program_id: String,
    /// Offset in the imported source file, never a CPU address.
    #[schemars(range(max = 9223372036854775807_u64))]
    pub file_offset: u64,
}
impl Validate for MapFileOffsetParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        if self.file_offset > i64::MAX as u64 {
            return Err("file_offset exceeds Java's signed file offset range".into());
        }
        Ok(())
    }
}

fn default_function_limit() -> u32 {
    50
}
fn default_search_limit() -> u32 {
    100
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListFunctionsParams {
    pub expected_program_id: String,
    #[serde(default)]
    #[schemars(range(max = 2147483647))]
    pub offset: u32,
    #[serde(default = "default_function_limit")]
    #[schemars(range(min = 1, max = 200))]
    pub limit: u32,
}
impl Validate for ListFunctionsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        if self.offset > i32::MAX as u32 {
            return Err("offset must be at most 2147483647".into());
        }
        range(self.limit, 200, "limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisassembleParams {
    pub expected_program_id: String,
    pub address: String,
    #[schemars(range(min = 1, max = 200))]
    pub count: u32,
}
impl Validate for DisassembleParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        range(self.count, 200, "count")
    }
}

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[default]
    To,
    From,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReferencesParams {
    pub expected_program_id: String,
    pub address: String,
    #[serde(default)]
    pub direction: Direction,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1, max = 500))]
    pub limit: u32,
}
impl Validate for ReferencesParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        range(self.limit, 500, "limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchBytesParams {
    pub expected_program_id: String,
    /// Exact hexadecimal byte pairs, optionally separated by ASCII whitespace; no split nibbles or wildcards.
    pub pattern: String,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1, max = 500))]
    pub limit: u32,
}
impl Validate for SearchBytesParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        if self.pattern.len() > 2048 {
            return Err("pattern text is too long".into());
        }
        let mut digits = 0;
        for token in self.pattern.split_ascii_whitespace() {
            if token.len() % 2 != 0 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("pattern must contain complete hexadecimal byte pairs separated by ASCII whitespace".into());
            }
            digits += token.len();
        }
        if digits == 0 || digits > 512 || digits % 2 != 0 {
            return Err("pattern must contain 1 to 256 complete bytes".into());
        }
        range(self.limit, 500, "limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LabelParams {
    pub expected_program_id: String,
    pub address: String,
    pub name: String,
}
impl Validate for LabelParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        text(&self.name, "name", 1024)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommentParams {
    pub expected_program_id: String,
    pub address: String,
    #[schemars(length(max = 8192))]
    pub comment: String,
}
impl Validate for CommentParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        if self.comment.chars().count() > 8192
            || self
                .comment
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return Err("comment must be at most 8192 characters with no control characters except newlines/tabs".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisOptionsParams {
    pub expected_program_id: String,
    /// Existing Boolean analysis option names and the desired values.
    pub options: std::collections::BTreeMap<String, bool>,
}
impl Validate for AnalysisOptionsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        if self.options.is_empty() || self.options.len() > 200 {
            return Err("options must contain 1 to 200 existing Boolean option names".into());
        }
        for name in self.options.keys() {
            text(name, "option name", 512)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryBlockParams {
    pub expected_program_id: String,
    pub name: String,
    pub address: String,
    #[schemars(range(min = 1, max = 67108864))]
    pub size: u32,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}
impl Validate for MemoryBlockParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        text(&self.name, "name", 255)?;
        let (_, offset) = address(&self.address)?;
        range(self.size, 67108864, "size")?;
        offset
            .checked_add(u64::from(self.size) - 1)
            .ok_or("memory block address range overflow")?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstructionsParams {
    pub expected_program_id: String,
    pub address: String,
    #[schemars(range(min = 1, max = 65536))]
    pub length: u32,
}
impl Validate for InstructionsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        let (_, offset) = address(&self.address)?;
        range(self.length, 65536, "length")?;
        offset
            .checked_add(u64::from(self.length) - 1)
            .ok_or("instruction address range overflow")?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateFunctionParams {
    pub expected_program_id: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
impl Validate for CreateFunctionParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        if let Some(name) = &self.name {
            text(name, "name", 1024)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DataType {
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
}
impl DataType {
    fn size(&self) -> u64 {
        match self {
            Self::U8 | Self::S8 => 1,
            Self::U16 | Self::S16 => 2,
            Self::U32 | Self::S32 | Self::F32 => 4,
            Self::U64 | Self::S64 | Self::F64 => 8,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DefineDataParams {
    pub expected_program_id: String,
    pub address: String,
    pub type_name: DataType,
    #[schemars(range(min = 1, max = 65536))]
    pub count: u32,
}
impl Validate for DefineDataParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        let (_, offset) = address(&self.address)?;
        range(self.count, 65536, "count")?;
        offset
            .checked_add(u64::from(self.count) * self.type_name.size() - 1)
            .ok_or("data address range overflow")?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListSymbolsParams {
    pub expected_program_id: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    #[schemars(range(max = 1000000))]
    pub offset: u32,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1, max = 500))]
    pub limit: u32,
}
impl Validate for ListSymbolsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        if self.offset > 1_000_000 {
            return Err("offset must be at most 1000000".into());
        }
        if !self.query.is_empty() {
            text(&self.query, "query", 1024)?;
        }
        range(self.limit, 500, "limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListStringsParams {
    pub expected_program_id: String,
    #[serde(default)]
    #[schemars(range(max = 1000000))]
    pub offset: u32,
    #[serde(default = "default_search_limit")]
    #[schemars(range(min = 1, max = 500))]
    pub limit: u32,
}
impl Validate for ListStringsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        if self.offset > 1_000_000 {
            return Err("offset must be at most 1000000".into());
        }
        range(self.limit, 500, "limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportProgramParams {
    pub expected_program_id: String,
    pub path: String,
}
impl Validate for ExportProgramParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        text(&self.path, "path", 4096)?;
        let path = Path::new(&self.path);
        if !path.is_absolute()
            || path.components().any(|c| matches!(c, Component::ParentDir))
            || path.extension().and_then(|x| x.to_str()) != Some("gzf")
        {
            return Err(
                "export path must be absolute, end in .gzf, and contain no parent traversal".into(),
            );
        }
        if path.try_exists().map_err(|e| e.to_string())? {
            return Err("export path already exists; overwrite is forbidden".into());
        }
        if !path.parent().is_some_and(Path::is_dir) {
            return Err("export parent directory must exist".into());
        }
        simple_name(
            path.file_name()
                .and_then(|x| x.to_str())
                .ok_or("invalid export filename")?,
        )
    }
}
