//! Bounded listing, memory, context and annotation operations.
use super::*;

fn limit() -> u32 {
    128
}
fn span(id: &str, at: &str, length: u32, maximum: u32) -> Result<(), String> {
    identity(id)?;
    let (_, offset) = address(at)?;
    range(length, maximum, "length")?;
    offset
        .checked_add(u64::from(length) - 1)
        .ok_or("address range overflow")?;
    Ok(())
}
fn comment(value: &str) -> Result<(), String> {
    if value.chars().count() > 8192 || value.contains('\0') {
        return Err("comment exceeds 8192 characters or contains NUL".into());
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListingParams {
    pub expected_program_id: String,
    pub address: String,
    #[schemars(range(min = 1, max = 65536))]
    pub length: u32,
    #[serde(default = "limit")]
    #[schemars(range(min = 1, max = 256))]
    pub limit: u32,
}
impl Validate for ListingParams {
    fn validate(&self) -> Result<(), String> {
        span(&self.expected_program_id, &self.address, self.length, 65536)?;
        range(self.limit, 256, "limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HashMemoryParams {
    pub expected_program_id: String,
    pub address: String,
    #[schemars(range(min = 1, max = 16777216))]
    pub length: u32,
}
impl Validate for HashMemoryParams {
    fn validate(&self) -> Result<(), String> {
        span(
            &self.expected_program_id,
            &self.address,
            self.length,
            16777216,
        )
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessorContextParams {
    pub expected_program_id: String,
    pub address: String,
    /// Optional exact register name. Otherwise returns a page of language registers.
    pub register: Option<String>,
    #[serde(default)]
    #[schemars(range(max = 65536))]
    pub offset: u32,
    #[serde(default = "limit")]
    #[schemars(range(min = 1, max = 256))]
    pub limit: u32,
}
impl Validate for ProcessorContextParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        if let Some(name) = &self.register {
            text(name, "register", 256)?;
        }
        if self.offset > 65536 {
            return Err("offset exceeds 65536".into());
        }
        range(self.limit, 256, "limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetProcessorContextParams {
    pub expected_program_id: String,
    pub address: String,
    #[schemars(range(min = 1, max = 65536))]
    pub length: u32,
    pub register: String,
    /// Unsigned hexadecimal register value, without 0x; up to 1024 bits.
    pub value: String,
}
impl Validate for SetProcessorContextParams {
    fn validate(&self) -> Result<(), String> {
        span(&self.expected_program_id, &self.address, self.length, 65536)?;
        text(&self.register, "register", 256)?;
        if self.value.is_empty()
            || self.value.len() > 256
            || !self.value.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("value must be 1..256 hexadecimal digits".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ListingKind {
    Data,
    Instruction,
    Any,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClearListingParams {
    pub expected_program_id: String,
    pub address: String,
    #[schemars(range(min = 1, max = 65536))]
    pub length: u32,
    /// Must match each defined unit; functions and partial units are rejected.
    pub expected_kind: ListingKind,
}
impl Validate for ClearListingParams {
    fn validate(&self) -> Result<(), String> {
        span(&self.expected_program_id, &self.address, self.length, 65536)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListBookmarksParams {
    pub expected_program_id: String,
    /// Pagination in native bookmark iteration order; not a count of matching rows.
    #[serde(default)]
    #[schemars(range(max = 2147483647))]
    pub offset: u32,
    #[serde(default = "limit")]
    #[schemars(range(min = 1, max = 256))]
    pub limit: u32,
}
impl Validate for ListBookmarksParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        if self.offset > i32::MAX as u32 {
            return Err("offset exceeds 2147483647".into());
        }
        range(self.limit, 256, "limit")
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetBookmarkParams {
    pub expected_program_id: String,
    pub address: String,
    pub bookmark_type: String,
    pub category: String,
    pub comment: String,
    /// Omit only when the bookmark does not yet exist.
    pub expected_comment: Option<String>,
}
impl Validate for SetBookmarkParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        text(&self.bookmark_type, "bookmark_type", 64)?;
        text(&self.category, "category", 128)?;
        comment(&self.comment)?;
        if let Some(old) = &self.expected_comment {
            comment(old)?;
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteBookmarkParams {
    pub expected_program_id: String,
    pub address: String,
    pub bookmark_type: String,
    pub category: String,
    pub expected_comment: String,
}
impl Validate for DeleteBookmarkParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        text(&self.bookmark_type, "bookmark_type", 64)?;
        text(&self.category, "category", 128)?;
        comment(&self.expected_comment)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StoredCommentType {
    Eol,
    Pre,
    Post,
    Plate,
    Repeatable,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListCommentsParams {
    pub expected_program_id: String,
    pub address: String,
    #[schemars(range(min = 1, max = 16777216))]
    pub length: u32,
    pub comment_type: StoredCommentType,
    pub query: Option<String>,
    #[serde(default = "limit")]
    #[schemars(range(min = 1, max = 128))]
    pub limit: u32,
}
impl Validate for ListCommentsParams {
    fn validate(&self) -> Result<(), String> {
        span(
            &self.expected_program_id,
            &self.address,
            self.length,
            16777216,
        )?;
        if let Some(q) = &self.query {
            text(q, "query", 256)?;
        }
        range(self.limit, 128, "limit")
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommentUpdate {
    pub address: String,
    pub comment_type: StoredCommentType,
    /// Null removes this stored comment.
    pub comment: Option<String>,
    /// Null requires that this comment type is currently absent.
    pub expected_comment: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchCommentsParams {
    pub expected_program_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub updates: Vec<CommentUpdate>,
}
impl Validate for BatchCommentsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        range(self.updates.len() as u32, 64, "updates")?;
        let mut total = 0;
        for u in &self.updates {
            address(&u.address)?;
            for c in [&u.comment, &u.expected_comment].into_iter().flatten() {
                comment(c)?;
                total += c.chars().count();
            }
        }
        if total > 65536 {
            return Err("batch comments exceed 65536 characters".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateFunctionTagsParams {
    pub expected_program_id: String,
    pub address: String,
    #[schemars(length(max = 32))]
    pub add: Vec<String>,
    #[schemars(length(max = 32))]
    pub remove: Vec<String>,
}
impl Validate for UpdateFunctionTagsParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        if self.add.len() > 32
            || self.remove.len() > 32
            || self.add.is_empty() && self.remove.is_empty()
        {
            return Err("provide 1..64 tag changes, at most32 per list".into());
        }
        let mut seen = std::collections::HashSet::new();
        for s in self.add.iter().chain(&self.remove) {
            text(s, "tag", 128)?;
            if !seen.insert(s) {
                return Err("duplicate or contradictory tag changes".into());
            }
        }
        Ok(())
    }
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RenameKind {
    Function,
    Label,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenameUpdate {
    pub kind: RenameKind,
    pub address: String,
    pub name: String,
    /// Current function or primary label name; null creates a label only when no primary label exists.
    pub expected_name: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BatchRenameParams {
    pub expected_program_id: String,
    #[schemars(length(min = 1, max = 64))]
    pub updates: Vec<RenameUpdate>,
}
impl Validate for BatchRenameParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        range(self.updates.len() as u32, 64, "updates")?;
        for u in &self.updates {
            address(&u.address)?;
            text(&u.name, "name", 200)?;
            if let Some(n) = &u.expected_name {
                text(n, "expected_name", 200)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareProgramMemoryParams {
    pub expected_program_id: String,
    pub address: String,
    /// Domain path of a saved program in the current local project.
    pub other_program_path: String,
    /// Imported-source SHA-256 guards the selected saved program; returned region hashes describe actual compared bytes.
    pub expected_other_source_sha256: String,
    pub other_address: String,
    #[schemars(range(min = 1, max = 1048576))]
    pub length: u32,
    #[serde(default = "limit")]
    #[schemars(range(min = 1, max = 256))]
    pub limit: u32,
}
impl Validate for CompareProgramMemoryParams {
    fn validate(&self) -> Result<(), String> {
        span(
            &self.expected_program_id,
            &self.address,
            self.length,
            1048576,
        )?;
        span(
            &self.expected_program_id,
            &self.other_address,
            self.length,
            1048576,
        )?;
        domain_path(&self.other_program_path)?;
        if self.expected_other_source_sha256.len() != 64
            || !self
                .expected_other_source_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err("expected_other_source_sha256 must contain64 hex digits".into());
        }
        range(self.limit, 256, "limit")
    }
}

fn default_comparison_instructions() -> u32 {
    1024
}
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareSavedFunctionParams {
    pub expected_program_id: String,
    pub address: String,
    pub other_program_path: String,
    pub expected_other_source_sha256: String,
    pub other_address: String,
    #[serde(default = "default_comparison_instructions")]
    #[schemars(range(min = 1, max = 4096))]
    pub max_instructions: u32,
}
impl Validate for CompareSavedFunctionParams {
    fn validate(&self) -> Result<(), String> {
        identity(&self.expected_program_id)?;
        address(&self.address)?;
        address(&self.other_address)?;
        domain_path(&self.other_program_path)?;
        if self.expected_other_source_sha256.len() != 64
            || !self
                .expected_other_source_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err("expected_other_source_sha256 must contain64 hex digits".into());
        }
        range(self.max_instructions, 4096, "max_instructions")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn protects_context_ranges_batches_and_snapshot_identity() {
        let p: SetProcessorContextParams=serde_json::from_value(json!({"expected_program_id":"p","address":"ram:ffffffffffffffff","length":2,"register":"TMode","value":"1"})).unwrap();
        assert!(p.validate().is_err());
        let p: BatchCommentsParams =
            serde_json::from_value(json!({"expected_program_id":"p","updates":[]})).unwrap();
        assert!(p.validate().is_err());
        let p: UpdateFunctionTagsParams=serde_json::from_value(json!({"expected_program_id":"p","address":"ram:0","add":["confirmed"],"remove":["confirmed"]})).unwrap();
        assert!(p.validate().is_err());
        let p: CompareProgramMemoryParams=serde_json::from_value(json!({"expected_program_id":"p","address":"ram:0","other_program_path":"/../x","expected_other_source_sha256":"a".repeat(64),"other_address":"ram:0","length":1})).unwrap();
        assert!(p.validate().is_err());
    }
}
