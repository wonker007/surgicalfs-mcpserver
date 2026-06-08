use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub security: SecurityConfig,
    #[serde(default)]
    pub search: SearchConfig,
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub response_budget: ResponseBudgetConfig,
    #[serde(default)]
    pub tools: ToolsConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub allowed_directories: Vec<String>,
    #[serde(default)]
    pub follow_symlinks: bool,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchConfig {
    #[serde(default = "default_ripgrep_path")]
    pub ripgrep_path: String,
    #[serde(default = "default_max_results")]
    pub max_results: u32,
    #[serde(default = "default_context_lines")]
    pub default_context_lines: u32,
    #[serde(default = "default_respect_gitignore")]
    pub respect_gitignore: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DefaultsConfig {
    #[serde(default = "default_head_lines")]
    pub head_lines: u32,
    #[serde(default = "default_tail_lines")]
    pub tail_lines: u32,
    #[serde(default = "default_max_read_lines")]
    pub max_read_lines: u32,
    #[serde(default = "default_encoding")]
    pub encoding: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseBudgetConfig {
    #[serde(default = "default_max_response_lines")]
    pub max_response_lines: u32,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: u32,
    #[serde(default = "default_truncation_mode")]
    pub truncation_mode: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ToolsConfig {
    /// Which tool categories to enable. None = all enabled.
    pub enable: Option<Vec<String>>,
}

/// Process runtime / lifecycle settings.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuntimeConfig {
    /// Seconds of no tool activity after which the server self-exits (0 = never).
    ///
    /// Intended for the remote `supergateway` deployment, whose stateless mode
    /// spawns a child per request and cannot reap it (see `src/lifecycle.rs`).
    /// A non-zero value lets each orphaned child reap itself once idle, bounding
    /// the live process count. Leave 0 for local stdio clients (Claude Desktop,
    /// IDEs), where an idle pause is normal and stdin-EOF is the real shutdown.
    #[serde(default)]
    pub idle_timeout_secs: u64,
}

/// All valid tool category names.
pub const ALL_TOOL_CATEGORIES: &[&str] = &[
    "inspect",
    "search",
    "mutate",
    "json",
    "csv",
    "document",
    "spreadsheet",
    "manage",
    "directory",
    "utility",
    "compat",
];

/// Map a tool category name to the tool function names it contains.
pub fn tools_in_category(category: &str) -> &[&str] {
    match category {
        "inspect" => &["file_info", "file_head", "file_tail", "file_read_lines"],
        "search" => &["file_search", "file_grep", "file_search_replace_preview"],
        "mutate" => &[
            "file_replace",
            "file_insert",
            "file_append",
            "file_patch_lines",
            "file_batch_edit",
        ],
        "json" => &["json_query", "json_mutate"],
        "csv" => &["csv_info", "csv_read", "csv_query", "csv_write"],
        "document" => &["pdf_info", "pdf_extract", "docx_extract"],
        "spreadsheet" => &["xlsx_info", "xlsx_read", "xlsx_query"],
        "manage" => &[
            "file_write",
            "file_write_chunked",
            "file_write_stream",
            "file_copy",
            "file_delete",
            "file_move",
        ],
        "directory" => &["directory_list", "directory_tree"],
        "utility" => &["file_checksum"],
        "compat" => &[
            "read_file",
            "read_text_file",
            "read_media_file",
            "read_multiple_files",
            "write_file",
            "edit_file",
            "create_directory",
            "list_directory",
            "list_directory_with_sizes",
            "directory_tree_compat",
            "move_file",
            "search_files",
            "get_file_info",
            "list_allowed_directories",
        ],
        _ => &[],
    }
}

/// Compute the set of enabled tool names from the config.
pub fn enabled_tool_names(config: &ToolsConfig) -> std::collections::HashSet<String> {
    let categories = match &config.enable {
        Some(cats) => cats.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        None => ALL_TOOL_CATEGORIES.to_vec(),
    };
    let mut names = std::collections::HashSet::new();
    for cat in categories {
        for name in tools_in_category(cat) {
            names.insert(name.to_string());
        }
    }
    names
}

/// Names of tools that perform write/mutation operations (for read-only mode).
pub const WRITE_TOOL_NAMES: &[&str] = &[
    "file_replace",
    "file_insert",
    "file_append",
    "file_patch_lines",
    "file_batch_edit",
    "file_write",
    "file_write_chunked",
    "file_write_stream",
    "file_copy",
    "file_delete",
    "file_move",
    "json_mutate",
    "csv_write",
    "write_file",
    "edit_file",
    "create_directory",
    "move_file",
];

// Default value functions
fn default_max_file_size() -> u64 {
    5_242_880
}
fn default_ripgrep_path() -> String {
    "auto".into()
}
fn default_max_results() -> u32 {
    100
}
fn default_context_lines() -> u32 {
    2
}
fn default_respect_gitignore() -> bool {
    true
}
fn default_head_lines() -> u32 {
    50
}
fn default_tail_lines() -> u32 {
    50
}
fn default_max_read_lines() -> u32 {
    500
}
fn default_encoding() -> String {
    "auto".into()
}
fn default_max_response_lines() -> u32 {
    200
}
fn default_max_response_bytes() -> u32 {
    32_768
}
fn default_truncation_mode() -> String {
    "smart".into()
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            ripgrep_path: default_ripgrep_path(),
            max_results: default_max_results(),
            default_context_lines: default_context_lines(),
            respect_gitignore: default_respect_gitignore(),
        }
    }
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            head_lines: default_head_lines(),
            tail_lines: default_tail_lines(),
            max_read_lines: default_max_read_lines(),
            encoding: default_encoding(),
        }
    }
}

impl Default for ResponseBudgetConfig {
    fn default() -> Self {
        Self {
            max_response_lines: default_max_response_lines(),
            max_response_bytes: default_max_response_bytes(),
            truncation_mode: default_truncation_mode(),
        }
    }
}

impl Config {
    /// Load config from a TOML file path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config =
            toml::from_str(&content).with_context(|| "Failed to parse config TOML")?;
        if config.security.allowed_directories.is_empty() {
            anyhow::bail!("Config must specify at least one allowed_directory");
        }
        // Validate tool category names if specified
        if let Some(ref categories) = config.tools.enable {
            if categories.is_empty() {
                anyhow::bail!(
                    "tools.enable cannot be empty (all tools would be disabled). \
                     Remove the 'enable' key to enable all categories."
                );
            }
            for cat in categories {
                if !ALL_TOOL_CATEGORIES.contains(&cat.as_str()) {
                    anyhow::bail!(
                        "Unknown tool category '{}' in tools.enable. Valid categories: {:?}",
                        cat,
                        ALL_TOOL_CATEGORIES
                    );
                }
            }
        }
        Ok(config)
    }

    /// Create a config from positional directory arguments (fallback mode).
    pub fn from_directories(dirs: Vec<String>) -> Result<Self> {
        if dirs.is_empty() {
            anyhow::bail!(
                "No config file or directories specified. Use --config <path> or pass directory paths."
            );
        }
        Ok(Self {
            security: SecurityConfig {
                allowed_directories: dirs,
                follow_symlinks: false,
                max_file_size: default_max_file_size(),
                read_only: false,
            },
            search: SearchConfig::default(),
            defaults: DefaultsConfig::default(),
            response_budget: ResponseBudgetConfig::default(),
            tools: ToolsConfig::default(),
            runtime: RuntimeConfig::default(),
        })
    }

    /// Try to find config in default locations.
    pub fn find_default() -> Option<PathBuf> {
        // Next to executable
        if let Ok(exe) = std::env::current_exe() {
            let beside_exe = exe.parent().map(|p| p.join("surgicalfs.toml"));
            if let Some(p) = beside_exe {
                if p.exists() {
                    return Some(p);
                }
            }
        }
        // %APPDATA%/surgicalfs-mcp/config.toml
        if let Some(config_dir) = dirs::config_dir() {
            let appdata_config = config_dir.join("surgicalfs-mcp").join("config.toml");
            if appdata_config.exists() {
                return Some(appdata_config);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_directories() {
        let config =
            Config::from_directories(vec!["C:\\Users\\Test".into()]).expect("should create config");
        assert_eq!(config.security.allowed_directories.len(), 1);
        assert_eq!(config.defaults.head_lines, 50);
        assert_eq!(config.response_budget.max_response_lines, 200);
    }

    #[test]
    fn test_from_empty_directories_fails() {
        assert!(Config::from_directories(vec![]).is_err());
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
[security]
allowed_directories = ["C:\\Test"]
follow_symlinks = true
max_file_size = 1000000

[search]
max_results = 50

[defaults]
head_lines = 100
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.security.follow_symlinks);
        assert_eq!(config.security.max_file_size, 1_000_000);
        assert_eq!(config.search.max_results, 50);
        assert_eq!(config.defaults.head_lines, 100);
        assert_eq!(config.defaults.tail_lines, 50); // default
        assert_eq!(config.runtime.idle_timeout_secs, 0); // default: idle-reap off
    }

    #[test]
    fn test_runtime_idle_timeout_parses() {
        let toml_str = r#"
[security]
allowed_directories = ["C:\\Test"]

[runtime]
idle_timeout_secs = 30
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.runtime.idle_timeout_secs, 30);
    }
}
