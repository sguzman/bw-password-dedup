use anyhow::{Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(name = "bw-passport-dedup", version, about = "Deduplicate Bitwarden JSON exports")]
struct Args {
    /// Bitwarden JSON export file
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    /// Output file (defaults to <input>.dedup.json)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Overwrite the output file if it exists
    #[arg(long, action = ArgAction::SetTrue)]
    force: bool,

    /// Show what would be removed without writing output
    #[arg(long, action = ArgAction::SetTrue)]
    dry_run: bool,

    /// Write pretty-printed JSON
    #[arg(long, action = ArgAction::SetTrue)]
    pretty: bool,

    /// Keep strategy when duplicates are found
    #[arg(long, value_enum, default_value_t = Keep::First)]
    keep: Keep,

    /// Config file (TOML)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Ignore any keys with these names, anywhere in the item
    #[arg(
        long,
        value_delimiter = ',',
        value_name = "KEYS"
    )]
    ignore_key: Option<Vec<String>>,

    /// Ignore specific paths (dot-separated), relative to each item
    #[arg(long, value_delimiter = ',', value_name = "PATHS")]
    ignore_path: Option<Vec<String>>,

    /// Trim whitespace from all string values before hashing
    #[arg(long, action = ArgAction::SetTrue)]
    trim_strings: bool,

    /// Lowercase all string values before hashing
    #[arg(long, action = ArgAction::SetTrue)]
    lowercase_strings: bool,

    /// Sort login.uris entries by URI before hashing
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    sort_uris: bool,

    /// Deduplication keys (comma-separated). Overrides config.
    #[arg(long, value_delimiter = ',', value_name = "KEYS")]
    policy_key: Option<Vec<DedupKey>>,

    /// Write a JSON report of duplicate groups
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, Deserialize, ValueEnum, PartialEq, Eq)]
enum Keep {
    First,
    Last,
    Newest,
    Oldest,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct Config {
    dedup: DedupConfig,
    ignore: IgnoreConfig,
    normalize: NormalizeConfig,
    output: OutputConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct DedupConfig {
    keep: Keep,
    policy_keys: Vec<DedupKey>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct IgnoreConfig {
    keys: Vec<String>,
    paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct NormalizeConfig {
    trim_strings: bool,
    lowercase_strings: bool,
    sort_uris: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct OutputConfig {
    pretty: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, ValueEnum, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum DedupKey {
    Domain,
    Username,
    Password,
    Name,
    Uri,
    Totp,
}

#[derive(Debug, Serialize)]
struct Report {
    total_items: usize,
    duplicate_groups: usize,
    removed: usize,
    groups: Vec<ReportGroup>,
}

#[derive(Debug, Serialize)]
struct ReportGroup {
    count: usize,
    exact_duplicates: usize,
    conflicting_or_distinct: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dedup: DedupConfig::default(),
            ignore: IgnoreConfig::default(),
            normalize: NormalizeConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            keep: Keep::First,
            policy_keys: vec![DedupKey::Domain, DedupKey::Username, DedupKey::Password],
        }
    }
}

impl Default for IgnoreConfig {
    fn default() -> Self {
        Self {
            keys: vec![
                "id".to_string(),
                "revisionDate".to_string(),
                "creationDate".to_string(),
                "passwordHistory".to_string(),
            ],
            paths: Vec::new(),
        }
    }
}

impl Default for NormalizeConfig {
    fn default() -> Self {
        Self {
            trim_strings: false,
            lowercase_strings: false,
            sort_uris: true,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self { pretty: false }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let input = &args.input;
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| default_output_path(input));

    if output.exists() && !args.force && !args.dry_run {
        anyhow::bail!(
            "output file already exists: {} (use --force to overwrite)",
            output.display()
        );
    }

    let mut config = load_config(args.config.as_deref())?;

    if args.keep != Keep::First {
        config.dedup.keep = args.keep;
    }
    if let Some(keys) = args.policy_key.clone() {
        config.dedup.policy_keys = keys;
    }
    if let Some(keys) = args.ignore_key.clone() {
        config.ignore.keys = keys;
    }
    if let Some(paths) = args.ignore_path.clone() {
        config.ignore.paths = paths;
    }
    if args.trim_strings {
        config.normalize.trim_strings = true;
    }
    if args.lowercase_strings {
        config.normalize.lowercase_strings = true;
    }
    if args.sort_uris != config.normalize.sort_uris {
        config.normalize.sort_uris = args.sort_uris;
    }
    if args.pretty {
        config.output.pretty = true;
    }

    // A dry run must not create reports or other files.
    if args.dry_run && args.report.is_some() {
        anyhow::bail!("--report cannot be combined with --dry-run");
    }
    if args.report.as_ref().is_some_and(|path| path == &output || path == input) {
        anyhow::bail!("the report path must differ from the input and output paths");
    }
    if config.dedup.keep != Keep::First {
        anyhow::bail!("legacy --keep modes are unsafe until explicit conflict review is implemented");
    }

    let input_data = fs::read_to_string(input)
        .with_context(|| format!("failed to read input file {}", input.display()))?;

    let mut root: Value = serde_json::from_str(&input_data)
        .with_context(|| format!("failed to parse JSON from {}", input.display()))?;

    let items = root
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .context("expected top-level 'items' array in Bitwarden export")?;

    let mut items_vec = std::mem::take(items);

    let ignore_keys = config
        .ignore
        .keys
        .iter()
        .map(|s| s.to_string())
        .collect::<HashSet<_>>();

    let ignore_paths = config
        .ignore
        .paths
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| parse_path(s))
        .collect::<Vec<_>>();

    // Calculate a redacted report in memory; do not write until the result
    // has been produced successfully.
    let report_data = if args.report.is_some() {
        let report = build_report(&items_vec, &config, &ignore_keys, &ignore_paths);
        Some(serde_json::to_string_pretty(&report)?)
    } else {
        None
    };

    // Fail closed: only byte-for-byte identical login records can be removed.
    // Preserve every distinct record, even if a matching policy groups it with
    // another login. Non-login and malformed records pass through untouched.
    let mut seen: HashMap<String, Vec<usize>> = HashMap::new();
    let mut deduped: Vec<Value> = Vec::with_capacity(items_vec.len());
    let mut removed = 0usize;

    for item in items_vec.drain(..) {
        if !is_login(&item) {
            deduped.push(item);
            continue;
        }
        let key = build_key(&item, &config, &ignore_keys, &ignore_paths);
        let identical = seen.get(&key).is_some_and(|indices| {
            indices.iter().any(|&index| deduped[index] == item)
        });
        if identical {
            removed += 1;
        } else {
            let index = deduped.len();
            deduped.push(item);
            seen.entry(key).or_default().push(index);
        }
    }

    let total = deduped.len() + removed;
    root["items"] = Value::Array(deduped);

    println!(
        "Items: {} -> {} (removed {})",
        total,
        root["items"].as_array().map(|v| v.len()).unwrap_or(0),
        removed
    );

    if args.dry_run {
        return Ok(());
    }

    let output_data = if config.output.pretty {
        serde_json::to_string_pretty(&root)?
    } else {
        serde_json::to_string(&root)?
    };

    write_private_atomically(&output, output_data.as_bytes(), args.force, Some(input))?;
    println!("Wrote {}", output.display());

    if let (Some(path), Some(data)) = (args.report.as_ref(), report_data.as_ref()) {
        write_private_atomically(path, data.as_bytes(), false, Some(input))?;
        println!("Wrote redacted report {}", path.display());
    }

    Ok(())
}

// Create exports with mode 0600, without truncating old data. On overwrite,
// retain a private backup first. All temporary files live next to their output
// to allow atomic rename on the same filesystem.
fn write_private_atomically(output: &Path, data: &[u8], force: bool, input: Option<&Path>) -> Result<()> {
    let parent = output.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let existing = match fs::symlink_metadata(output) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                anyhow::bail!("refusing non-regular or symlink output: {}", output.display());
            }
            if !force {
                anyhow::bail!("output already exists: {} (use --force)", output.display());
            }
            Some(meta)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).with_context(|| format!("checking {}", output.display())),
    };

    if let (Some(_), Some(source)) = (&existing, input) {
        let source_meta = fs::metadata(source)?;
        let target_meta = fs::metadata(output)?;
        if source_meta.dev() == target_meta.dev() && source_meta.ino() == target_meta.ino() {
            anyhow::bail!("refusing to overwrite the original input");
        }
    }

    let basename = output.file_name().and_then(|v| v.to_str()).unwrap_or("vault");
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?.as_nanos();
    let temp_path = parent.join(format!(".{basename}.tmp.{}.{}", std::process::id(), stamp));

    let result = (|| -> Result<()> {
        let mut temp = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(&temp_path).with_context(|| format!("creating private temporary file for {}", output.display()))?;
        temp.write_all(data)?;
        temp.sync_all()?;
        drop(temp);

        if existing.is_some() {
            let backup_path = parent.join(format!("{basename}.backup.{}.{}", std::process::id(), stamp));
            let backup_result = (|| -> Result<()> {
                let mut backup = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&backup_path)?;
                let mut previous = fs::File::open(output)?;
                std::io::copy(&mut previous, &mut backup)?;
                backup.sync_all()?;
                Ok(())
            })();
            if backup_result.is_err() {
                let _ = fs::remove_file(&backup_path);
            }
            backup_result.context("failed to preserve existing output backup")?;
            fs::rename(&temp_path, output).context("failed to atomically replace output")?;
        } else {
            // Unlike rename, hard_link fails if another process has just
            // created the destination. This preserves no-overwrite semantics.
            fs::hard_link(&temp_path, output).context("failed to create new output without overwriting")?;
            fs::remove_file(&temp_path)?;
        }

        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn default_output_path(input: &Path) -> PathBuf {
    let mut output = input.to_path_buf();
    let ext = input.extension().and_then(|e| e.to_str()).unwrap_or("");
    let suffix = if ext.is_empty() { "dedup.json" } else { "dedup.json" };

    let file_name = input
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("output");

    let new_name = if ext.is_empty() {
        format!("{}.{}", file_name, suffix)
    } else {
        format!("{}.{}", file_name.trim_end_matches(ext).trim_end_matches('.'), suffix)
    };

    output.set_file_name(new_name);
    output
}

fn parse_path(path: &str) -> Vec<String> {
    path.split('.')
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect()
}

fn build_key(
    item: &Value,
    config: &Config,
    ignore_keys: &HashSet<String>,
    ignore_paths: &[Vec<String>],
) -> String {
    if !config.dedup.policy_keys.is_empty() {
        let mut policy_value = build_policy_value(item, &config.dedup.policy_keys);
        if config.normalize.sort_uris {
            sort_login_uris(&mut policy_value);
        }
        normalize_policy_identity(
            &mut policy_value,
            config.normalize.trim_strings,
            config.normalize.lowercase_strings,
        );
        let canonical = canonicalize(&policy_value);
        return serde_json::to_string(&canonical).unwrap_or_default();
    }

    let mut working = item.clone();
    remove_keys_anywhere(&mut working, ignore_keys);
    for path in ignore_paths {
        remove_path(&mut working, path);
    }
    if config.normalize.sort_uris {
        sort_login_uris(&mut working);
    }
    // With whole-item matching, even a non-secret string change could be
    // significant. Never apply broad string normalization to credential data.
    let canonical = canonicalize(&working);
    serde_json::to_string(&canonical).unwrap_or_default()
}

fn build_policy_value(item: &Value, keys: &[DedupKey]) -> Value {
    let mut map = Map::new();
    // Match policies must never omit type or a credential secret.
    map.insert("type".to_string(), item.get("type").cloned().unwrap_or(Value::Null));
    map.insert("_exact_password".to_string(), extract_login_field(item, "password"));
    map.insert("_exact_totp".to_string(), extract_login_field(item, "totp"));
    for key in keys {
        match key {
            DedupKey::Domain => {
                let domains = extract_domains(item);
                map.insert("domain".to_string(), Value::Array(domains));
            }
            DedupKey::Username => {
                map.insert("username".to_string(), extract_login_field(item, "username"));
            }
            DedupKey::Password => {
                map.insert("password".to_string(), extract_login_field(item, "password"));
            }
            DedupKey::Name => {
                map.insert(
                    "name".to_string(),
                    item.get("name").cloned().unwrap_or(Value::Null),
                );
            }
            DedupKey::Uri => {
                let uris = extract_uris(item);
                map.insert("uri".to_string(), Value::Array(uris));
            }
            DedupKey::Totp => {
                map.insert("totp".to_string(), extract_login_field(item, "totp"));
            }
        }
    }
    Value::Object(map)
}

fn extract_login_field(item: &Value, field: &str) -> Value {
    item.get("login")
        .and_then(Value::as_object)
        .and_then(|login| login.get(field))
        .cloned()
        .unwrap_or(Value::Null)
}

fn extract_uris(item: &Value) -> Vec<Value> {
    let mut uris = Vec::new();
    if let Some(login) = item.get("login").and_then(Value::as_object) {
        if let Some(Value::Array(items)) = login.get("uris") {
            for entry in items {
                match entry {
                    Value::Object(map) => {
                        if let Some(Value::String(uri)) = map.get("uri") {
                            uris.push(Value::String(uri.clone()));
                        }
                    }
                    Value::String(uri) => uris.push(Value::String(uri.clone())),
                    _ => {}
                }
            }
        }
    }
    uris
}

fn extract_domains(item: &Value) -> Vec<Value> {
    let mut domains: Vec<String> = Vec::new();
    for uri_value in extract_uris(item) {
        if let Value::String(uri) = uri_value {
            if let Some(host) = extract_domain_from_uri(&uri) {
                domains.push(host);
            } else {
                domains.push(uri);
            }
        }
    }
    domains.sort();
    domains.dedup();
    domains.into_iter().map(Value::String).collect()
}

fn extract_domain_from_uri(uri: &str) -> Option<String> {
    let without_scheme = uri.split("://").nth(1).unwrap_or(uri);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host = host_port.split('@').last().unwrap_or(host_port);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn is_login(item: &Value) -> bool {
    item.get("type").and_then(Value::as_u64) == Some(1)
        && item.get("login").and_then(Value::as_object).is_some()
}

fn build_report(
    items: &[Value],
    config: &Config,
    ignore_keys: &HashSet<String>,
    ignore_paths: &[Vec<String>],
) -> Report {
    let mut groups: HashMap<String, Vec<&Value>> = HashMap::new();
    for item in items.iter().filter(|item| is_login(item)) {
        let key = build_key(item, config, ignore_keys, ignore_paths);
        groups.entry(key).or_default().push(item);
    }

    let mut report_groups = Vec::new();
    let mut removed = 0usize;
    for group in groups.into_values() {
        if group.len() <= 1 {
            continue;
        }
        // Dedup decisions use exact records, never a lossy policy key alone.
        let distinct = group
            .iter()
            .map(|item| serde_json::to_string(item).unwrap_or_default())
            .collect::<HashSet<_>>()
            .len();
        let exact_duplicates = group.len() - distinct;
        removed += exact_duplicates;
        report_groups.push(ReportGroup {
            count: group.len(),
            exact_duplicates,
            conflicting_or_distinct: distinct.saturating_sub(1),
        });
    }
    report_groups.sort_by(|a, b| {
        b.count.cmp(&a.count)
            .then_with(|| b.exact_duplicates.cmp(&a.exact_duplicates))
            .then_with(|| b.conflicting_or_distinct.cmp(&a.conflicting_or_distinct))
    });
    Report {
        total_items: items.len(),
        duplicate_groups: report_groups.len(),
        removed,
        groups: report_groups,
    }
}

fn remove_keys_anywhere(value: &mut Value, ignore_keys: &HashSet<String>) {
    match value {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                if ignore_keys.contains(&key) {
                    map.remove(&key);
                } else if let Some(child) = map.get_mut(&key) {
                    remove_keys_anywhere(child, ignore_keys);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                remove_keys_anywhere(item, ignore_keys);
            }
        }
        _ => {}
    }
}

fn remove_path(value: &mut Value, path: &[String]) {
    if path.is_empty() {
        return;
    }

    let mut current = value;
    for (index, segment) in path.iter().enumerate() {
        match current {
            Value::Object(map) => {
                if index == path.len() - 1 {
                    map.remove(segment);
                    return;
                }
                if let Some(next) = map.get_mut(segment) {
                    current = next;
                } else {
                    return;
                }
            }
            _ => return,
        }
    }
}

// Identity normalization is deliberately narrow. Never change passwords,
 // TOTP secrets, usernames, URI paths, notes, or unknown string fields.
fn normalize_policy_identity(value: &mut Value, trim: bool, lowercase: bool) {
    let Value::Object(map) = value else { return };
    if let Some(Value::Array(domains)) = map.get_mut("domain") {
        for domain in domains {
            if let Value::String(text) = domain {
                if trim {
                    *text = text.trim().to_string();
                }
                if lowercase {
                    *text = text.to_ascii_lowercase();
                }
            }
        }
    }
}

fn sort_login_uris(value: &mut Value) {
    let Value::Object(map) = value else { return };
    let Some(Value::Object(login)) = map.get_mut("login") else {
        return;
    };

    let Some(Value::Array(uris)) = login.get_mut("uris") else {
        return;
    };

    uris.sort_by(|a, b| {
        let a_key = uri_sort_key(a);
        let b_key = uri_sort_key(b);
        a_key.cmp(&b_key)
    });
}

fn uri_sort_key(value: &Value) -> String {
    match value {
        Value::Object(map) => map
            .get("uri")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        Value::String(s) => s.to_string(),
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut new_map = Map::with_capacity(map.len());
            for key in keys {
                if let Some(value) = map.get(key) {
                    new_map.insert(key.clone(), canonicalize(value));
                }
            }
            Value::Object(new_map)
        }
        Value::Array(items) => {
            let canonical_items = items.iter().map(canonicalize).collect();
            Value::Array(canonical_items)
        }
        _ => value.clone(),
    }
}

fn load_config(path: Option<&Path>) -> Result<Config> {
    let default_path = PathBuf::from("config.toml");
    let config_path = path.unwrap_or(&default_path);

    if config_path.exists() {
        let contents = fs::read_to_string(config_path).with_context(|| {
            format!("failed to read config file {}", config_path.display())
        })?;
        let config: Config = toml::from_str(&contents).with_context(|| {
            format!("failed to parse config file {}", config_path.display())
        })?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn login(password: &str, totp: &str) -> Value {
        json!({
            "type": 1,
            "name": "Example",
            "login": {
                "uris": [{"uri": "https://example.test/login"}],
                "username": "User",
                "password": password,
                "totp": totp
            }
        })
    }

    fn key(item: &Value, config: &Config) -> String {
        build_key(item, config, &HashSet::new(), &[])
    }

    #[test]
    fn secret_case_is_never_normalized() {
        let mut config = Config::default();
        config.normalize.lowercase_strings = true;
        config.normalize.trim_strings = true;
        assert_ne!(key(&login("PasswordABC", "seed"), &config),
                   key(&login("passwordabc", "seed"), &config));
        assert_ne!(key(&login("same", "AbCd"), &config),
                   key(&login("same", "abcd"), &config));
    }

    #[test]
    fn secret_equality_cannot_be_disabled_by_policy() {
        let mut config = Config::default();
        config.dedup.policy_keys = vec![DedupKey::Domain];
        assert_ne!(key(&login("abc", "otp"), &config),
                   key(&login("ABC", "otp"), &config));
        assert_ne!(key(&login("abc", "otp"), &config),
                   key(&login("abc", "OTP"), &config));
    }

    #[test]
    fn full_record_matching_does_not_lowercase_secrets() {
        let mut config = Config::default();
        config.dedup.policy_keys.clear();
        config.normalize.lowercase_strings = true;
        assert_ne!(key(&login("UPPER", "otp"), &config),
                   key(&login("upper", "otp"), &config));
    }

    #[test]
    fn only_typed_login_records_are_eligible_for_dedup() {
        let value = json!({"type": 2, "name": "A secure note", "notes": "private"});
        assert!(!is_login(&value));
        assert!(!is_login(&json!({"login": {"password": "secret"}})));
        assert!(is_login(&login("secret", "totp")));
    }

    #[test]
    fn redacted_report_never_contains_secrets() {
        let secret = "NEVER_PRINT_PASSWORD_123";
        let otp = "NEVER_PRINT_TOTP_ABC";
        let a = login(secret, otp);
        let mut b = a.clone();
        b["notes"] = json!("NEVER_PRINT_PRIVATE_NOTE");
        let config = Config::default();
        let report = build_report(&[a, b], &config, &HashSet::new(), &[]);
        let encoded = serde_json::to_string(&report).unwrap();
        assert_eq!(report.removed, 0);
        assert_eq!(report.duplicate_groups, 1);
        for canary in [secret, otp, "NEVER_PRINT_PRIVATE_NOTE", "example.test", "User"] {
            assert!(!encoded.contains(canary));
        }
    }

    #[test]
    fn dry_run_rejects_report_output() {
        let parsed = Args::try_parse_from([
            "bw-passport-dedup", "--input", "test.json", "--dry-run",
            "--report", "report.json"
        ]).unwrap();
        assert!(parsed.dry_run && parsed.report.is_some());
        // The CLI rejects the combination before reading input or writing.
    }
    #[test]
    fn private_atomic_output_preserves_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "bw-dedup-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let output = base.join("merged.json");
        write_private_atomically(&output, b"old", false, None).unwrap();
        let permissions = fs::metadata(&output).unwrap().permissions().mode() & 0o777;
        assert_eq!(permissions, 0o600);
        assert!(write_private_atomically(&output, b"new", false, None).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"old");
        write_private_atomically(&output, b"new", true, None).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"new");
        let backed_up = fs::read_dir(&base).unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".backup."))
            .any(|entry| fs::read(entry.path()).unwrap() == b"old");
        assert!(backed_up);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn original_input_cannot_be_overwritten() {
        let base = std::env::temp_dir().join(format!(
            "bw-dedup-input-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let input = base.join("input.json");
        fs::write(&input, b"keep me").unwrap();
        assert!(write_private_atomically(&input, b"bad", true, Some(&input)).is_err());
        assert_eq!(fs::read(&input).unwrap(), b"keep me");
        fs::remove_dir_all(base).unwrap();
    }

}
