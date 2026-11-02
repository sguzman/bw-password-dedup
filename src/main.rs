mod import;
mod merge;
mod model;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use import::{SourceKind, import_csv, parse_source_spec};
use merge::{AccountGroupSummary, Reconciliation, analyze_accounts, exact_dedup_tracked, merge_uris_tracked, reconcile};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(
    name = "bw-passport-dedup",
    version,
    about = "Deduplicate Bitwarden JSON exports"
)]
struct Args {
    /// Optional Bitwarden/Vaultwarden JSON export
    #[arg(short, long, value_name = "FILE")]
    input: Option<PathBuf>,

    /// Additional browser export; repeat KIND=FILE (edge, chrome, firefox, apple)
    #[arg(long, value_name = "KIND=FILE", action = ArgAction::Append)]
    source: Vec<String>,

    /// Output file (defaults to <input>.dedup.json or consolidated.json)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Overwrite the output file if it exists
    #[arg(long, action = ArgAction::SetTrue)]
    force: bool,

    /// Show what would be removed without writing output
    #[arg(long, action = ArgAction::SetTrue)]
    dry_run: bool,

    /// Merge only URI variants with otherwise entirely identical records
    #[arg(long, action = ArgAction::SetTrue)]
    merge_compatible_uris: bool,

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
    #[arg(long, value_delimiter = ',', value_name = "KEYS")]
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

#[derive(Clone, Debug, Deserialize, Default)]
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

#[derive(Clone, Debug, Deserialize, Default)]
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
    account_groups: Vec<AccountGroupSummary>,
    compatible_uri_merges: usize,
    reconciliation: Option<Reconciliation>,
    unavailable_data_notice: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct ReportGroup {
    count: usize,
    exact_duplicates: usize,
    conflicting_or_distinct: usize,
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

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_INPUT_ITEMS: usize = 100_000;

fn inspect_regular_input(input: &Path) -> Result<()> {
    let meta =
        fs::metadata(input).with_context(|| format!("checking input {}", input.display()))?;
    if !meta.is_file() {
        anyhow::bail!("input must be a regular file: {}", input.display());
    }
    if meta.len() > MAX_INPUT_BYTES {
        anyhow::bail!("input exceeds the 64 MiB limit");
    }
    Ok(())
}

// Resolve file-name aliases before any export is written. Check existing files
// by inode as well, so hardlink aliases are handled conservatively.
fn same_destination(a: &Path, b: &Path) -> Result<bool> {
    let parent_a = fs::canonicalize(
        a.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )?;
    let parent_b = fs::canonicalize(
        b.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )?;
    if parent_a == parent_b && a.file_name() == b.file_name() {
        return Ok(true);
    }
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(meta_a), Ok(meta_b)) => {
            Ok(meta_a.dev() == meta_b.dev() && meta_a.ino() == meta_b.ino())
        }
        _ => Ok(false),
    }
}

fn validate_destination(output: &Path, input: &Path, force: bool) -> Result<()> {
    if same_destination(output, input)? {
        anyhow::bail!("refusing to write to original input");
    }
    match fs::symlink_metadata(output) {
        Ok(meta) => {
            if !meta.file_type().is_file() {
                anyhow::bail!(
                    "output must not be a symlink or non-regular file: {}",
                    output.display()
                );
            }
            if !force {
                anyhow::bail!(
                    "output exists: {} (use --force for a private backed-up replacement)",
                    output.display()
                );
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("checking output {}", output.display()));
        }
    }
    Ok(())
}

fn read_bounded_json(input: &Path) -> Result<Value> {
    inspect_regular_input(input)?;
    let file = fs::File::open(input)?;
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        anyhow::bail!("input exceeds the 64 MiB limit");
    }
    let root: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid JSON in {}", input.display()))?;
    validate_bitwarden_root(&root)?;
    Ok(root)
}

fn validate_bitwarden_root(root: &Value) -> Result<()> {
    if root
        .get("encrypted")
        .is_some_and(|flag| flag != &Value::Bool(false))
    {
        anyhow::bail!(
            "encrypted Bitwarden JSON exports are unsupported; use a plaintext export in private local storage"
        );
    }
    if root
        .get("folders")
        .is_some_and(|folders| !folders.is_array())
    {
        anyhow::bail!("Bitwarden export has a malformed folders collection");
    }
    let items = root
        .get("items")
        .and_then(Value::as_array)
        .context("expected a top-level items array in Bitwarden JSON")?;
    if items.len() > MAX_INPUT_ITEMS {
        anyhow::bail!("input exceeds the 100,000 item limit");
    }
    for item in items {
        let kind = item
            .get("type")
            .and_then(Value::as_u64)
            .context("Bitwarden item missing numeric type")?;
        if kind == 1 && !item.get("login").is_some_and(Value::is_object) {
            anyhow::bail!("Bitwarden login item has malformed login data");
        }
        // Unknown numeric types survive unchanged and cannot be deduplicated.
    }
    Ok(())
}

fn validate_run(args: &Args, config: &Config, output: &Path) -> Result<Vec<(SourceKind, PathBuf)>> {
    let sources = args
        .source
        .iter()
        .map(|spec| parse_source_spec(spec))
        .collect::<Result<Vec<_>>>()?;
    if args.input.is_none() && sources.is_empty() {
        anyhow::bail!("at least one --input or --source KIND=FILE is required");
    }
    if args.dry_run && args.report.is_some() {
        anyhow::bail!("--report cannot be combined with --dry-run");
    }
    if config.dedup.keep != Keep::First {
        anyhow::bail!(
            "legacy --keep modes are unsafe until explicit conflict review is implemented"
        );
    }

    let mut originals: Vec<&Path> = Vec::new();
    if let Some(input) = &args.input {
        originals.push(input.as_path());
    }
    for (_, path) in &sources {
        originals.push(path.as_path());
    }
    for (idx, first) in originals.iter().enumerate() {
        for second in originals.iter().skip(idx + 1) {
            if same_destination(first, second)? {
                anyhow::bail!("duplicate source file supplied; each input must be distinct");
            }
        }
    }
    if let Some(report) = &args.report
        && (same_destination(report, output)?
            || originals
                .iter()
                .any(|original| same_destination(report, original).unwrap_or(true)))
    {
        anyhow::bail!("the report path must differ from all inputs and the output");
    }

    // Preflight all destination/source combinations before reading any secrets.
    if !args.dry_run {
        for original in &originals {
            validate_destination(output, original, args.force)?;
            if let Some(report) = &args.report {
                validate_destination(report, original, false)?;
            }
        }
    }
    Ok(sources)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let output = args.output.clone().unwrap_or_else(|| {
        args.input
            .as_ref()
            .map(|p| default_output_path(p))
            .unwrap_or_else(|| PathBuf::from("consolidated.json"))
    });

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

    let sources = validate_run(&args, &config, &output)?;

    let mut root = if let Some(input) = &args.input {
        read_bounded_json(input)?
    } else {
        json!({"encrypted": false, "folders": [], "items": []})
    };

    let items = root
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .context("expected top-level 'items' array in Bitwarden export")?;

    let mut items_vec = std::mem::take(items);
    for (kind, path) in sources {
        let incoming = import_csv(kind, &path)?;
        if items_vec.len() + incoming.len() > MAX_INPUT_ITEMS {
            anyhow::bail!("combined sources exceed the 100,000 item limit");
        }
        items_vec.extend(incoming);
    }

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

    // The original items stay intact in memory for a private, position-based
    // reconciliation. No record is allowed to vanish without an audit trail.
    let originals = items_vec.clone();
    let mut report = if args.report.is_some() {
        Some(build_report(&items_vec, &config, &ignore_keys, &ignore_paths))
    } else {
        None
    };

    let (tracked, removed) = exact_dedup_tracked(
        items_vec, &config, &ignore_keys, &ignore_paths
    );
    let (tracked, uri_merged) = if args.merge_compatible_uris {
        merge_uris_tracked(tracked)
    } else {
        (tracked, 0)
    };
    let reconciliation = reconcile(
        &tracked, originals.len(), removed, uri_merged, &originals
    )?;
    let total = originals.len();
    if let Some(ref mut report) = report {
        report.compatible_uri_merges = uri_merged;
        report.reconciliation = Some(reconciliation);
    }
    let report_data = report.as_ref()
        .map(serde_json::to_string_pretty).transpose()?;
    root["items"] = Value::Array(
        tracked.into_iter().map(|record| record.value).collect()
    );

    println!(
        "Items: {} -> {} (exact duplicates {}, compatible URI merges {})",
        total,
        root["items"].as_array().map(|v| v.len()).unwrap_or(0),
        removed,
        uri_merged
    );
    eprintln!(
        "Notice: exports may omit passkeys, attachments, external authenticator codes, and later browser changes; verify separately."
    );

    if args.dry_run {
        return Ok(());
    }

    let output_data = if config.output.pretty {
        serde_json::to_string_pretty(&root)?
    } else {
        serde_json::to_string(&root)?
    };

    write_private_atomically(
        &output,
        output_data.as_bytes(),
        args.force,
        args.input.as_deref(),
    )?;
    println!("Wrote {}", output.display());

    if let (Some(path), Some(data)) = (args.report.as_ref(), report_data.as_ref()) {
        write_private_atomically(path, data.as_bytes(), false, args.input.as_deref())?;
        println!("Wrote redacted report {}", path.display());
    }

    Ok(())
}

// Create exports with mode 0600, without truncating old data. On overwrite,
// retain a private backup first. All temporary files live next to their output
// to allow atomic rename on the same filesystem.
fn write_private_atomically(
    output: &Path,
    data: &[u8],
    force: bool,
    input: Option<&Path>,
) -> Result<()> {
    write_private_atomically_inner(output, data, force, input, false)
}

// The injection flag is never exposed to CLI users. It lets tests exercise
// the exact failure point between durable staging and replacement.
fn write_private_atomically_inner(
    output: &Path,
    data: &[u8],
    force: bool,
    input: Option<&Path>,
    simulate_interruption: bool,
) -> Result<()> {
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let existing = match fs::symlink_metadata(output) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                anyhow::bail!(
                    "refusing non-regular or symlink output: {}",
                    output.display()
                );
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

    let basename = output
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("vault");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_nanos();
    let temp_path = parent.join(format!(".{basename}.tmp.{}.{}", std::process::id(), stamp));

    let result = (|| -> Result<()> {
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
            .with_context(|| format!("creating private temporary file for {}", output.display()))?;
        temp.write_all(data)?;
        temp.sync_all()?;
        drop(temp);

        if existing.is_some() {
            let backup_path = parent.join(format!(
                "{basename}.backup.{}.{}",
                std::process::id(),
                stamp
            ));
            let backup_result = (|| -> Result<()> {
                let mut backup = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&backup_path)?;
                let mut previous = fs::File::open(output)?;
                std::io::copy(&mut previous, &mut backup)?;
                backup.sync_all()?;
                Ok(())
            })();
            if backup_result.is_err() {
                let _ = fs::remove_file(&backup_path);
            }
            backup_result.context("failed to preserve existing output backup")?;
            if simulate_interruption {
                anyhow::bail!("simulated interruption before replacing existing output");
            }
            fs::rename(&temp_path, output).context("failed to atomically replace output")?;
        } else {
            // Unlike rename, hard_link fails if another process has just
            // created the destination. This preserves no-overwrite semantics.
            if simulate_interruption {
                anyhow::bail!("simulated interruption before creating new output");
            }
            fs::hard_link(&temp_path, output)
                .context("failed to create new output without overwriting")?;
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
    let suffix = "dedup.json";

    let file_name = input
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("output");

    let new_name = if ext.is_empty() {
        format!("{}.{}", file_name, suffix)
    } else {
        format!(
            "{}.{}",
            file_name.trim_end_matches(ext).trim_end_matches('.'),
            suffix
        )
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
    map.insert(
        "type".to_string(),
        item.get("type").cloned().unwrap_or(Value::Null),
    );
    map.insert(
        "_exact_password".to_string(),
        extract_login_field(item, "password"),
    );
    map.insert("_exact_totp".to_string(), extract_login_field(item, "totp"));
    for key in keys {
        match key {
            DedupKey::Domain => {
                let domains = extract_domains(item);
                map.insert("domain".to_string(), Value::Array(domains));
            }
            DedupKey::Username => {
                map.insert(
                    "username".to_string(),
                    extract_login_field(item, "username"),
                );
            }
            DedupKey::Password => {
                map.insert(
                    "password".to_string(),
                    extract_login_field(item, "password"),
                );
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
    if let Some(login) = item.get("login").and_then(Value::as_object)
        && let Some(Value::Array(items)) = login.get("uris")
    {
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
    uris
}

fn extract_domains(item: &Value) -> Vec<Value> {
    let mut domains: Vec<String> = Vec::new();
    for uri_value in extract_uris(item) {
        if let Value::String(uri) = uri_value {
            if let Some(host) = extract_origin_from_uri(&uri) {
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

// A conservative origin identity, not a registrable-domain/eTLD+1 guess.
// Unknown, internationalized, or non-web identifiers are retained as raw URLs.
fn extract_origin_from_uri(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    let authority = rest.split(&['/', '?', '#'][..]).next()?;
    if authority.is_empty() || authority.contains('@') || !authority.is_ascii() {
        return None;
    }

    let (host, port_suffix) = if let Some(bracketed) = authority.strip_prefix('[') {
        let closing = bracketed.find(']')?;
        let parsed = bracketed[..closing].parse::<Ipv6Addr>().ok()?;
        let suffix = &bracketed[closing + 1..];
        (format!("[{parsed}]"), normalized_port(suffix, &scheme)?)
    } else {
        let (host, suffix) = match authority.rsplit_once(':') {
            Some((host, suffix)) => {
                if host.contains(':') {
                    return None; // Unbracketed IPv6 is ambiguous.
                }
                (host, format!(":{suffix}"))
            }
            None => (authority, String::new()),
        };
        let host = host.strip_suffix('.').unwrap_or(host);
        if host.is_empty()
            || host
                .split('.')
                .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return None;
        }
        let canonical = match host.parse::<Ipv4Addr>() {
            Ok(ip) => ip.to_string(),
            Err(_) => host.to_ascii_lowercase(),
        };
        (canonical, normalized_port(&suffix, &scheme)?)
    };
    Some(format!("{scheme}://{host}{port_suffix}"))
}

fn normalized_port(suffix: &str, scheme: &str) -> Option<String> {
    if suffix.is_empty() {
        return Some(String::new());
    }
    let digits = suffix.strip_prefix(':')?;
    let port = digits.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        return Some(String::new());
    }
    Some(format!(":{port}"))
}

// Deliberately conservative until conflict-review and lossless merging exist.
#[cfg(test)]
fn deduplicate_items(
    items: Vec<Value>,
    config: &Config,
    ignore_keys: &HashSet<String>,
    ignore_paths: &[Vec<String>],
) -> (Vec<Value>, usize) {
    let (items, removed) = exact_dedup_tracked(
        items, config, ignore_keys, ignore_paths
    );
    (items.into_iter().map(|record| record.value).collect(), removed)
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
        b.count
            .cmp(&a.count)
            .then_with(|| b.exact_duplicates.cmp(&a.exact_duplicates))
            .then_with(|| b.conflicting_or_distinct.cmp(&a.conflicting_or_distinct))
    });
    Report {
        total_items: items.len(),
        duplicate_groups: report_groups.len(),
        removed,
        groups: report_groups,
        account_groups: analyze_accounts(items),
        compatible_uri_merges: 0,
        reconciliation: None,
        unavailable_data_notice: vec![
            "Passkeys may be absent from source exports",
            "Attachments and binary data may be absent from source exports",
            "External authenticator accounts are not imported automatically",
            "Changes after the original export snapshot are not included",
        ],
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
        let contents = fs::read_to_string(config_path)
            .with_context(|| format!("failed to read config file {}", config_path.display()))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config file {}", config_path.display()))?;
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
        assert_ne!(
            key(&login("PasswordABC", "seed"), &config),
            key(&login("passwordabc", "seed"), &config)
        );
        assert_ne!(
            key(&login("same", "AbCd"), &config),
            key(&login("same", "abcd"), &config)
        );
    }

    #[test]
    fn secret_equality_cannot_be_disabled_by_policy() {
        let mut config = Config::default();
        config.dedup.policy_keys = vec![DedupKey::Domain];
        assert_ne!(
            key(&login("abc", "otp"), &config),
            key(&login("ABC", "otp"), &config)
        );
        assert_ne!(
            key(&login("abc", "otp"), &config),
            key(&login("abc", "OTP"), &config)
        );
    }

    #[test]
    fn full_record_matching_does_not_lowercase_secrets() {
        let mut config = Config::default();
        config.dedup.policy_keys.clear();
        config.normalize.lowercase_strings = true;
        assert_ne!(
            key(&login("UPPER", "otp"), &config),
            key(&login("upper", "otp"), &config)
        );
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
        for canary in [
            secret,
            otp,
            "NEVER_PRINT_PRIVATE_NOTE",
            "example.test",
            "User",
        ] {
            assert!(!encoded.contains(canary));
        }
    }

    #[test]
    fn dry_run_rejects_report_output() {
        let parsed = Args::try_parse_from([
            "bw-passport-dedup",
            "--input",
            "test.json",
            "--dry-run",
            "--report",
            "report.json",
        ])
        .unwrap();
        assert!(parsed.dry_run && parsed.report.is_some());
        // Exercise the actual CLI rejection logic, not merely Clap parsing.
        assert!(validate_run(&parsed, &Config::default(), Path::new("clean.json")).is_err());
    }
    #[test]
    fn private_atomic_output_preserves_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "bw-dedup-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
        let backed_up = fs::read_dir(&base)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".backup."))
            .any(|entry| fs::read(entry.path()).unwrap() == b"old");
        assert!(backed_up);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn original_input_cannot_be_overwritten() {
        let base = std::env::temp_dir().join(format!(
            "bw-dedup-input-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let input = base.join("input.json");
        fs::write(&input, b"keep me").unwrap();
        assert!(write_private_atomically(&input, b"bad", true, Some(&input)).is_err());
        assert_eq!(fs::read(&input).unwrap(), b"keep me");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn preserve_distinct_metadata_and_2fa() {
        let config = Config::default();
        let original = login("secret", "otpA");
        let mut with_notes = original.clone();
        with_notes["notes"] = json!("Valuable private note");
        let changed_totp = login("secret", "otpB");
        let (items, removed) = deduplicate_items(
            vec![original, with_notes, changed_totp],
            &config,
            &HashSet::new(),
            &[],
        );
        assert_eq!(removed, 0);
        assert_eq!(items.len(), 3);
        assert_eq!(items[1]["notes"], "Valuable private note");
    }

    #[test]
    fn identical_login_is_only_record_that_can_be_removed() {
        let original = login("Password", "OTP");
        let unrelated = json!({"type": 2, "name": "Secure note", "notes": "valuable"});
        let (items, removed) = deduplicate_items(
            vec![
                original.clone(),
                unrelated.clone(),
                unrelated,
                original.clone(),
            ],
            &Config::default(),
            &HashSet::new(),
            &[],
        );
        assert_eq!(removed, 1);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], original);
    }

    #[test]
    fn rejects_output_alias_of_original_input() {
        let base = std::env::temp_dir().join(format!(
            "bw-alias-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let source = base.join("input.json");
        fs::write(&source, b"keep me").unwrap();
        assert!(same_destination(&source, &base.join("./input.json")).unwrap());
        assert!(validate_destination(&source, &source, true).is_err());
        let alias = base.join("linked.json");
        fs::hard_link(&source, &alias).unwrap();
        assert!(same_destination(&source, &alias).unwrap());
        assert!(validate_destination(&alias, &source, true).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn preflight_rejects_existing_reports_without_side_effects() {
        let base = std::env::temp_dir().join(format!(
            "bw-report-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let input = base.join("source.json");
        let output = base.join("clean.json");
        let report = base.join("report.json");
        fs::write(&input, b"{}").unwrap();
        fs::write(&report, b"existing").unwrap();
        assert!(validate_destination(&output, &input, false).is_ok());
        assert!(validate_destination(&report, &input, false).is_err());
        assert!(!output.exists());
        assert_eq!(fs::read(&report).unwrap(), b"existing");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn malformed_and_nonfile_input_fail_closed() {
        let base = std::env::temp_dir().join(format!(
            "bw-input-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        assert!(read_bounded_json(&base).is_err());
        let input = base.join("invalid.json");
        fs::write(&input, b"{ definitely not valid json").unwrap();
        assert!(read_bounded_json(&input).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn bounded_input_rejects_sparse_oversize_file() {
        let base = std::env::temp_dir().join(format!(
            "bw-size-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let input = base.join("oversize.json");
        let file = fs::File::create(&input).unwrap();
        file.set_len(MAX_INPUT_BYTES + 1).unwrap();
        drop(file);
        assert!(read_bounded_json(&input).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn unknown_item_type_does_not_deduplicate() {
        let a = json!({"type": 99, "name": "unknown", "value": "opaque"});
        let (items, removed) =
            deduplicate_items(vec![a.clone(), a], &Config::default(), &HashSet::new(), &[]);
        assert_eq!(items.len(), 2);
        assert_eq!(removed, 0);
    }

    #[test]
    fn interrupted_force_replacement_preserves_old_data() {
        let base = std::env::temp_dir().join(format!(
            "bw-interrupt-old-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let output = base.join("existing.json");
        fs::write(&output, b"original must survive").unwrap();
        let err = write_private_atomically_inner(&output, b"replacement", true, None, true);
        assert!(err.is_err());
        assert_eq!(fs::read(&output).unwrap(), b"original must survive");
        let entries: Vec<_> = fs::read_dir(&base)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(
            entries.len(),
            2,
            "only the original and its backup should remain"
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.file_name().to_string_lossy().contains(".backup."))
        );
        assert!(
            !entries
                .iter()
                .any(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn interrupted_initial_write_leaves_no_partial_export() {
        let base = std::env::temp_dir().join(format!(
            "bw-interrupt-new-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let output = base.join("new.json");
        assert!(write_private_atomically_inner(&output, b"secret", false, None, true).is_err());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(&base).unwrap().count(), 0);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn plaintext_bitwarden_types_survive_schema_validation() {
        let root = json!({
            "encrypted": false,
            "folders": [{"id":"folder-1","name":"Archive"}],
            "items": [
                {"type": 2, "name": "secure note", "notes": "fictional"},
                {"type": 3, "name": "card", "card": {"brand": "Visa", "number": "TEST"}},
                {"type": 4, "name": "identity", "identity": {"firstName": "Synthetic"}},
                {"type": 99, "name": "future item", "unknownField": {"nested": true}}
            ]
        });
        assert!(validate_bitwarden_root(&root).is_ok());
        let (items, removed) = deduplicate_items(
            root["items"].as_array().unwrap().clone(),
            &Config::default(),
            &HashSet::new(),
            &[],
        );
        assert_eq!(items.len(), 4);
        assert_eq!(removed, 0);
    }

    #[test]
    fn encrypted_and_malformed_bitwarden_input_rejected() {
        assert!(validate_bitwarden_root(&json!({"encrypted":true,"items":[]})).is_err());
        assert!(validate_bitwarden_root(&json!({"encrypted":"cipher","items":[]})).is_err());
        assert!(
            validate_bitwarden_root(&json!({"encrypted":false,"items":[{"name":"missing type"}]}))
                .is_err()
        );
        assert!(validate_bitwarden_root(&json!({"encrypted":false,"items":[{"type":1}]})).is_err());
        assert!(
            validate_bitwarden_root(&json!({"encrypted":false,"folders":"bad","items":[]}))
                .is_err()
        );
    }
    #[test]
    fn safe_origin_matching_preserves_ports_subdomains_and_schemes() {
        assert_eq!(
            extract_origin_from_uri("https://EXAMPLE.test:443/path"),
            Some("https://example.test".to_owned())
        );
        assert_eq!(
            extract_origin_from_uri("http://EXAMPLE.test:80/path"),
            Some("http://example.test".to_owned())
        );
        assert_eq!(
            extract_origin_from_uri("https://example.test:8443/path"),
            Some("https://example.test:8443".to_owned())
        );
        assert_ne!(
            extract_origin_from_uri("https://app.example.test"),
            extract_origin_from_uri("https://example.test")
        );
        assert_ne!(
            extract_origin_from_uri("https://example.test"),
            extract_origin_from_uri("http://example.test")
        );
        assert_eq!(
            extract_origin_from_uri("https://[::1]:443/a"),
            Some("https://[::1]".to_owned())
        );
        assert_eq!(
            extract_origin_from_uri("http://[2001:DB8::1]:8080/a"),
            Some("http://[2001:db8::1]:8080".to_owned())
        );
        assert_eq!(
            extract_origin_from_uri("http://127.0.0.1:8080/test"),
            Some("http://127.0.0.1:8080".to_owned())
        );
    }

    #[test]
    fn ambiguous_uris_are_never_broadly_normalized() {
        for uri in [
            "https://alice:secret@example.test",
            "https://example.test:notaport",
            "https://example.test:0/",
            "https://example..test",
            "https://bücher.example",
            "androidapp://com.example",
            "file:///private/path",
            "https://unbracketed::1/",
        ] {
            assert!(
                extract_origin_from_uri(uri).is_none(),
                "unexpected normalization"
            );
        }
    }
    #[test]
    fn canonical_identity_and_redacted_reports_are_order_independent() {
        let first = login("SyntheticSecret", "TOTPA");
        let mut second = first.clone();
        second["notes"] = json!("fictional note");
        let mut third = first.clone();
        third["login"]["uris"] = json!([
            {"uri":"https://example.test/login"},
            {"uri":"https://another.test/account"}
        ]);
        let cfg = Config::default();
        let a = vec![first.clone(), second.clone(), third.clone()];
        let b = vec![third, second, first];
        let report_a = serde_json::to_value(build_report(&a, &cfg, &HashSet::new(), &[])).unwrap();
        let report_b = serde_json::to_value(build_report(&b, &cfg, &HashSet::new(), &[])).unwrap();
        let mut report_a = report_a;
        let mut report_b = report_b;
        // Input positions are intentionally snapshot-relative references,
        // not stable IDs: reordered inputs must produce different positions.
        for report in [&mut report_a, &mut report_b] {
            for group in report["account_groups"].as_array_mut().unwrap() {
                group.as_object_mut().unwrap().remove("records");
            }
        }
        assert_eq!(report_a, report_b);
        let (items_a, _) = deduplicate_items(a, &cfg, &HashSet::new(), &[]);
        let (items_b, _) = deduplicate_items(b, &cfg, &HashSet::new(), &[]);
        let mut canonical_a = items_a
            .iter()
            .map(|item| serde_json::to_string(&canonicalize(item)).unwrap())
            .collect::<Vec<_>>();
        let mut canonical_b = items_b
            .iter()
            .map(|item| serde_json::to_string(&canonicalize(item)).unwrap())
            .collect::<Vec<_>>();
        canonical_a.sort();
        canonical_b.sort();
        assert_eq!(canonical_a, canonical_b);
    }

    #[test]
    fn custom_fields_and_unknown_json_keys_survive_cleanup() {
        let mut item = login("SeCrEt", "OTP");
        item["fields"] = json!([
            {"name":"custom-private","value":"SyntheticOpaqueData","type":1}
        ]);
        item["vendorFutureField"] = json!({"modes":[{"name":"fictional"}]});
        let (records, removed) =
            deduplicate_items(vec![item.clone()], &Config::default(), &HashSet::new(), &[]);
        assert_eq!(removed, 0);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], item);
    }
}
