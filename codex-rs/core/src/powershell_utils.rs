//! PowerShell- and Windows-cmd specific helpers used by command parsing and safety checks.

use crate::is_safe_command::is_known_safe_command;
use crate::parse_command::{
    ParsedCommand, shlex_join, short_display_path, simplify_once, summarize_main_tokens,
};
use shlex::split as shlex_split;

// ---- Small utilities & constants -----------------------------------------------------------

#[inline]
fn is_ps(s: &str) -> bool {
    s == "powershell" || s == "pwsh"
}

const PS_ALLOWED_CMDLETS: &[&str] = &[
    "get-content",
    "select-string",
    "get-childitem",
    "foreach-object",
    "measure-object",
    "join-path",
    "where-object",
    "select-object",
    "test-path",
    "write-output",
    "write-host",
    "out-string",
    // common safe aliases
    "%",
];

const PS_BANNED_SUBSTRS: &[&str] = &[
    ">>",
    ">",
    // common mutating verbs
    " set-",
    " remove-",
    " new-",
    " copy-",
    " move-",
    " start-",
    " stop-",
    " restart-",
    " invoke-",
    " out-",
    " add-",
    " clear-",
    " write-",
    " rename-",
    // explicit dangerous cmdlets
    " set-content",
    " add-content",
    " new-item",
    " remove-item",
    " set-acl",
    " remove-acl",
];

const PS_BANNED_ALIASES: &[&str] = &["rm", "del", "rmdir", "mkdir"]; // case-insensitive

#[inline]
fn contains_banned_substring(lower: &str) -> bool {
    PS_BANNED_SUBSTRS.iter().any(|s| {
        if *s == " out-" {
            // Allow Out-String specifically; reject other Out-*
            lower.contains(s) && !lower.contains(" out-string")
        } else if *s == " write-" {
            // Allow Write-Output and Write-Host specifically; reject other Write-*
            lower.contains(s) && !lower.contains(" write-output") && !lower.contains(" write-host")
        } else {
            lower.contains(s)
        }
    })
}

#[inline]
fn split_top_level_segments(script: &str) -> Vec<String> {
    let mut segments: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_squote = false;
    let mut in_dquote = false;
    for ch in script.chars() {
        match ch {
            '\'' if !in_dquote => {
                in_squote = !in_squote;
                current.push(ch);
            }
            '"' if !in_squote => {
                in_dquote = !in_dquote;
                current.push(ch);
            }
            '|' | ';' if !in_squote && !in_dquote => {
                if !current.trim().is_empty() {
                    segments.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        segments.push(current.trim().to_string());
    }
    segments
}

#[inline]
fn split_simple_tokens(seg: &str) -> Vec<String> {
    let mut toks: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_s = false;
    let mut in_d = false;
    for ch in seg.chars().chain(std::iter::once(' ')) {
        match ch {
            '\'' if !in_d => in_s = !in_s,
            '"' if !in_s => in_d = !in_d,
            // Treat common separators (including parentheses) as token boundaries
            ' ' | '\t' | '\n' | '(' | ')' if !in_s && !in_d => {
                if !cur.is_empty() {
                    toks.push(cur.clone());
                    cur.clear();
                }
            }
            _ => cur.push(ch),
        }
    }
    toks
}

/// If the command is a PowerShell invocation, extract the inner script string.
/// Supports both `powershell` and `pwsh` with common flag permutations.
pub fn try_extract_powershell_command_script(command: &[String]) -> Option<String> {
    let ps = command.first()?;
    if !is_ps(ps) {
        return None;
    }
    // Accept optional -NoLogo/-NoProfile in any order, then -Command|-c and a script
    let mut i = 1;
    while i < command.len() && (command[i] == "-NoLogo" || command[i] == "-NoProfile") {
        i += 1;
    }
    if i + 1 < command.len() && (command[i] == "-Command" || command[i] == "-c") {
        return Some(command[i + 1].clone());
    }
    None
}

/// Conservative check that a PowerShell script appears read-only.
pub fn is_powershell_read_only_script(script: &str) -> bool {
    // Fast rejections for common mutating patterns/verbs or redirections.
    let lower = script.to_ascii_lowercase();
    if contains_banned_substring(&lower) {
        return false;
    }

    // Tokenize and enforce allow/deny lists.
    // - Reject known mutating aliases (e.g., rm, del, rmdir, mkdir)
    // - For non-cmdlet invocations inside the script (e.g., `rg ...; cargo check`),
    //   split into subcommands and recursively defer to `is_known_safe_command`.
    // - Otherwise, allow only a small set of read-only cmdlets (Word-Word)

    // First, split the script into top-level segments by ';' and '|', respecting quotes.
    let segments = split_top_level_segments(script);

    // Collect external commands to be checked recursively.
    let mut external_cmds: Vec<Vec<String>> = Vec::new();
    for seg in &segments {
        let tokens = split_simple_tokens(seg);
        if tokens.is_empty() {
            continue;
        }
        // Find the first token that is not a variable/assignment or flag.
        let first_tok = tokens
            .iter()
            .find(|t| {
                let t0 = t.chars().next().unwrap_or(' ');
                // Consider tokens that start with an alphabetic character OR '%'
                // (the common alias for ForEach-Object) as candidates for the
                // first command-like token. Exclude variables, flags, and
                // simple assignments.
                (t0.is_ascii_alphabetic() || t0 == '%')
                    && t0 != '$'
                    && t0 != '-'
                    && !t.contains('=')
            })
            .cloned();
        let Some(first_raw) = first_tok else { continue };
        let first = first_raw.to_ascii_lowercase();
        // If the first token looks like a cmdlet (has a dash or is '%'), skip here; handled below.
        let looks_like_cmdlet = first == "%" || first.contains('-');
        if !looks_like_cmdlet {
            // Allow common PowerShell language keywords that control flow and are inherently
            // read-only by themselves.
            const PS_KEYWORDS_READ_ONLY: &[&str] = &[
                "for", "foreach", "if", "elseif", "else", "while", "switch", "try", "catch",
                "finally",
            ];
            if PS_KEYWORDS_READ_ONLY.contains(&first.as_str()) {
                continue;
            }
            // Reject banned aliases immediately.
            if PS_BANNED_ALIASES.contains(&first.as_str()) {
                return false;
            }
            external_cmds.push(tokens);
        }
    }

    if !external_cmds.is_empty() {
        // Defer to `is_known_safe_command` for each external subcommand.
        return external_cmds.iter().all(|cmd| is_known_safe_command(cmd));
    }

    // If we only see assignments/keywords and read-only cmdlets (e.g., Get-Content)
    // with no external commands detected, consider the script read-only.
    // This accommodates patterns like loops and formatting operators (-f).
    if script.to_ascii_lowercase().contains("get-content") {
        return true;
    }

    // No external commands detected; enforce a conservative cmdlet allowlist.
    let mut buf = String::new();
    let mut allowed = true;
    for ch in script.chars().chain(std::iter::once(' ')) {
        let is_sep = matches!(
            ch,
            ' ' | '\t' | '\n' | '|' | ';' | '(' | ')' | '{' | '}' | ',' | '='
        );
        if !is_sep {
            buf.push(ch);
            continue;
        }
        if !buf.is_empty() {
            let token = buf.trim();
            if !token.is_empty() {
                let t0 = token.chars().next().unwrap_or(' ');
                if t0 != '$' && t0 != '-' {
                    if token.contains('-') && token.chars().any(|c| c.is_ascii_alphabetic()) {
                        let lname = token.to_ascii_lowercase();
                        if !PS_ALLOWED_CMDLETS.contains(&lname.as_str()) {
                            allowed = false;
                            break;
                        }
                    }
                }
            }
            buf.clear();
        }
    }

    allowed
}

// ---- PowerShell parsing helpers used by parse_command.rs ----

/// Extract a list of filenames from a PowerShell Get-Content invocation.
/// Specifically handles: Get-Content -Path a,b,c ...
pub fn ps_extract_filenames(script: &str) -> Vec<String> {
    let lower = script.to_ascii_lowercase();
    let idx = match lower.find("-path") {
        Some(i) => i,
        None => return Vec::new(),
    };
    let after = &script[idx + "-path".len()..];
    let rest = after.trim_start_matches(|c: char| c.is_whitespace() || c == ':' || c == '=');
    // Capture a comma/space separated list until next flag or pipeline separator
    let mut buf = String::new();
    let mut in_quote: Option<char> = None;
    let mut prev: Option<char> = None;
    for ch in rest.chars() {
        match in_quote {
            Some(q) => {
                if ch == q {
                    in_quote = None;
                }
                buf.push(ch);
            }
            None => {
                if ch == '\'' || ch == '"' {
                    in_quote = Some(ch);
                    buf.push(ch);
                } else if ch == '|' || ch == ';' {
                    break;
                } else if ch == '-' && prev.is_some_and(|p| p.is_whitespace()) {
                    break; // start of the next flag
                } else {
                    buf.push(ch);
                }
            }
        }
        prev = Some(ch);
    }
    let list = buf.trim();
    if list.is_empty() {
        return Vec::new();
    }
    list.split(',')
        .map(|s| s.trim().trim_matches('\'').trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Extract query used with -match in PowerShell (e.g., ... -match '"mod\\.rs"').
/// Returns a simplified string with quotes and backslashes removed when present.
pub fn ps_extract_match_query(script: &str) -> Option<String> {
    let lower = script.to_ascii_lowercase();
    let idx = lower.find("-match")?;
    let after = &script[idx + "-match".len()..];
    let rest = after.trim_start_matches(|c: char| c.is_whitespace() || c == ':' || c == '=');
    let mut chars = rest.chars();
    let quote = chars.next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let mut value = String::new();
    for ch in chars {
        if ch == quote {
            break;
        }
        value.push(ch);
    }
    let simplified = value.replace(['\\', '"', '\''], "");
    if simplified.is_empty() {
        None
    } else {
        Some(simplified)
    }
}

/// Find "-Pattern <value>" (case-insensitive). Values may be quoted.
pub fn ps_extract_pattern(script: &str) -> Option<String> {
    let lower = script.to_ascii_lowercase();
    let needle = "-pattern";
    let idx = lower.find(needle)?;
    let after = &script[idx + needle.len()..];
    // Skip whitespace and any '=' or ':'
    let mut chars = after.chars().peekable();
    while let Some(c) = chars.peek() {
        if c.is_whitespace() || *c == ':' || *c == '=' {
            chars.next();
        } else {
            break;
        }
    }
    let rest: String = chars.collect();
    if rest.is_empty() {
        return None;
    }
    let bytes = rest.as_bytes();
    let first = bytes[0] as char;
    if first == '\'' || first == '"' {
        // quoted string
        let quote = first;
        let mut value = String::new();
        for ch in rest.chars().skip(1) {
            if ch == quote {
                break;
            }
            value.push(ch);
        }
        Some(value)
    } else {
        // unquoted until whitespace
        let mut value = String::new();
        for ch in rest.chars() {
            if ch.is_whitespace() {
                break;
            }
            value.push(ch);
        }
        if value.is_empty() { None } else { Some(value) }
    }
}

/// Heuristically extract a single filename from a script string.
pub fn ps_extract_filename(script: &str) -> Option<String> {
    // Look for a plausible filename with an extension, e.g. foo.rs or foo.toml
    // Scan through quoted segments and plain tokens.
    let mut cur = String::new();
    let mut in_quote: Option<char> = None;
    let mut candidates: Vec<String> = Vec::new();
    for ch in script.chars() {
        match in_quote {
            Some(q) => {
                if ch == q {
                    // end quote
                    if !cur.is_empty() {
                        candidates.push(cur.clone());
                        cur.clear();
                    }
                    in_quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => {
                if ch == '\'' || ch == '"' {
                    in_quote = Some(ch);
                    if !cur.is_empty() {
                        candidates.push(cur.clone());
                        cur.clear();
                    }
                } else if ch.is_whitespace()
                    || matches!(ch, '|' | ';' | '(' | ')' | '{' | '}' | ',' | '=')
                {
                    if !cur.is_empty() {
                        candidates.push(cur.clone());
                        cur.clear();
                    }
                } else {
                    cur.push(ch);
                }
            }
        }
    }
    if !cur.is_empty() {
        candidates.push(cur);
    }
    for c in candidates {
        let lc = c.to_ascii_lowercase();
        // Heuristic: pick the last token that looks like a filename (contains a dot and letters)
        if lc.contains('.') && lc.chars().any(|ch| ch.is_ascii_alphabetic()) {
            return Some(c);
        }
    }
    None
}

/// Heuristically extract a directory-like path from a script string.
pub fn ps_extract_directory(script: &str) -> Option<String> {
    // Look for a quoted path following a variable assignment (e.g. $p='C:\\...\\src')
    // or an argument to Get-ChildItem.
    // Simple heuristic: take the first quoted string that contains a path separator.
    let mut cur = String::new();
    let mut in_quote: Option<char> = None;
    let mut first_quoted_with_sep: Option<String> = None;
    for ch in script.chars() {
        match in_quote {
            Some(q) => {
                if ch == q {
                    if !cur.is_empty() && (cur.contains('/') || cur.contains('\\')) {
                        first_quoted_with_sep = Some(cur.clone());
                        break;
                    }
                    cur.clear();
                    in_quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => {
                if ch == '\'' || ch == '"' {
                    in_quote = Some(ch);
                }
            }
        }
    }
    first_quoted_with_sep
}

// ---- Windows cmd.exe helpers ----

/// Parse `cmd.exe`/`cmd` invocations into ParsedCommand entries.
pub fn parse_cmd_exe_commands(original: &[String]) -> Option<Vec<ParsedCommand>> {
    // Accepted shapes (case-insensitive on program name):
    //   [cmd, /d, /s, /c, script]
    //   [cmd, /s, /c, script]
    //   [cmd, /c, script]
    fn is_cmd(s: &str) -> bool {
        let l = s.to_ascii_lowercase();
        l == "cmd" || l == "cmd.exe"
    }

    let (prefix_flags, script) = match original {
        [cmd, a, b, c, script] if is_cmd(cmd) && a == "/d" && b == "/s" && c == "/c" => (
            vec![(*cmd).clone(), a.clone(), b.clone(), c.clone()],
            script,
        ),
        [cmd, a, b, script] if is_cmd(cmd) && a == "/s" && b == "/c" => {
            (vec![(*cmd).clone(), a.clone(), b.clone()], script)
        }
        [cmd, a, script] if is_cmd(cmd) && a == "/c" => (vec![(*cmd).clone(), a.clone()], script),
        _ => return None,
    };
    let prefix = prefix_flags.join(" ");

    let lower = script.to_ascii_lowercase();

    // Heuristic: recognize simple read/list/search commands
    if (lower.starts_with("type ") || lower == "type")
        && let Some(name) = ps_extract_filename(script)
    {
        return Some(vec![ParsedCommand::Read {
            cmd: format!("{} {}", prefix, script),
            name: short_display_path(&name),
        }]);
    }

    if lower.starts_with("dir") {
        // Try to extract a path operand; fall back to None
        return Some(vec![ParsedCommand::ListFiles {
            cmd: format!("{} {}", prefix, script),
            path: None,
        }]);
    }

    if lower.contains("findstr") {
        let query = cmd_extract_query(script);
        return Some(vec![ParsedCommand::Search {
            cmd: format!("{} {}", prefix, script),
            query,
            path: None,
        }]);
    }

    Some(vec![ParsedCommand::Unknown {
        cmd: format!("{} {}", prefix, script),
    }])
}

/// Extract the first quoted search query used with `findstr`.
pub fn cmd_extract_query(script: &str) -> Option<String> {
    let lower = script.to_ascii_lowercase();
    let idx = lower.find("findstr")?;
    let after = &script[idx + "findstr".len()..];
    let mut in_quote: Option<char> = None;
    let mut cur = String::new();
    for ch in after.chars() {
        match in_quote {
            Some(q) => {
                if ch == q {
                    if !cur.is_empty() {
                        return Some(cur);
                    }
                    cur = String::new();
                    in_quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => {
                if ch == '\'' || ch == '"' {
                    in_quote = Some(ch);
                }
            }
        }
    }
    None
}

/// Collect plausible positional arguments following any `Get-Content` token when
/// `-Path`/`-LiteralPath` are not used. This preserves the previous heuristics
/// but isolates the logic for readability.
fn collect_positional_get_content_args(script: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for seg in split_top_level_segments(script) {
        let toks = split_simple_tokens(&seg);
        let mut i = 0usize;
        while i < toks.len() {
            if toks[i].eq_ignore_ascii_case("get-content") {
                let has_path_flag = toks.iter().skip(i + 1).any(|t| {
                    let l = t.to_ascii_lowercase();
                    l == "-path"
                        || l.starts_with("-path:")
                        || l == "-literalpath"
                        || l.starts_with("-literalpath:")
                });
                if has_path_flag {
                    i += 1;
                    continue;
                }
                let mut j = i + 1;
                while j < toks.len() {
                    let t = &toks[j];
                    if t.starts_with('-') {
                        j += 1;
                        continue;
                    }
                    let raw = t.trim_matches('\'').trim_matches('"');
                    let looks_like_path = raw.contains('/')
                        || raw.contains('\\')
                        || (raw.contains('.') && raw.chars().any(|c| c.is_ascii_alphabetic()));
                    if looks_like_path && !raw.is_empty() {
                        out.push(raw.to_string());
                    }
                    break;
                }
                i = j;
                continue;
            }
            i += 1;
        }
    }
    out
}

fn handle_select_string(
    script: &str,
    cmd_for_display: &str,
    lower_script: &str,
    pattern_query: Option<String>,
    dir_path: &mut Option<String>,
) -> Option<Vec<ParsedCommand>> {
    if !lower_script.contains("select-string") {
        return None;
    }
    let mut out: Vec<ParsedCommand> = Vec::new();
    if lower_script.contains("get-content") {
        if let Some(n) = ps_extract_filename(script) {
            out.push(ParsedCommand::Read {
                cmd: cmd_for_display.to_string(),
                name: short_display_path(&n),
            });
            return Some(out);
        }
    }
    let first_path = ps_extract_filenames(script).into_iter().next();
    let path_hint = first_path
        .map(|p| short_display_path(&p))
        .or(dir_path.take());
    out.push(ParsedCommand::Search {
        cmd: cmd_for_display.to_string(),
        query: pattern_query,
        path: path_hint,
    });
    Some(out)
}

fn handle_get_childitem(
    script: &str,
    cmd_for_display: &str,
    lower_script: &str,
    mut dir_path: Option<String>,
) -> Option<Vec<ParsedCommand>> {
    if !lower_script.contains("get-childitem") {
        return None;
    }
    let match_query = ps_extract_match_query(script);
    if match_query.is_some() {
        dir_path = None;
    }
    Some(vec![ParsedCommand::Search {
        cmd: cmd_for_display.to_string(),
        query: match_query,
        path: dir_path,
    }])
}

fn handle_get_content(
    script: &str,
    cmd_for_display: &str,
    lower_script: &str,
    mut file_names: Vec<String>,
    mut positional_get_content_args: Vec<String>,
) -> Option<Vec<ParsedCommand>> {
    if !lower_script.contains("get-content") {
        return None;
    }
    let mut out: Vec<ParsedCommand> = Vec::new();
    if !file_names.is_empty() || !positional_get_content_args.is_empty() {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut names: Vec<String> = Vec::new();
        for n in file_names
            .drain(..)
            .chain(positional_get_content_args.drain(..))
        {
            let name = short_display_path(&n);
            if seen.insert(name.clone()) {
                names.push(name);
            }
        }
        names.sort_by_key(|n| script.find(n).unwrap_or(usize::MAX));
        for name in names {
            out.push(ParsedCommand::Read {
                cmd: cmd_for_display.to_string(),
                name,
            });
        }
        return Some(out);
    }
    if let Some(n) = ps_extract_filename(script) {
        return Some(vec![ParsedCommand::Read {
            cmd: cmd_for_display.to_string(),
            name: short_display_path(&n),
        }]);
    }
    None
}

fn shlex_fallback(script: &str, cmd_for_display: String) -> Option<Vec<ParsedCommand>> {
    if let Some(tokens) = shlex_split(script) {
        let has_control_connectors = tokens.iter().any(|t| t == "&&" || t == "||" || t == ";");
        return if has_control_connectors {
            let mut segments: Vec<Vec<String>> = Vec::new();
            let mut cur: Vec<String> = Vec::new();
            for t in tokens {
                if t == "&&" || t == "||" || t == ";" {
                    if !cur.is_empty() {
                        segments.push(std::mem::take(&mut cur));
                    }
                } else {
                    cur.push(t);
                }
            }
            if !cur.is_empty() {
                segments.push(cur);
            }
            let mut commands: Vec<ParsedCommand> = segments
                .into_iter()
                .map(|seg| {
                    let pc = summarize_main_tokens(&seg);
                    let joined = shlex_join(&seg);
                    match pc {
                        ParsedCommand::Read { name, .. } => {
                            ParsedCommand::Read { cmd: joined, name }
                        }
                        ParsedCommand::ListFiles { path, .. } => {
                            ParsedCommand::ListFiles { cmd: joined, path }
                        }
                        ParsedCommand::Search { query, path, .. } => ParsedCommand::Search {
                            cmd: joined,
                            query,
                            path,
                        },
                        ParsedCommand::Format { tool, targets, .. } => ParsedCommand::Format {
                            cmd: joined,
                            tool,
                            targets,
                        },
                        ParsedCommand::Test { .. } => ParsedCommand::Test { cmd: joined },
                        ParsedCommand::Lint { tool, targets, .. } => ParsedCommand::Lint {
                            cmd: joined,
                            tool,
                            targets,
                        },
                        _ => ParsedCommand::Unknown { cmd: joined },
                    }
                })
                .collect();
            while let Some(next) = simplify_once(&commands) {
                commands = next;
            }
            Some(commands)
        } else {
            let summarized = summarize_main_tokens(&tokens);
            let remapped = match summarized {
                ParsedCommand::Read { name, .. } => ParsedCommand::Read {
                    cmd: cmd_for_display,
                    name,
                },
                ParsedCommand::ListFiles { path, .. } => ParsedCommand::ListFiles {
                    cmd: cmd_for_display,
                    path,
                },
                ParsedCommand::Search { query, path, .. } => ParsedCommand::Search {
                    cmd: cmd_for_display,
                    query,
                    path,
                },
                ParsedCommand::Format { tool, targets, .. } => ParsedCommand::Format {
                    cmd: cmd_for_display,
                    tool,
                    targets,
                },
                ParsedCommand::Test { .. } => ParsedCommand::Test {
                    cmd: cmd_for_display,
                },
                ParsedCommand::Lint { tool, targets, .. } => ParsedCommand::Lint {
                    cmd: cmd_for_display,
                    tool,
                    targets,
                },
                _ => ParsedCommand::Unknown {
                    cmd: cmd_for_display,
                },
            };
            Some(vec![remapped])
        };
    }
    None
}

/// Parse PowerShell (`powershell`/`pwsh`) command invocations into ParsedCommand entries.
pub fn parse_powershell_commands(original: &[String]) -> Option<Vec<ParsedCommand>> {
    let script = try_extract_powershell_command_script(original)?;

    // Display rule: show only the inner script for readability.
    let cmd_for_display = script.clone();
    let lower_script = script.to_ascii_lowercase();

    // Extract common hints once up-front.
    let pattern_query = ps_extract_pattern(&script);
    let file_names = ps_extract_filenames(&script);
    let positional_get_content_args = collect_positional_get_content_args(&script);
    let mut dir_path = ps_extract_directory(&script).map(|p| short_display_path(&p));

    // Handle common pipelines first.
    if let Some(res) = handle_select_string(
        &script,
        &cmd_for_display,
        &lower_script,
        pattern_query.clone(),
        &mut dir_path,
    ) {
        return Some(res);
    }
    if let Some(res) =
        handle_get_childitem(&script, &cmd_for_display, &lower_script, dir_path.clone())
    {
        return Some(res);
    }
    if let Some(res) = handle_get_content(
        &script,
        &cmd_for_display,
        &lower_script,
        file_names,
        positional_get_content_args,
    ) {
        return Some(res);
    }

    // Fallbacks.
    if let Some(v) = shlex_fallback(&script, cmd_for_display.clone()) {
        return Some(v);
    }

    Some(vec![ParsedCommand::Unknown {
        cmd: cmd_for_display,
    }])
}
