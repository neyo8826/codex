use crate::bash::parse_bash_lc_plain_commands;
use crate::powershell_utils::is_powershell_read_only_script;
use crate::powershell_utils::parse_powershell_commands;
use crate::powershell_utils::try_extract_powershell_command_script;
use codex_protocol::parse_command::ParsedCommand;
use shlex::split as shlex_split;

pub fn is_known_safe_command(command: &[String]) -> bool {
    #[cfg(target_os = "windows")]
    {
        use super::windows_safe_commands::is_safe_command_windows;
        if is_safe_command_windows(command) {
            return true;
        }
    }

    if is_safe_to_call_with_exec(command) {
        return true;
    }

    // Support `bash -lc "..."` where the script consists solely of one or
    // more "plain" commands (only bare words / quoted strings) combined with
    // a conservative allow‑list of shell operators that themselves do not
    // introduce side effects ( "&&", "||", ";", and "|" ). If every
    // individual command in the script is itself a known‑safe command, then
    // the composite expression is considered safe.
    if let Some(all_commands) = parse_bash_lc_plain_commands(command)
        && !all_commands.is_empty()
        && all_commands
            .iter()
            .all(|cmd| is_safe_to_call_with_exec(cmd))
    {
        return true;
    }

    // Fallback for bash -lc: allow a conservative read-only subset with
    // simple variable assignments and $(...) substitutions, combined with
    // pipes/&&/||/; between known-safe commands.
    if let [shell, flag, script] = command
        && (shell == "bash" || shell == "zsh")
        && flag == "-lc"
        && is_bash_read_only_with_assignments(script)
    {
        return true;
    }

    // Support read-only PowerShell invocations like:
    //   powershell -NoProfile -Command "Get-Content file | Select-String -Pattern 'foo'"
    // We conservatively allow only a small, read-only set of cmdlets/operators.
    if let Some(script) = try_extract_powershell_command_script(command) {
        if is_powershell_read_only_script(&script) {
            return true;
        }
        // Fallback heuristic: allow simple read-only scripts centered around Get-Content
        // when no obvious mutation or redirection is present.
        let lower = script.to_ascii_lowercase();
        const MUTATING_HINTS: &[&str] = &[
            "remove-item",
            "set-content",
            "add-content",
            "new-item",
            ">>",
            ">",
        ];
        if lower.contains("get-content") && !MUTATING_HINTS.iter().any(|s| lower.contains(s)) {
            return true;
        }
        // Additional fallback: if our parser recognizes this PowerShell script as a
        // read-only action (Read/ListFiles/Search/Noop), allow it.
        if let Some(parsed) = parse_powershell_commands(command) {
            let read_only = parsed.iter().all(|pc| {
                matches!(
                    pc,
                    ParsedCommand::Read { .. }
                        | ParsedCommand::ListFiles { .. }
                        | ParsedCommand::Search { .. }
                )
            });
            if read_only {
                return true;
            }
        }
    }

    false
}

fn is_safe_to_call_with_exec(command: &[String]) -> bool {
    // If this vector encodes a pipeline/sequence using tokens like "|", "&&", "||", ";",
    // split and ensure every sub-command is itself safe, and that no redirections appear.
    if command
        .iter()
        .any(|s| s == "|" || s == "&&" || s == "||" || s == ";")
    {
        // Quick rejection for obvious mutation/redirection/backgrounding tokens.
        if command
            .iter()
            .any(|s| s == ">" || s == ">>" || s == "<" || s == "|&")
        {
            return false;
        }

        let mut parts: Vec<Vec<String>> = Vec::new();
        let mut current: Vec<String> = Vec::new();
        for tok in command {
            match tok.as_str() {
                "|" | "&&" | "||" | ";" => {
                    if !current.is_empty() {
                        parts.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(tok.clone()),
            }
        }
        if !current.is_empty() {
            parts.push(current);
        }

        return !parts.is_empty() && parts.iter().all(|p| is_safe_to_call_with_exec(p));
    }

    let cmd0 = command.first().map(String::as_str);

    match cmd0 {
        #[rustfmt::skip]
        Some(
            "cat" |
            "cd" |
            "echo" |
            "false" |
            "grep" |
            "head" |
            "ls" |
            "nl" |
            "pwd" |
            "tail" |
            "true" |
            "wc" |
            "which") => {
            true
        },

        Some("find") => {
            // Certain options to `find` can delete files, write to files, or
            // execute arbitrary commands, so we cannot auto-approve the
            // invocation of `find` in such cases.
            #[rustfmt::skip]
            const UNSAFE_FIND_OPTIONS: &[&str] = &[
                // Options that can execute arbitrary commands.
                "-exec", "-execdir", "-ok", "-okdir",
                // Option that deletes matching files.
                "-delete",
                // Options that write pathnames to a file.
                "-fls", "-fprint", "-fprint0", "-fprintf",
            ];

            !command
                .iter()
                .any(|arg| UNSAFE_FIND_OPTIONS.contains(&arg.as_str()))
        }

        // Ripgrep
        Some("rg") => {
            const UNSAFE_RIPGREP_OPTIONS_WITH_ARGS: &[&str] = &[
                // Takes an arbitrary command that is executed for each match.
                "--pre",
                // Takes a command that can be used to obtain the local hostname.
                "--hostname-bin",
            ];
            const UNSAFE_RIPGREP_OPTIONS_WITHOUT_ARGS: &[&str] = &[
                // Calls out to other decompression tools, so do not auto-approve
                // out of an abundance of caution.
                "--search-zip",
                "-z",
            ];

            !command.iter().any(|arg| {
                UNSAFE_RIPGREP_OPTIONS_WITHOUT_ARGS.contains(&arg.as_str())
                    || UNSAFE_RIPGREP_OPTIONS_WITH_ARGS
                        .iter()
                        .any(|&opt| arg == opt || arg.starts_with(&format!("{opt}=")))
            })
        }

        // Git
        Some("git") => matches!(
            command.get(1).map(String::as_str),
            Some("branch" | "status" | "log" | "diff" | "show")
        ),

        // Rust
        Some("cargo") if command.get(1).map(String::as_str) == Some("check") => true,

        // Bazel (read-only queries)
        Some("bazel") => matches!(
            command.get(1).map(String::as_str),
            Some("query" | "aquery" | "cquery" | "info")
        ),

        // Special-case `sed -n {N|M,N}p [FILE]`
        // Allow both forms:
        //  - reading from a file:  sed -n 1,200p file.txt
        //  - reading from stdin:   sed -n 1,200p
        Some("sed")
            if {
                // 1) Strict allow-list: `sed -n {N|M,N}p [FILE]`
                let strict_ok = {
                    let has_dash_n = command.get(1).map(String::as_str) == Some("-n");
                    let valid_range = is_valid_sed_n_arg(command.get(2).map(String::as_str));
                    if has_dash_n && valid_range {
                        match command.len() {
                            3 => true,
                            4 => command.get(3).map(String::is_empty) == Some(false),
                            _ => false,
                        }
                    } else {
                        false
                    }
                };

                if strict_ok {
                    true
                } else {
                    sed_flags_whitelisted(command)
                }
            } =>
        {
            true
        }

        // ── anything else ─────────────────────────────────────────────────
        _ => false,
    }
}

// (bash parsing helpers implemented in crate::bash)

/* ----------------------------------------------------------
Example
---------------------------------------------------------- */

/// Returns true if `arg` matches /^(\d+,)?\d+p$/
fn is_valid_sed_n_arg(arg: Option<&str>) -> bool {
    // unwrap or bail
    let s = match arg {
        Some(s) => s,
        None => return false,
    };

    // must end with 'p', strip it
    let core = match s.strip_suffix('p') {
        Some(rest) => rest,
        None => return false,
    };

    // split on ',' and ensure 1 or 2 numeric parts
    let parts: Vec<&str> = core.split(',').collect();
    match parts.as_slice() {
        // single number, e.g. "10"
        [num] => !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()),

        // two numbers, e.g. "1,5"
        [a, b] => {
            !a.is_empty()
                && !b.is_empty()
                && a.chars().all(|c| c.is_ascii_digit())
                && b.chars().all(|c| c.is_ascii_digit())
        }

        // anything else (more than one comma) is invalid
        _ => false,
    }
}

fn sed_flags_whitelisted(command: &[String]) -> bool {
    // Allowed short flags: -n, -e, -E, -r, -u, -s, -z, -l N
    // Allowed combined short flags: any combo of [nErusz] (no e/l in combos)
    // Allowed long flags (GNU/BSD): --quiet/--silent, --expression, --regexp-extended,
    // --unbuffered, --null-data, --line-length=N
    // Disallowed: -i/--in-place (and variants), -f/--file, anything unknown.

    let mut i = 1usize; // start examining after the "sed" command
    let mut saw_expression = false;
    while i < command.len() {
        let tok = &command[i];
        let s = tok.as_str();
        if !s.starts_with('-') {
            i += 1;
            continue; // script fragments (like '1,200p') or filenames
        }

        // In-place editing is always unsafe.
        if s == "-i" || s.starts_with("-i") || s.starts_with("--in-place") {
            return false;
        }
        // External script file is unsafe because we cannot vet it.
        if s == "-f" || s == "--file" || s.starts_with("--file=") {
            return false;
        }

        // Handle flags with required argument
        if s == "-e" || s == "--expression" || s.starts_with("--expression=") {
            if s == "-e" {
                // needs a following argument
                if i + 1 >= command.len() {
                    return false;
                }
                saw_expression = true;
                i += 2;
                continue;
            }
            // --expression=SCRIPT is fine
            saw_expression = true;
            i += 1;
            continue;
        }
        if s == "-l" || s == "--line-length" || s.starts_with("--line-length=") {
            if s == "-l" || s == "--line-length" {
                if i + 1 >= command.len() {
                    return false;
                }
                let val = command[i + 1].as_str();
                if !val.chars().all(|c| c.is_ascii_digit()) {
                    return false;
                }
                i += 2;
                continue;
            }
            // --line-length=N form; validate suffix is numeric
            if let Some(eq) = s.find('=') {
                let num = &s[eq + 1..];
                if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
                    return false;
                }
            } else {
                return false;
            }
            i += 1;
            continue;
        }

        // Allow long no-arg flags
        match s {
            "--quiet" | "--silent" | "--regexp-extended" | "--unbuffered" | "--null-data" => {
                i += 1;
                continue;
            }
            _ => {}
        }

        // Allow simple short flags and safe combinations
        if s.starts_with('-') && s.len() > 1 {
            // combined short options like -nErsuz (but not e/l which need args)
            let mut ok = true;
            for ch in s[1..].chars() {
                match ch {
                    'n' | 'E' | 'r' | 'u' | 's' | 'z' => {}
                    // disallow combining options that expect arguments
                    'e' | 'l' => {
                        ok = false;
                        break;
                    }
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                i += 1;
                continue;
            }
        }

        // Unknown or unsafe flag encountered
        return false;
    }

    // Require an explicit -e/--expression unless the strict `-n {..}p` form matched earlier.
    saw_expression
}

// ---- helpers for bash -lc fallback ----

fn is_bash_read_only_with_assignments(script: &str) -> bool {
    // Validate each $(...) substitution is itself a safe command.
    let mut s = script.to_string();
    loop {
        let Some(start) = s.find("$(") else { break };
        // find matching ')'
        let mut depth = 1i32;
        let mut i = start + 2;
        let bytes = s.as_bytes();
        let mut end_opt = None;
        while i < s.len() {
            let c = bytes[i] as char;
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                if depth == 0 {
                    end_opt = Some(i);
                    break;
                }
            }
            i += 1;
        }
        let Some(end) = end_opt else { return false };
        let inner = s[start + 2..end].trim();
        let inner_tokens = shlex_split(inner)
            .unwrap_or_else(|| inner.split_whitespace().map(ToString::to_string).collect());
        if inner_tokens.is_empty() || !is_safe_to_call_with_exec(&inner_tokens) {
            return false;
        }
        // Replace the whole $(...) with a placeholder to avoid false positives when scanning
        s.replace_range(start..=end, "SUBST");
    }

    // Quick reject of redirections, backticks, and grouping.
    if s.contains('`') || s.contains('<') || s.contains('>') || s.contains('{') || s.contains('}') {
        return false;
    }
    // Reject standalone '&' (background). Allow '&&'.
    if s.replace("&&", "").contains('&') {
        return false;
    }

    // Split into segments by |, &&, ||, ; while respecting basic quotes.
    let segments = split_on_shell_operators(&s);
    if segments.is_empty() {
        return false;
    }
    for seg in segments {
        let trimmed = seg.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Allow pure variable assignment like: foo=BAR
        if is_pure_assignment(trimmed) {
            continue;
        }
        // Disallow assignment-prefix before a command (e.g., FOO=bar ls) for now.
        if has_assignment_prefix(trimmed) {
            return false;
        }
        let tokens = shlex_split(trimmed).unwrap_or_else(|| {
            trimmed
                .split_whitespace()
                .map(ToString::to_string)
                .collect()
        });
        if tokens.is_empty() || !is_safe_to_call_with_exec(&tokens) {
            return false;
        }
    }
    true
}

fn is_pure_assignment(s: &str) -> bool {
    // NAME=VALUE with NAME=[A-Za-z_][A-Za-z0-9_]*
    let Some(eq) = s.find('=') else { return false };
    if s[..eq].chars().enumerate().all(|(i, c)| {
        if i == 0 {
            c.is_ascii_alphabetic() || c == '_'
        } else {
            c.is_ascii_alphanumeric() || c == '_'
        }
    }) && !s[..eq].is_empty()
    {
        // Ensure there are no spaces; treat it as a standalone assignment.
        !s[..eq].contains(' ') && !s[eq + 1..].is_empty() && !s.contains(' ')
    } else {
        false
    }
}

fn has_assignment_prefix(s: &str) -> bool {
    // Detect patterns like NAME=value <rest>
    if let Some(space) = s.find(' ') {
        let head = &s[..space];
        is_pure_assignment(head)
    } else {
        false
    }
}

fn split_on_shell_operators(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut buf = String::new();
    let mut chars = s.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                buf.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                buf.push(c);
            }
            '|' if !in_single && !in_double => {
                parts.push(buf.trim().to_string());
                buf.clear();
            }
            '&' if !in_single && !in_double => {
                if matches!(chars.peek(), Some('&')) {
                    // consume second '&'
                    let _ = chars.next();
                    parts.push(buf.trim().to_string());
                    buf.clear();
                } else {
                    // standalone '&' not allowed
                    return Vec::new();
                }
            }
            ';' if !in_single && !in_double => {
                parts.push(buf.trim().to_string());
                buf.clear();
            }
            c2 => buf.push(c2),
        }
    }
    if !buf.trim().is_empty() {
        parts.push(buf.trim().to_string());
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    fn vec_str(args: &[&str]) -> Vec<String> {
        args.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn known_safe_examples() {
        assert!(is_safe_to_call_with_exec(&vec_str(&["ls"])));
        assert!(is_safe_to_call_with_exec(&vec_str(&["git", "status"])));
        assert!(is_safe_to_call_with_exec(&vec_str(&[
            "sed", "-n", "1,5p", "file.txt"
        ])));
        assert!(is_safe_to_call_with_exec(&vec_str(&[
            "nl",
            "-nrz",
            "Cargo.toml"
        ])));

        // Safe `find` command (no unsafe options).
        assert!(is_safe_to_call_with_exec(&vec_str(&[
            "find", ".", "-name", "file.txt"
        ])));

        // Safe `sed` command with wildcard in file path.
        assert!(is_safe_to_call_with_exec(&vec_str(&[
            "sed",
            "-n",
            "1,200p",
            "/home/user/.cache/bazel/*/defs.bzl"
        ])));

        // Safe `sed` command reading from stdin.
        assert!(is_safe_to_call_with_exec(&vec_str(&[
            "sed",
            "-n",
            "13,24p",
            "file.txt",
            "|",
            "sed",
            "-n",
            "1,200p",
            "|",
            "sed",
            "-e",
            "s/\\t/[TAB]/g",
            "-e",
            "s/ /[SP]/g",
            "-n",
            "-e",
            "1,200p"
        ])));
    }

    #[test]
    fn unknown_or_partial() {
        assert!(!is_safe_to_call_with_exec(&vec_str(&["foo"])));
        assert!(!is_safe_to_call_with_exec(&vec_str(&["git", "fetch"])));
        assert!(!is_safe_to_call_with_exec(&vec_str(&[
            "sed", "-n", "xp", "file.txt"
        ])));

        // Unsafe `find` commands.
        for args in [
            vec_str(&["find", ".", "-name", "file.txt", "-exec", "rm", "{}", ";"]),
            vec_str(&[
                "find", ".", "-name", "*.py", "-execdir", "python3", "{}", ";",
            ]),
            vec_str(&["find", ".", "-name", "file.txt", "-ok", "rm", "{}", ";"]),
            vec_str(&["find", ".", "-name", "*.py", "-okdir", "python3", "{}", ";"]),
            vec_str(&["find", ".", "-delete", "-name", "file.txt"]),
            vec_str(&["find", ".", "-fls", "/etc/passwd"]),
            vec_str(&["find", ".", "-fprint", "/etc/passwd"]),
            vec_str(&["find", ".", "-fprint0", "/etc/passwd"]),
            vec_str(&["find", ".", "-fprintf", "/root/suid.txt", "%#m %u %p\n"]),
        ] {
            assert!(
                !is_safe_to_call_with_exec(&args),
                "expected {args:?} to be unsafe"
            );
        }
    }

    #[test]
    fn ripgrep_rules() {
        // Safe ripgrep invocations – none of the unsafe flags are present.
        assert!(is_safe_to_call_with_exec(&vec_str(&[
            "rg",
            "Cargo.toml",
            "-n"
        ])));

        // Unsafe flags that do not take an argument (present verbatim).
        for args in [
            vec_str(&["rg", "--search-zip", "files"]),
            vec_str(&["rg", "-z", "files"]),
        ] {
            assert!(
                !is_safe_to_call_with_exec(&args),
                "expected {args:?} to be considered unsafe due to zip-search flag",
            );
        }

        // Unsafe flags that expect a value, provided in both split and = forms.
        for args in [
            vec_str(&["rg", "--pre", "pwned", "files"]),
            vec_str(&["rg", "--pre=pwned", "files"]),
            vec_str(&["rg", "--hostname-bin", "pwned", "files"]),
            vec_str(&["rg", "--hostname-bin=pwned", "files"]),
        ] {
            assert!(
                !is_safe_to_call_with_exec(&args),
                "expected {args:?} to be considered unsafe due to external-command flag",
            );
        }
    }

    #[test]
    fn bash_lc_safe_examples() {
        assert!(is_known_safe_command(&vec_str(&["bash", "-lc", "ls"])));
        assert!(is_known_safe_command(&vec_str(&["bash", "-lc", "ls -1"])));
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "git status"
        ])));
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "grep -R \"Cargo.toml\" -n"
        ])));
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "sed -n 1,5p file.txt"
        ])));
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "sed -n '1,5p' file.txt"
        ])));

        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "find . -name file.txt"
        ])));

        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "ls -la /home/user/.cache/bazel | sed -n '1,200p'"
        ])));
    }

    #[test]
    fn zsh_lc_safe_examples() {
        assert!(is_known_safe_command(&vec_str(&["zsh", "-lc", "ls"])));
        assert!(is_known_safe_command(&vec_str(&[
            "zsh",
            "-lc",
            "ls && pwd"
        ])));
    }

    #[test]
    fn bash_lc_safe_examples_with_operators() {
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "grep -R \"Cargo.toml\" -n || true"
        ])));
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "ls && pwd"
        ])));
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "echo 'hi' ; ls"
        ])));
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "ls | wc -l"
        ])));
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "ls -d bazel-*/external/rules_cuda/cuda | head -n1"
        ])));
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "sed -n '1,200p' /home/attila/.cache/bazel/*/defs.bzl | sed -n '1,200p'"
        ])));
    }

    #[test]
    fn bash_lc_unsafe_examples() {
        assert!(
            !is_known_safe_command(&vec_str(&["bash", "-lc", "git", "status"])),
            "Four arg version is not known to be safe."
        );
        assert!(
            !is_known_safe_command(&vec_str(&["bash", "-lc", "'git status'"])),
            "The extra quoting around 'git status' makes it a program named 'git status' and is therefore unsafe."
        );

        assert!(
            !is_known_safe_command(&vec_str(&["bash", "-lc", "find . -name file.txt -delete"])),
            "Unsafe find option should not be auto-approved."
        );

        // Disallowed because of unsafe command in sequence.
        assert!(
            !is_known_safe_command(&vec_str(&["bash", "-lc", "ls && rm -rf /"])),
            "Sequence containing unsafe command must be rejected"
        );

        // Disallowed because of parentheses / subshell.
        assert!(
            !is_known_safe_command(&vec_str(&["bash", "-lc", "(ls)"])),
            "Parentheses (subshell) are not provably safe with the current parser"
        );
        assert!(
            !is_known_safe_command(&vec_str(&["bash", "-lc", "ls || (pwd && echo hi)"])),
            "Nested parentheses are not provably safe with the current parser"
        );

        // Disallowed redirection.
        assert!(
            !is_known_safe_command(&vec_str(&["bash", "-lc", "ls > out.txt"])),
            "> redirection should be rejected"
        );
    }

    #[test]
    fn zsh_lc_unsafe_examples() {
        assert!(
            !is_known_safe_command(&vec_str(&["zsh", "-lc", "ls && rm -rf /"])),
            "Sequence containing unsafe command must be rejected"
        );
        assert!(
            !is_known_safe_command(&vec_str(&["zsh", "-lc", "ls > out.txt"])),
            "> redirection should be rejected"
        );
    }

    #[test]
    fn powershell_read_only_examples() {
        // 1) Read slice of a file
        let cmd1 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "$f='C:\\Users\\User\\.cargo\\registry\\src\\...\\virt.rs'; $c=Get-Content $f; $c[80..120]",
        ]);
        assert!(is_known_safe_command(&cmd1));

        // 2) Read and search with Select-String
        let cmd2 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "$f='C:\\Users\\User\\.cargo\\registry\\src\\...\\time.rs'; Get-Content $f | Select-String -Pattern 'advance_by|from_millis(500)|MAX' -Context 2,2 | ForEach-Object { $_ }",
        ]);
        assert!(is_known_safe_command(&cmd2));

        // 3) List files and search in a specific file under a directory
        let cmd3 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "$p='C:\\Users\\User\\.cargo\\registry\\src\\...\\src'; Get-ChildItem $p -Filter '*.rs' | % { $_.FullName }; Get-Content (Join-Path $p 'real.rs') -ErrorAction SilentlyContinue | Select-String -Pattern 'DEFAULT_MAX_DELTA|max_delta|clamp' -Context 1,1",
        ]);
        assert!(is_known_safe_command(&cmd3));

        // 4) Find a specific file by name
        let cmd4 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-ChildItem -Recurse -File | Where-Object {$_.Name -match '\"mod\\\\.rs\"'} | Select-Object -Expand FullName",
        ]);
        assert!(is_known_safe_command(&cmd4));

        // 5) Read a specific slice of a file
        let cmd5 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "$c = Get-Content core/src/is_safe_command.rs; $start=460; $end=520; $c[($start-1)..($end-1)] -join \"`n\"",
        ]);
        assert!(is_known_safe_command(&cmd5));

        // 6) Read a slice of a file with Select-Object
        let cmd6 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-Content -Path src/character.rs -TotalCount 800 | Select-Object -Index ((520-1)..(800-1)) | Out-String",
        ]);
        assert!(is_known_safe_command(&cmd6));

        // 7) Read multiple files and output their content
        let cmd7 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-Content -Path multiplayer/Cargo.toml, doc/README.md, singleplayer/Cargo.toml -Raw | Write-Output",
        ]);
        assert!(is_known_safe_command(&cmd7));

        // 8) Invoke ripgrep
        let cmd8 = vec_str(&["pwsh", "-Command", "rg -n 'TODO' -g '*.rs' -g '*.md' src"]);
        assert!(is_known_safe_command(&cmd8));

        // 9) Ripgrep with dash in pattern
        let cmd9 = vec_str(&[
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "rg -n 'test_dash|dash' src | Select-Object -First 200",
        ]);
        assert!(is_known_safe_command(&cmd9));

        // 10) Read a file and output the last 260 lines
        let cmd10 = vec_str(&[
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "Get-Content -Path src/character.rs -TotalCount 800 | Select-Object -Last 260",
        ]);
        assert!(is_known_safe_command(&cmd10));

        // 11) Select-String with ForEach-Object
        let cmd11 = vec_str(&[
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "Select-String -Path core/src/parse_command.rs -Pattern powershell,pwsh -SimpleMatch | ForEach-Object { \"{0}:{1}\" -f $_.LineNumber, $_.Line }",
        ]);
        assert!(is_known_safe_command(&cmd11));

        // 12) Read a slice of a file with Get-Content and Write-Output
        let cmd12 = vec_str(&[
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "$c = Get-Content core/src/is_safe_command.rs; for ($i=120; $i -le 180 -and $i -lt $c.Length; $i++) { $num=$i+1; Write-Output (\"{0,4}: {1}\" -f $num, $c[$i]) }",
        ]);
        assert!(is_known_safe_command(&cmd12));

        // 13) Read a slice of a file with Get-Content and Select-Object
        let cmd13 = vec_str(&[
            "pwsh",
            "-c",
            "(Get-Content core/src/parse_command.rs | Select-Object -First 220) -join \"`n\"",
        ]);
        assert!(is_known_safe_command(&cmd13));

        // 14) Read a file in chunks of 200 lines
        let cmd14 = vec_str(&[
            "pwsh",
            "-Command",
            "$lines = Get-Content src/game2d.rs; $lines.Count; $start=1; while ($start -le $lines.Count) { Write-Host \"--- src/game2d.rs lines $start..$([Math]::Min($start+199,$lines.Count)) ---\"; $lines[$start-1..([Math]::Min($start+199,$lines.Count)-1)]; $start += 200 }",
        ]);
        assert!(is_known_safe_command(&cmd14));

        // 15) Read a file with Measure-Object and Select-Object
        let cmd15 = vec_str(&[
            "pwsh",
            "-NoLogo",
            "-Command",
            "Get-Content src/map.rs | Measure-Object -Line | % Lines; Get-Content src/map.rs | Select-Object -First 260; echo '...'; Get-Content src/map.rs | Select-Object -Skip 260 -First 260",
        ]);
        assert!(is_known_safe_command(&cmd15));

        // 16) Read multiple files with Get-Content and Write-Host
        let cmd16 = vec_str(&[
            "pwsh",
            "-NoLogo",
            "-Command",
            "Write-Host \"# FILE: src/lib.rs\"; Get-Content src/lib.rs -TotalCount 250; Write-Host \"`n# FILE: src/app.rs (if exists)\"; if (Test-Path src/app.rs) { Get-Content src/app.rs -TotalCount 250 } else { Write-Host \"(no src/app.rs)\" }",
        ]);
        assert!(is_known_safe_command(&cmd16));

        // 17) Read a file with Get-Content and format output
        let cmd17 = vec_str(&[
            "pwsh",
            "-Command",
            "$path = 'core/src/is_safe_command.rs'; $c = Get-Content $path; $start=430; $end=540; for ($i=$start; $i -le $end -and $i -le $c.Length; $i++) { $num=$i; \"{0,4}: {1}\" -f $num, $c[$i-1] }",
        ]);
        assert!(is_known_safe_command(&cmd17));

        // 18) Ripgrep with context and search patterns
        let cmd18 = vec_str(&[
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "rg -n \"Spawn::Player|send\\(<Spawn|add_event::<Spawn>\" src -S",
        ]);
        assert!(is_known_safe_command(&cmd18));

        // 19) Get-ChildItem to find specific crates in Cargo registry
        let cmd19 = vec_str(&[
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "$cargoHome = \"$env:USERPROFILE\\.cargo\"; $src = Join-Path $cargoHome 'registry\\src'; Get-ChildItem $src -Directory | ForEach-Object { Get-ChildItem $_.FullName -Directory | Where-Object { $_.Name -like 'leafwing-input-manager-*' } } | Select-Object -ExpandProperty FullName",
        ]);
        assert!(is_known_safe_command(&cmd19));

        // 20) Get-ChildItem to list files in a specific crate
        let cmd20 = vec_str(&[
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "Get-ChildItem \"C:\\Users\\User\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\leafwing-input-manager-0.17.1\" | Select-Object Name",
        ]);
        assert!(is_known_safe_command(&cmd20));

        // 21) type (Get-Content) a single file
        let cmd21 = vec_str(&[
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "type mcp-client/src/mcp_client.rs",
        ]);
        assert!(is_known_safe_command(&cmd21));

        // 22) no type with bash
        let cmd22 = vec_str(&["bash", "-lc", "type mcp-client/src/mcp_client.rs"]);
        assert!(!is_known_safe_command(&cmd22));

        // 23) ripgrep with -g and -S in a specific directory
        let cmd23 = vec_str(&[
            "pwsh.exe",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "rg -n \"graalvm|wasm|shadowJar|polyglot\" -S -g \"plugin/**\"",
        ]);
        assert!(is_known_safe_command(&cmd23));

        // 24) Get-Content with -TotalCount
        let cmd24 = vec_str(&[
            "pwsh.exe",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "Get-Content plugin/build.gradle.kts -TotalCount 200",
        ]);
        assert!(is_known_safe_command(&cmd24));
    }

    #[test]
    fn powershell_read_only_examples_with_commands() {
        // 1) Cargo check command
        let cmd1 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "cargo check -p mycrate",
        ]);
        assert!(is_known_safe_command(&cmd1));

        // 2) Ripgrep command with context
        let cmd2 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "rg -n -C 10 \"fn is_powershell_read_only_script\" core/src/is_safe_command.rs; rg -n -C 10 \"try_extract_powershell_command_script\" core/src/is_safe_command.rs",
        ]);
        assert!(is_known_safe_command(&cmd2));
    }

    #[test]
    fn powershell_mutating_is_rejected() {
        let cmd = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "Remove-Item -Recurse -Force .\\foo",
        ]);
        assert!(!is_known_safe_command(&cmd));
    }

    #[test]
    fn powershell_mutating_with_aliases_is_rejected() {
        let cmd1 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "rm -Recurse -Force .\\foo",
        ]);
        assert!(!is_known_safe_command(&cmd1));

        let cmd2 = vec_str(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "cargo test -p mycrate -- --nocapture",
        ]);
        assert!(!is_known_safe_command(&cmd2));
    }

    #[test]
    fn bazel_commands_are_auto_approved() {
        assert!(is_known_safe_command(&vec_str(&[
            "bazel", "aquery", "//..."
        ])));
        assert!(is_known_safe_command(&vec_str(&[
            "bazel", "cquery", "//..."
        ])));
        assert!(is_known_safe_command(&vec_str(&["bazel", "info"])));
        assert!(is_known_safe_command(&vec_str(&[
            "bazel", "query", "//..."
        ])));

        // Complex bash -lc with bazel info and ls and rg
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "oot=$(bazel info execution_root) && ls -1 \"$root/external/+_repo_rules3+sysroot_linux_x86_64/usr/include/c++/13/bits\" | rg -n \"^c\\+\\+config\\.h$|^os_defines\\.h$|^cpu_defines\\.h$|^os\\.|c\\+\\+\" -n -S || true"
        ])));

        // Complex bash -lc with bazel info and find and sed
        assert!(is_known_safe_command(&vec_str(&[
            "bash",
            "-lc",
            "root=$(bazel info output_base)/sandbox/linux-sandbox/2761/execroot/_main && find \"$root\" -maxdepth 2 -type f -printf '%p\n' | sed -n '1,200p'"
        ])));
    }
    #[test]
    fn bazel_query_commands_are_not_auto_approved() {
        assert!(!is_known_safe_command(&vec_str(&[
            "bazel", "build", "//..."
        ])));
        assert!(!is_known_safe_command(&vec_str(&[
            "bazel", "clean", "//..."
        ])));
        assert!(!is_known_safe_command(&vec_str(&[
            "bazel", "fetch", "//..."
        ])));
        assert!(!is_known_safe_command(&vec_str(&["bazel", "run", "//..."])));
        assert!(!is_known_safe_command(&vec_str(&[
            "bazel", "test", "//..."
        ])));
        assert!(!is_known_safe_command(&vec_str(&[
            "bazel", "vendor", "//..."
        ])));
    }
}
