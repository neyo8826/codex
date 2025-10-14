use crate::bash::try_parse_bash;
use crate::bash::try_parse_word_only_commands_sequence;
use crate::powershell_utils::parse_cmd_exe_commands;
use crate::powershell_utils::parse_powershell_commands;
use codex_protocol::parse_command::ParsedCommand;
use shlex::split as shlex_split;
use shlex::try_join as shlex_try_join;
use std::path::PathBuf;

pub(crate) fn shlex_join(tokens: &[String]) -> String {
    shlex_try_join(tokens.iter().map(String::as_str))
        .unwrap_or_else(|_| "<command included NUL byte>".to_string())
}

/// DO NOT REVIEW THIS CODE BY HAND
/// This parsing code is quite complex and not easy to hand-modify.
/// The easiest way to iterate is to add unit tests and have Codex fix the implementation.
/// To encourage this, the tests have been put directly below this function rather than at the bottom of the
///
/// Parses metadata out of an arbitrary command.
/// These commands are model driven and could include just about anything.
/// The parsing is slightly lossy due to the ~infinite expressiveness of an arbitrary command.
/// The goal of the parsed metadata is to be able to provide the user with a human readable gis
/// of what it is doing.
pub fn parse_command(command: &[String]) -> Vec<ParsedCommand> {
    // Parse and then collapse consecutive duplicate commands to avoid redundant summaries.
    let parsed = parse_command_impl(command);
    let mut deduped: Vec<ParsedCommand> = Vec::with_capacity(parsed.len());
    for cmd in parsed.into_iter() {
        if deduped.last().is_some_and(|prev| prev == &cmd) {
            continue;
        }
        deduped.push(cmd);
    }
    deduped
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
/// Tests are at the top to encourage using TDD + Codex to fix the implementation.
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::string::ToString;

    fn shlex_split_safe(s: &str) -> Vec<String> {
        shlex_split(s).unwrap_or_else(|| s.split_whitespace().map(ToString::to_string).collect())
    }

    fn vec_str(args: &[&str]) -> Vec<String> {
        args.iter().map(ToString::to_string).collect()
    }

    #[track_caller]
    fn assert_parsed(args: &[String], expected: Vec<ParsedCommand>) {
        let out = parse_command(args);
        assert_eq!(out, expected);
    }

    #[test]
    fn git_status_is_unknown() {
        assert_parsed(
            &vec_str(&["git", "status"]),
            vec![ParsedCommand::Unknown {
                cmd: "git status".to_string(),
            }],
        );
    }

    #[test]
    fn handles_git_pipe_wc() {
        let inner = "git status | wc -l";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Unknown {
                cmd: "git status".to_string(),
            }],
        );
    }

    #[test]
    fn bash_lc_redirect_not_quoted() {
        let inner = "echo foo > bar";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Unknown {
                cmd: "echo foo > bar".to_string(),
            }],
        );
    }

    #[test]
    fn handles_complex_bash_command_head() {
        let inner =
            "rg --version && node -v && pnpm -v && rg --files | wc -l && rg --files | head -n 40";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![
                // Expect commands in left-to-right execution order
                ParsedCommand::Search {
                    cmd: "rg --version".to_string(),
                    query: None,
                    path: None,
                },
                ParsedCommand::Unknown {
                    cmd: "node -v".to_string(),
                },
                ParsedCommand::Unknown {
                    cmd: "pnpm -v".to_string(),
                },
                ParsedCommand::Search {
                    cmd: "rg --files".to_string(),
                    query: None,
                    path: None,
                },
                ParsedCommand::Unknown {
                    cmd: "head -n 40".to_string(),
                },
            ],
        );
    }

    #[test]
    fn supports_searching_for_navigate_to_route() -> anyhow::Result<()> {
        let inner = "rg -n \"navigate-to-route\" -S";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Search {
                cmd: "rg -n navigate-to-route -S".to_string(),
                query: Some("navigate-to-route".to_string()),
                path: None,
            }],
        );
        Ok(())
    }

    #[test]
    fn zsh_lc_matches_bash_parsing() {
        let inner = "rg -n \"navigate-to-route\" -S";
        let bash_args = vec_str(&["bash", "-lc", inner]);
        let zsh_args = vec_str(&["zsh", "-lc", inner]);
        assert_eq!(parse_command(&zsh_args), parse_command(&bash_args));
    }

    #[test]
    fn handles_complex_bash_command() {
        let inner = "rg -n \"BUG|FIXME|TODO|XXX|HACK\" -S | head -n 200";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![
                ParsedCommand::Search {
                    cmd: "rg -n 'BUG|FIXME|TODO|XXX|HACK' -S".to_string(),
                    query: Some("BUG|FIXME|TODO|XXX|HACK".to_string()),
                    path: None,
                },
                ParsedCommand::Unknown {
                    cmd: "head -n 200".to_string(),
                },
            ],
        );
    }

    #[test]
    fn supports_rg_files_with_path_and_pipe() {
        let inner = "rg --files webview/src | sed -n";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Search {
                cmd: "rg --files webview/src".to_string(),
                query: None,
                path: Some("webview".to_string()),
            }],
        );
    }

    #[test]
    fn supports_rg_files_then_head() {
        let inner = "rg --files | head -n 50";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![
                ParsedCommand::Search {
                    cmd: "rg --files".to_string(),
                    query: None,
                    path: None,
                },
                ParsedCommand::Unknown {
                    cmd: "head -n 50".to_string(),
                },
            ],
        );
    }

    #[test]
    fn supports_cat() {
        let inner = "cat webview/README.md";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Read {
                cmd: inner.to_string(),
                name: "README.md".to_string(),
                path: PathBuf::from("webview/README.md"),
            }],
        );
    }

    #[test]
    fn cd_then_cat_is_single_read() {
        assert_parsed(
            &shlex_split_safe("cd foo && cat foo.txt"),
            vec![ParsedCommand::Read {
                cmd: "cat foo.txt".to_string(),
                name: "foo.txt".to_string(),
                path: PathBuf::from("foo/foo.txt"),
            }],
        );
    }

    #[test]
    fn bash_cd_then_bar_is_same_as_bar() {
        // Ensure a leading `cd` inside bash -lc is dropped when followed by another command.
        assert_parsed(
            &shlex_split_safe("bash -lc 'cd foo && bar'"),
            vec![ParsedCommand::Unknown {
                cmd: "bar".to_string(),
            }],
        );
    }

    #[test]
    fn bash_cd_then_cat_is_read() {
        assert_parsed(
            &shlex_split_safe("bash -lc 'cd foo && cat foo.txt'"),
            vec![ParsedCommand::Read {
                cmd: "cat foo.txt".to_string(),
                name: "foo.txt".to_string(),
                path: PathBuf::from("foo/foo.txt"),
            }],
        );
    }

    #[test]
    fn supports_ls_with_pipe() {
        let inner = "ls -la | sed -n '1,120p'";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::ListFiles {
                cmd: "ls -la".to_string(),
                path: None,
            }],
        );
    }

    #[test]
    fn supports_head_n() {
        let inner = "head -n 50 Cargo.toml";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Read {
                cmd: inner.to_string(),
                name: "Cargo.toml".to_string(),
                path: PathBuf::from("Cargo.toml"),
            }],
        );
    }

    #[test]
    fn supports_cat_sed_n() {
        let inner = "cat tui/Cargo.toml | sed -n '1,200p'";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Read {
                cmd: inner.to_string(),
                name: "Cargo.toml".to_string(),
                path: PathBuf::from("tui/Cargo.toml"),
            }],
        );
    }

    #[test]
    fn supports_tail_n_plus() {
        let inner = "tail -n +522 README.md";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Read {
                cmd: inner.to_string(),
                name: "README.md".to_string(),
                path: PathBuf::from("README.md"),
            }],
        );
    }

    #[test]
    fn supports_tail_n_last_lines() {
        let inner = "tail -n 30 README.md";
        let out = parse_command(&vec_str(&["bash", "-lc", inner]));
        assert_eq!(
            out,
            vec![ParsedCommand::Read {
                cmd: inner.to_string(),
                name: "README.md".to_string(),
                path: PathBuf::from("README.md"),
            }]
        );
    }

    #[test]
    fn supports_npm_run_build_is_unknown() {
        assert_parsed(
            &vec_str(&["npm", "run", "build"]),
            vec![ParsedCommand::Unknown {
                cmd: "npm run build".to_string(),
            }],
        );
    }

    #[test]
    fn supports_grep_recursive_current_dir() {
        assert_parsed(
            &vec_str(&["grep", "-R", "CODEX_SANDBOX_ENV_VAR", "-n", "."]),
            vec![ParsedCommand::Search {
                cmd: "grep -R CODEX_SANDBOX_ENV_VAR -n .".to_string(),
                query: Some("CODEX_SANDBOX_ENV_VAR".to_string()),
                path: Some(".".to_string()),
            }],
        );
    }

    #[test]
    fn supports_grep_recursive_specific_file() {
        assert_parsed(
            &vec_str(&[
                "grep",
                "-R",
                "CODEX_SANDBOX_ENV_VAR",
                "-n",
                "core/src/spawn.rs",
            ]),
            vec![ParsedCommand::Search {
                cmd: "grep -R CODEX_SANDBOX_ENV_VAR -n core/src/spawn.rs".to_string(),
                query: Some("CODEX_SANDBOX_ENV_VAR".to_string()),
                path: Some("spawn.rs".to_string()),
            }],
        );
    }

    #[test]
    fn supports_grep_query_with_slashes_not_shortened() {
        // Query strings may contain slashes and should not be shortened to the basename.
        // Previously, grep queries were passed through short_display_path, which is incorrect.
        assert_parsed(
            &shlex_split_safe("grep -R src/main.rs -n ."),
            vec![ParsedCommand::Search {
                cmd: "grep -R src/main.rs -n .".to_string(),
                query: Some("src/main.rs".to_string()),
                path: Some(".".to_string()),
            }],
        );
    }

    #[test]
    fn supports_grep_weird_backtick_in_query() {
        assert_parsed(
            &shlex_split_safe("grep -R COD`EX_SANDBOX -n"),
            vec![ParsedCommand::Search {
                cmd: "grep -R 'COD`EX_SANDBOX' -n".to_string(),
                query: Some("COD`EX_SANDBOX".to_string()),
                path: None,
            }],
        );
    }

    #[test]
    fn supports_cd_and_rg_files() {
        assert_parsed(
            &shlex_split_safe("cd codex-rs && rg --files"),
            vec![ParsedCommand::Search {
                cmd: "rg --files".to_string(),
                query: None,
                path: None,
            }],
        );
    }

    // ---- is_small_formatting_command unit tests ----
    #[test]
    fn small_formatting_always_true_commands() {
        for cmd in [
            "wc", "tr", "cut", "sort", "uniq", "xargs", "tee", "column", "awk",
        ] {
            assert!(is_small_formatting_command(&shlex_split_safe(cmd)));
            assert!(is_small_formatting_command(&shlex_split_safe(&format!(
                "{cmd} -x"
            ))));
        }
    }

    #[test]
    fn head_behavior() {
        // No args -> small formatting
        assert!(is_small_formatting_command(&vec_str(&["head"])));
        // Numeric count only -> not considered small formatting by implementation
        assert!(!is_small_formatting_command(&shlex_split_safe(
            "head -n 40"
        )));
        // With explicit file -> not small formatting
        assert!(!is_small_formatting_command(&shlex_split_safe(
            "head -n 40 file.txt"
        )));
        // File only (no count) -> treated as small formatting by implementation
        assert!(is_small_formatting_command(&vec_str(&["head", "file.txt"])));
    }

    #[test]
    fn tail_behavior() {
        // No args -> small formatting
        assert!(is_small_formatting_command(&vec_str(&["tail"])));
        // Numeric with plus offset -> not small formatting
        assert!(!is_small_formatting_command(&shlex_split_safe(
            "tail -n +10"
        )));
        assert!(!is_small_formatting_command(&shlex_split_safe(
            "tail -n +10 file.txt"
        )));
        // Numeric count
        assert!(!is_small_formatting_command(&shlex_split_safe(
            "tail -n 30"
        )));
        assert!(!is_small_formatting_command(&shlex_split_safe(
            "tail -n 30 file.txt"
        )));
        // File only -> small formatting by implementation
        assert!(is_small_formatting_command(&vec_str(&["tail", "file.txt"])));
    }

    #[test]
    fn sed_behavior() {
        // Plain sed -> small formatting
        assert!(is_small_formatting_command(&vec_str(&["sed"])));
        // sed -n <range> (no file) -> still small formatting
        assert!(is_small_formatting_command(&vec_str(&["sed", "-n", "10p"])));
        // Valid range with file -> not small formatting
        assert!(!is_small_formatting_command(&shlex_split_safe(
            "sed -n 10p file.txt"
        )));
        assert!(!is_small_formatting_command(&shlex_split_safe(
            "sed -n 1,200p file.txt"
        )));
        // Invalid ranges with file -> small formatting
        assert!(is_small_formatting_command(&shlex_split_safe(
            "sed -n p file.txt"
        )));
        assert!(is_small_formatting_command(&shlex_split_safe(
            "sed -n +10p file.txt"
        )));
    }

    #[test]
    fn empty_tokens_is_not_small() {
        let empty: Vec<String> = Vec::new();
        assert!(!is_small_formatting_command(&empty));
    }

    #[test]
    fn supports_nl_then_sed_reading() {
        let inner = "nl -ba core/src/parse_command.rs | sed -n '1200,1720p'";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Read {
                cmd: inner.to_string(),
                name: "parse_command.rs".to_string(),
                path: PathBuf::from("core/src/parse_command.rs"),
            }],
        );
    }

    #[test]
    fn supports_sed_n() {
        let inner = "sed -n '2000,2200p' tui/src/history_cell.rs";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Read {
                cmd: inner.to_string(),
                name: "history_cell.rs".to_string(),
                path: PathBuf::from("tui/src/history_cell.rs"),
            }],
        );
    }

    #[test]
    fn filters_out_printf() {
        let inner =
            r#"printf "\n===== ansi-escape/Cargo.toml =====\n"; cat -- ansi-escape/Cargo.toml"#;
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Read {
                cmd: "cat -- ansi-escape/Cargo.toml".to_string(),
                name: "Cargo.toml".to_string(),
                path: PathBuf::from("ansi-escape/Cargo.toml"),
            }],
        );
    }

    #[test]
    fn drops_yes_in_pipelines() {
        // Inside bash -lc, `yes | rg --files` should focus on the primary command.
        let inner = "yes | rg --files";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Search {
                cmd: "rg --files".to_string(),
                query: None,
                path: None,
            }],
        );
    }

    #[test]
    fn supports_sed_n_then_nl_as_search() {
        // Ensure `sed -n '<range>' <file> | nl -ba` is summarized as a search for that file.
        let args = shlex_split_safe(
            "sed -n '260,640p' exec/src/event_processor_with_human_output.rs | nl -ba",
        );
        assert_parsed(
            &args,
            vec![ParsedCommand::Read {
                cmd: "sed -n '260,640p' exec/src/event_processor_with_human_output.rs".to_string(),
                name: "event_processor_with_human_output.rs".to_string(),
                path: PathBuf::from("exec/src/event_processor_with_human_output.rs"),
            }],
        );
    }

    #[test]
    fn preserves_rg_with_spaces() {
        assert_parsed(
            &shlex_split_safe("yes | rg -n 'foo bar' -S"),
            vec![ParsedCommand::Search {
                cmd: "rg -n 'foo bar' -S".to_string(),
                query: Some("foo bar".to_string()),
                path: None,
            }],
        );
    }

    #[test]
    fn ls_with_glob() {
        assert_parsed(
            &shlex_split_safe("ls -I '*.test.js'"),
            vec![ParsedCommand::ListFiles {
                cmd: "ls -I '*.test.js'".to_string(),
                path: None,
            }],
        );
    }

    #[test]
    fn trim_on_semicolon() {
        assert_parsed(
            &shlex_split_safe("rg foo ; echo done"),
            vec![
                ParsedCommand::Search {
                    cmd: "rg foo".to_string(),
                    query: Some("foo".to_string()),
                    path: None,
                },
                ParsedCommand::Unknown {
                    cmd: "echo done".to_string(),
                },
            ],
        );
    }

    #[test]
    fn split_on_or_connector() {
        // Ensure we split commands on the logical OR operator as well.
        assert_parsed(
            &shlex_split_safe("rg foo || echo done"),
            vec![
                ParsedCommand::Search {
                    cmd: "rg foo".to_string(),
                    query: Some("foo".to_string()),
                    path: None,
                },
                ParsedCommand::Unknown {
                    cmd: "echo done".to_string(),
                },
            ],
        );
    }

    #[test]
    fn parses_mixed_sequence_with_pipes_semicolons_and_or() {
        // Provided long command sequence combining sequencing, pipelines, and ORs.
        let inner = "pwd; ls -la; rg --files -g '!target' | wc -l; rg -n '^\\[workspace\\]' -n Cargo.toml || true; rg -n '^\\[package\\]' -n */Cargo.toml || true; cargo --version; rustc --version; cargo clippy --workspace --all-targets --all-features -q";
        let args = vec_str(&["bash", "-lc", inner]);

        let expected = vec![
            ParsedCommand::Unknown {
                cmd: "pwd".to_string(),
            },
            ParsedCommand::ListFiles {
                cmd: shlex_join(&shlex_split_safe("ls -la")),
                path: None,
            },
            ParsedCommand::Search {
                cmd: shlex_join(&shlex_split_safe("rg --files -g '!target'")),
                query: None,
                path: Some("!target".to_string()),
            },
            ParsedCommand::Search {
                cmd: shlex_join(&shlex_split_safe("rg -n '^\\[workspace\\]' -n Cargo.toml")),
                query: Some("^\\[workspace\\]".to_string()),
                path: Some("Cargo.toml".to_string()),
            },
            ParsedCommand::Search {
                cmd: shlex_join(&shlex_split_safe("rg -n '^\\[package\\]' -n */Cargo.toml")),
                query: Some("^\\[package\\]".to_string()),
                path: Some("Cargo.toml".to_string()),
            },
            ParsedCommand::Unknown {
                cmd: shlex_join(&shlex_split_safe("cargo --version")),
            },
            ParsedCommand::Unknown {
                cmd: shlex_join(&shlex_split_safe("rustc --version")),
            },
            ParsedCommand::Unknown {
                cmd: shlex_join(&shlex_split_safe(
                    "cargo clippy --workspace --all-targets --all-features -q",
                )),
            },
        ];

        assert_parsed(&args, expected);
    }

    #[test]
    fn strips_true_in_sequence() {
        // `true` should be dropped from parsed sequences
        assert_parsed(
            &shlex_split_safe("true && rg --files"),
            vec![ParsedCommand::Search {
                cmd: "rg --files".to_string(),
                query: None,
                path: None,
            }],
        );

        assert_parsed(
            &shlex_split_safe("rg --files && true"),
            vec![ParsedCommand::Search {
                cmd: "rg --files".to_string(),
                query: None,
                path: None,
            }],
        );
    }

    #[test]
    fn strips_true_inside_bash_lc() {
        let inner = "true && rg --files";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner]),
            vec![ParsedCommand::Search {
                cmd: "rg --files".to_string(),
                query: None,
                path: None,
            }],
        );

        let inner2 = "rg --files || true";
        assert_parsed(
            &vec_str(&["bash", "-lc", inner2]),
            vec![ParsedCommand::Search {
                cmd: "rg --files".to_string(),
                query: None,
                path: None,
            }],
        );
    }

    #[test]
    fn shorten_path_on_windows() {
        assert_parsed(
            &shlex_split_safe(r#"cat "pkg\src\main.rs""#),
            vec![ParsedCommand::Read {
                cmd: r#"cat "pkg\\src\\main.rs""#.to_string(),
                name: "main.rs".to_string(),
                path: PathBuf::from(r#"pkg\src\main.rs"#),
            }],
        );
    }

    #[test]
    fn head_with_no_space() {
        assert_parsed(
            &shlex_split_safe("bash -lc 'head -n50 Cargo.toml'"),
            vec![ParsedCommand::Read {
                cmd: "head -n50 Cargo.toml".to_string(),
                name: "Cargo.toml".to_string(),
                path: PathBuf::from("Cargo.toml"),
            }],
        );
    }

    #[test]
    fn bash_dash_c_pipeline_parsing() {
        // Ensure -c is handled similarly to -lc by normalization
        let inner = "rg --files | head -n 1";
        assert_parsed(
            &shlex_split_safe(inner),
            vec![
                ParsedCommand::Search {
                    cmd: "rg --files".to_string(),
                    query: None,
                    path: None,
                },
                ParsedCommand::Unknown {
                    cmd: "head -n 1".to_string(),
                },
            ],
        );
    }

    #[test]
    fn tail_with_no_space() {
        assert_parsed(
            &shlex_split_safe("bash -lc 'tail -n+10 README.md'"),
            vec![ParsedCommand::Read {
                cmd: "tail -n+10 README.md".to_string(),
                name: "README.md".to_string(),
                path: PathBuf::from("README.md"),
            }],
        );
    }

    #[test]
    fn grep_with_query_and_path() {
        assert_parsed(
            &shlex_split_safe("grep -R TODO src"),
            vec![ParsedCommand::Search {
                cmd: "grep -R TODO src".to_string(),
                query: Some("TODO".to_string()),
                path: Some("src".to_string()),
            }],
        );
    }

    #[test]
    fn rg_with_equals_style_flags() {
        assert_parsed(
            &shlex_split_safe("rg --colors=never -n foo src"),
            vec![ParsedCommand::Search {
                cmd: "rg '--colors=never' -n foo src".to_string(),
                query: Some("foo".to_string()),
                path: Some("src".to_string()),
            }],
        );
    }

    #[test]
    fn cat_with_double_dash_and_sed_ranges() {
        // cat -- <file> should be treated as a read of that file
        assert_parsed(
            &shlex_split_safe("cat -- ./-strange-file-name"),
            vec![ParsedCommand::Read {
                cmd: "cat -- ./-strange-file-name".to_string(),
                name: "-strange-file-name".to_string(),
                path: PathBuf::from("./-strange-file-name"),
            }],
        );

        // sed -n <range> <file> should be treated as a read of <file>
        assert_parsed(
            &shlex_split_safe("sed -n '12,20p' Cargo.toml"),
            vec![ParsedCommand::Read {
                cmd: "sed -n '12,20p' Cargo.toml".to_string(),
                name: "Cargo.toml".to_string(),
                path: PathBuf::from("Cargo.toml"),
            }],
        );
    }

    #[test]
    fn drop_trailing_nl_in_pipeline() {
        // When an `nl` stage has only flags, it should be dropped from the summary
        assert_parsed(
            &shlex_split_safe("rg --files | nl -ba"),
            vec![ParsedCommand::Search {
                cmd: "rg --files".to_string(),
                query: None,
                path: None,
            }],
        );
    }

    #[test]
    fn ls_with_time_style_and_path() {
        assert_parsed(
            &shlex_split_safe("ls --time-style=long-iso ./dist"),
            vec![ParsedCommand::ListFiles {
                cmd: "ls '--time-style=long-iso' ./dist".to_string(),
                // short_display_path drops "dist" and shows "." as the last useful segment
                path: Some(".".to_string()),
            }],
        );
    }

    #[test]
    fn fd_file_finder_variants() {
        assert_parsed(
            &shlex_split_safe("fd -t f src/"),
            vec![ParsedCommand::Search {
                cmd: "fd -t f src/".to_string(),
                query: None,
                path: Some("src".to_string()),
            }],
        );

        // fd with query and path should capture both
        assert_parsed(
            &shlex_split_safe("fd main src"),
            vec![ParsedCommand::Search {
                cmd: "fd main src".to_string(),
                query: Some("main".to_string()),
                path: Some("src".to_string()),
            }],
        );
    }

    #[test]
    fn find_basic_name_filter() {
        assert_parsed(
            &shlex_split_safe("find . -name '*.rs'"),
            vec![ParsedCommand::Search {
                cmd: "find . -name '*.rs'".to_string(),
                query: Some("*.rs".to_string()),
                path: Some(".".to_string()),
            }],
        );
    }

    #[test]
    fn find_type_only_path() {
        assert_parsed(
            &shlex_split_safe("find src -type f"),
            vec![ParsedCommand::Search {
                cmd: "find src -type f".to_string(),
                query: None,
                path: Some("src".to_string()),
            }],
        );
    }

    #[test]
    fn powershell_select_string_basic() {
        assert_parsed(
            &vec_str(&["powershell", "-Command", "Select-String -Pattern 'TODO'"]),
            vec![ParsedCommand::Search {
                cmd: "Select-String -Pattern 'TODO'".to_string(),
                query: Some("TODO".to_string()),
                path: None,
            }],
        );
    }
    #[test]
    fn powershell_get_childitem_with_path() {
        assert_parsed(
            &vec_str(&[
                "powershell",
                "-Command",
                "Get-ChildItem -Path 'C\\project\\src' -Recurse",
            ]),
            vec![ParsedCommand::Search {
                cmd: "Get-ChildItem -Path 'C\\project\\src' -Recurse".to_string(),
                query: None,
                path: Some("project".to_string()),
            }],
        );
    }
    #[test]
    fn powershell_get_content_read_file() {
        assert_parsed(
            &vec_str(&["powershell", "-Command", "Get-Content -Path '.\\README.md'"]),
            vec![ParsedCommand::Read {
                cmd: "Get-Content -Path '.\\README.md'".to_string(),
                name: "README.md".to_string(),
                path: PathBuf::from(".\\README.md"),
            }],
        );
    }
    #[test]
    fn powershell_get_content_with_range() {
        assert_parsed(
            &vec_str(&["powershell", "-Command", "$f='C:\\Users\\User\\.cargo\\registry\\src\\...\\virt.rs'; $c=Get-Content $f; $c[80..120]"]),
            vec![ParsedCommand::Read {
                cmd: "$f='C:\\Users\\User\\.cargo\\registry\\src\\...\\virt.rs'; $c=Get-Content $f; $c[80..120]".to_string(),
                name: "virt.rs".to_string(),
                path: PathBuf::from("C:\\Users\\User\\.cargo\\registry\\src\\...\\virt.rs"),
            }],
        );
    }
    #[test]
    fn powershell_get_content_with_select_string() {
        assert_parsed(
            &vec_str(&["powershell", "-Command", "$f='C:\\Users\\User\\.cargo\\registry\\src\\...\\time.rs'; Get-Content $f | Select-String -Pattern 'advance_by|from_millis(500)|MAX' -Context 2,2 | ForEach-Object { $_ }"]),
            vec![ParsedCommand::Read {
                cmd: "$f='C:\\Users\\User\\.cargo\\registry\\src\\...\\time.rs'; Get-Content $f | Select-String -Pattern 'advance_by|from_millis(500)|MAX' -Context 2,2 | ForEach-Object { $_ }".to_string(),
                name: "time.rs".to_string(),
                path: PathBuf::from("C:\\Users\\User\\.cargo\\registry\\src\\...\\time.rs"),
            }],
        );
    }
    #[test]
    fn powershell_get_content_with_range_and_join() {
        assert_parsed(
            &vec_str(&["powershell", "-Command", "$c = Get-Content core/src/is_safe_command.rs; $start=460; $end=520; $c[($start-1)..($end-1)] -join \"`n\""]),
            vec![ParsedCommand::Read {
                cmd: "$c = Get-Content core/src/is_safe_command.rs; $start=460; $end=520; $c[($start-1)..($end-1)] -join \"`n\"".to_string(),
                name: "is_safe_command.rs".to_string(),
                path: PathBuf::from("core/src/is_safe_command.rs"),
            }],
        );
    }
    #[test]
    fn powershell_get_content_with_select_object() {
        assert_parsed(
            &vec_str(&["powershell", "-Command", "Get-Content -Path src/character.rs -TotalCount 800 | Select-Object -Index ((520-1)..(800-1)) | Out-String"]),
            vec![ParsedCommand::Read {
                cmd: "Get-Content -Path src/character.rs -TotalCount 800 | Select-Object -Index ((520-1)..(800-1)) | Out-String".to_string(),
                name: "character.rs".to_string(),
                path: PathBuf::from("src/character.rs"),
            }],
        );
    }
    #[test]
    fn powershell_get_childitem_with_where_object() {
        assert_parsed(
            &vec_str(&["powershell", "-Command", "Get-ChildItem -Recurse -File | Where-Object {$_.Name -match '\"mod\\\\.rs\"'} | Select-Object -Expand FullName"]),
            vec![ParsedCommand::Search {
                cmd: "Get-ChildItem -Recurse -File | Where-Object {$_.Name -match '\"mod\\\\.rs\"'} | Select-Object -Expand FullName".to_string(),
                path: None,
                query: Some("mod.rs".to_string()),
            }],
        );
    }
    #[test]
    fn powershell_get_content_multiple_files() {
        assert_parsed(
            &vec_str(&["powershell", "-Command",  "Get-Content -Path multiplayer/Cargo.toml, doc/README.md, singleplayer/Cargo.toml -Raw | Write-Output"]),
            vec![
                ParsedCommand::Read {
                    cmd: "Get-Content -Path multiplayer/Cargo.toml, doc/README.md, singleplayer/Cargo.toml -Raw | Write-Output".to_string(),
                    name: "Cargo.toml".to_string(),
                    path: PathBuf::from("multiplayer/Cargo.toml"),
                },
                ParsedCommand::Read {
                    cmd: "Get-Content -Path multiplayer/Cargo.toml, doc/README.md, singleplayer/Cargo.toml -Raw | Write-Output".to_string(),
                    name: "README.md".to_string(),
                    path: PathBuf::from("doc/README.md"),
                },
            ],
        );
    }
    #[test]
    fn powershell_cargo_fmt_and_test() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-Command",
                "cargo fmt && cargo test -p codex-core -- --nocapture",
            ]),
            vec![
                ParsedCommand::Unknown {
                    cmd: "cargo fmt".to_string(),
                },
                ParsedCommand::Unknown {
                    cmd: "cargo test -p codex-core -- --nocapture".to_string(),
                },
            ],
        );
    }
    #[test]
    fn powershell_ripgrep() {
        assert_parsed(
            &vec_str(&["pwsh", "-Command", "rg -n 'a b' -g '*.rs' -g '*.md' src"]),
            vec![ParsedCommand::Search {
                cmd: "rg -n 'a b' -g '*.rs' -g '*.md' src".to_string(),
                query: Some("a b".to_string()),
                path: Some("src".to_string()),
            }],
        );
    }
    #[test]
    fn powershell_ripgrep_with_select_object() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "rg -n 'test_dash|dash' src | Select-Object -First 200",
            ]),
            vec![ParsedCommand::Search {
                cmd: "rg -n 'test_dash|dash' src | Select-Object -First 200".to_string(),
                query: Some("test_dash|dash".to_string()),
                path: Some("src".to_string()),
            }],
        );
    }
    #[test]
    fn powershell_get_content_with_select_object_last() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "Get-Content -Path src/character.rs -TotalCount 800 | Select-Object -Last 260",
            ]),
            vec![ParsedCommand::Read {
                cmd: "Get-Content -Path src/character.rs -TotalCount 800 | Select-Object -Last 260"
                    .to_string(),
                name: "character.rs".to_string(),
                path: PathBuf::from("src/character.rs"),
            }],
        );
    }
    #[test]
    fn powershell_select_string_with_for_each_object() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-c",
                "Select-String -Path core/src/parse_command.rs -Pattern powershell,pwsh -SimpleMatch | ForEach-Object { \"{0}:{1}\" -f $_.LineNumber, $_.Line }",
            ]),
            vec![ParsedCommand::Search {
                cmd: "Select-String -Path core/src/parse_command.rs -Pattern powershell,pwsh -SimpleMatch | ForEach-Object { \"{0}:{1}\" -f $_.LineNumber, $_.Line }"
                    .to_string(),
                query: Some("powershell,pwsh".to_string()),
                path: Some("parse_command.rs".to_string()),
            }],
        );
    }
    #[test]
    fn powershell_ripgrep_with_file() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-c",
                "rg -n \"asd asd\" \"C:\\Users\\User\\myfile.txt\" -S",
            ]),
            vec![ParsedCommand::Search {
                cmd: "rg -n \"asd asd\" \"C:\\Users\\User\\myfile.txt\" -S".to_string(),
                query: Some("asd asd".to_string()),
                path: Some("myfile.txt".to_string()),
            }],
        );
    }
    #[test]
    fn powershell_ripgrep_with_file_variable() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-c",
                "$file = \"C:\\Users\\User\\myfile.txt\"; rg -n \"asd asd\" $file -S",
            ]),
            vec![ParsedCommand::Search {
                cmd: "rg -n \"asd asd\" C:\\Users\\User\\myfile.txt -S".to_string(),
                query: Some("asd asd".to_string()),
                path: Some("myfile.txt".to_string()),
            }],
        );
    }
    #[test]
    fn powershell_get_content_with_for_each_object() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-NoLogo",
                "-NoProfile",
                "-c",
                "$c = Get-Content core/src/is_safe_command.rs; for ($i=120; $i -le 180 -and $i -lt $c.Length; $i++) { $num=$i+1; Write-Output (\"{0,4}: {1}\" -f $num, $c[$i]) }",
            ]),
            vec![ParsedCommand::Read {
                cmd: "$c = Get-Content core/src/is_safe_command.rs; for ($i=120; $i -le 180 -and $i -lt $c.Length; $i++) { $num=$i+1; Write-Output (\"{0,4}: {1}\" -f $num, $c[$i]) }"
                    .to_string(),
                name: "is_safe_command.rs".to_string(),
                path: PathBuf::from("core/src/is_safe_command.rs"),
            }],
        );
    }
    #[test]
    fn powershell_get_content_with_select_object_first() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-c",
                "(Get-Content core/src/parse_command.rs | Select-Object -First 220) -join \"`n\"",
            ]),
            vec![ParsedCommand::Read {
                cmd: "(Get-Content core/src/parse_command.rs | Select-Object -First 220) -join \"`n\"".to_string(),
                name: "parse_command.rs".to_string(),
                path: PathBuf::from("core/src/parse_command.rs"),
            }],
        );
    }
    #[test]
    fn pwsh_short_flag_variants() {
        assert_parsed(
            &vec_str(&["pwsh", "-c", "Get-Content 'C:\\file.txt'"]),
            vec![ParsedCommand::Read {
                cmd: "Get-Content 'C:\\file.txt'".to_string(),
                name: "file.txt".to_string(),
                path: PathBuf::from("C:\\file.txt"),
            }],
        );
    }
    #[test]
    fn powershell_command_with_cargo_check() {
        assert_parsed(
            &vec_str(&[
                "powershell",
                "-NoProfile",
                "-Command",
                "cargo check -p mycrate",
            ]),
            vec![ParsedCommand::Unknown {
                cmd: "cargo check -p mycrate".to_string(),
            }],
        );
    }
    #[test]
    fn powershell_command_with_cargo_test() {
        assert_parsed(
            &vec_str(&[
                "powershell",
                "-NoProfile",
                "-Command",
                "cargo test -p mycrate",
            ]),
            vec![ParsedCommand::Unknown {
                cmd: "cargo test -p mycrate".to_string(),
            }],
        );
    }
    #[test]
    fn powershell_read_file_with_type() {
        assert_parsed(
            &vec_str(&["pwsh", "-Command", "type mcp-client/src/mcp_client.rs"]),
            vec![ParsedCommand::Read {
                cmd: "type mcp-client/src/mcp_client.rs".to_string(),
                name: "mcp_client.rs".to_string(),
                path: PathBuf::from("mcp-client/src/mcp_client.rs"),
            }],
        );
    }
    #[test]
    fn powershell_read_file_in_chunks() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-Command",
                "$lines = Get-Content src/game2d.rs; $lines.Count; $start=1; while ($start -le $lines.Count) { Write-Host \"--- src/game2d.rs lines $start..$([Math]::Min($start+199,$lines.Count)) ---\"; $lines[$start-1..([Math]::Min($start+199,$lines.Count)-1)]; $start += 200 }",
            ]),
            vec![ParsedCommand::Read {
                cmd: "$lines = Get-Content src/game2d.rs; $lines.Count; $start=1; while ($start -le $lines.Count) { Write-Host \"--- src/game2d.rs lines $start..$([Math]::Min($start+199,$lines.Count)) ---\"; $lines[$start-1..([Math]::Min($start+199,$lines.Count)-1)]; $start += 200 }".to_string(),
                name: "game2d.rs".to_string(),
                path: PathBuf::from("src/game2d.rs"),
            }],
        );
    }
    #[test]
    fn powershell_read_file_with_measure_object() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-Command",
                "Get-Content src/map.rs | Measure-Object -Line | % Lines; Get-Content src/map.rs | Select-Object -First 260; echo '...'; Get-Content src/map.rs | Select-Object -Skip 260 -First 260",
            ]),
            vec![ParsedCommand::Read {
                cmd: "Get-Content src/map.rs | Measure-Object -Line | % Lines; Get-Content src/map.rs | Select-Object -First 260; echo '...'; Get-Content src/map.rs | Select-Object -Skip 260 -First 260".to_string(),
                name: "map.rs".to_string(),
                path: PathBuf::from("src/map.rs"),
            }],
        );
    }
    #[test]
    fn powershell_read_multiple_files_with_get_content() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-NoLogo",
                "-Command",
                "Write-Host \"# FILE: src/lib.rs\"; Get-Content src/lib.rs -TotalCount 250; Write-Host \"`n# FILE: src/app.rs (if exists)\"; if (Test-Path src/app.rs) { Get-Content src/app.rs -TotalCount 250 } else { Write-Host \"(no src/app.rs)\" }",
            ]),
            vec![
                ParsedCommand::Read {
                    cmd: "Write-Host \"# FILE: src/lib.rs\"; Get-Content src/lib.rs -TotalCount 250; Write-Host \"`n# FILE: src/app.rs (if exists)\"; if (Test-Path src/app.rs) { Get-Content src/app.rs -TotalCount 250 } else { Write-Host \"(no src/app.rs)\" }".to_string(),
                    name: "lib.rs".to_string(),
                    path: PathBuf::from("src/lib.rs"),
                },
                ParsedCommand::Read {
                    cmd: "Write-Host \"# FILE: src/lib.rs\"; Get-Content src/lib.rs -TotalCount 250; Write-Host \"`n# FILE: src/app.rs (if exists)\"; if (Test-Path src/app.rs) { Get-Content src/app.rs -TotalCount 250 } else { Write-Host \"(no src/app.rs)\" }".to_string(),
                    name: "app.rs".to_string(),
                    path: PathBuf::from("src/app.rs"),
                },
            ],
        );
    }
    #[test]
    fn powershell_read_file_with_get_content_and_range() {
        assert_parsed(
            &vec_str(&[
                "pwsh",
                "-Command",
                "$path = 'core/src/is_safe_command.rs'; $c = Get-Content $path; $start=430; $end=540; for ($i=$start; $i -le $end -and $i -le $c.Length; $i++) { $num=$i; \"{0,4}: {1}\" -f $num, $c[$i-1] }",
            ]),
            vec![ParsedCommand::Read {
                cmd: "$path = 'core/src/is_safe_command.rs'; $c = Get-Content $path; $start=430; $end=540; for ($i=$start; $i -le $end -and $i -le $c.Length; $i++) { $num=$i; \"{0,4}: {1}\" -f $num, $c[$i-1] }".to_string(),
                name: "is_safe_command.rs".to_string(),
                path: PathBuf::from("core/src/is_safe_command.rs"),
            }],
        );
    }

    #[test]
    fn cmd_type_reads_file() {
        assert_parsed(
            &vec_str(&["cmd.exe", "/c", "type README.md"]),
            vec![ParsedCommand::Read {
                cmd: "cmd.exe /c type README.md".to_string(),
                name: "README.md".to_string(),
                path: PathBuf::from("README.md"),
            }],
        );
    }
    #[test]
    fn cmd_findstr_searches_query() {
        assert_parsed(
            &vec_str(&["cmd.exe", "/c", "findstr /n \"TODO\" ."]),
            vec![ParsedCommand::Search {
                cmd: "cmd.exe /c findstr /n \"TODO\" .".to_string(),
                query: Some("TODO".to_string()),
                path: None,
            }],
        );
    }
    #[test]
    fn cmd_dir_lists_files() {
        assert_parsed(
            &vec_str(&["cmd", "/c", "dir ."]),
            vec![ParsedCommand::ListFiles {
                cmd: "cmd /c dir .".to_string(),
                path: None,
            }],
        );
    }
}

pub fn parse_command_impl(command: &[String]) -> Vec<ParsedCommand> {
    if let Some(commands) = parse_bash_lc_commands(command) {
        return commands;
    }
    if let Some(commands) = parse_powershell_commands(command) {
        return commands;
    }
    if let Some(commands) = parse_cmd_exe_commands(command) {
        return commands;
    }

    let normalized = normalize_tokens(command);

    let parts = if contains_connectors(&normalized) {
        split_on_connectors(&normalized)
    } else {
        vec![normalized]
    };

    // Preserve left-to-right execution order for all commands, including bash -c/-lc
    // so summaries reflect the order they will run.

    // Map each pipeline segment to its parsed summary, tracking `cd` to compute paths.
    let mut commands: Vec<ParsedCommand> = Vec::new();
    let mut cwd: Option<String> = None;
    for tokens in &parts {
        if let Some((head, tail)) = tokens.split_first()
            && head == "cd"
        {
            if let Some(dir) = tail.first() {
                cwd = Some(match &cwd {
                    Some(base) => join_paths(base, dir),
                    None => dir.clone(),
                });
            }
            continue;
        }
        let parsed = summarize_main_tokens(tokens);
        let parsed = match parsed {
            ParsedCommand::Read { cmd, name, path } => {
                if let Some(base) = &cwd {
                    let full = join_paths(base, &path.to_string_lossy());
                    ParsedCommand::Read {
                        cmd,
                        name,
                        path: PathBuf::from(full),
                    }
                } else {
                    ParsedCommand::Read { cmd, name, path }
                }
            }
            other => other,
        };
        commands.push(parsed);
    }

    while let Some(next) = simplify_once(&commands) {
        commands = next;
    }

    commands
}

pub(crate) fn simplify_once(commands: &[ParsedCommand]) -> Option<Vec<ParsedCommand>> {
    if commands.len() <= 1 {
        return None;
    }

    // echo ... && ...rest => ...rest
    if let ParsedCommand::Unknown { cmd } = &commands[0]
        && shlex_split(cmd).is_some_and(|t| t.first().map(String::as_str) == Some("echo"))
    {
        return Some(commands[1..].to_vec());
    }

    // cd foo && [any command] => [any command] (keep non-cd when a cd is followed by something)
    if let Some(idx) = commands.iter().position(|pc| match pc {
        ParsedCommand::Unknown { cmd } => {
            shlex_split(cmd).is_some_and(|t| t.first().map(String::as_str) == Some("cd"))
        }
        _ => false,
    }) && commands.len() > idx + 1
    {
        let mut out = Vec::with_capacity(commands.len() - 1);
        out.extend_from_slice(&commands[..idx]);
        out.extend_from_slice(&commands[idx + 1..]);
        return Some(out);
    }

    // cmd || true => cmd
    if let Some(idx) = commands
        .iter()
        .position(|pc| matches!(pc, ParsedCommand::Unknown { cmd } if cmd == "true"))
    {
        let mut out = Vec::with_capacity(commands.len() - 1);
        out.extend_from_slice(&commands[..idx]);
        out.extend_from_slice(&commands[idx + 1..]);
        return Some(out);
    }

    // nl -[any_flags] && ...rest => ...rest
    if let Some(idx) = commands.iter().position(|pc| match pc {
        ParsedCommand::Unknown { cmd } => {
            if let Some(tokens) = shlex_split(cmd) {
                tokens.first().is_some_and(|s| s.as_str() == "nl")
                    && tokens.iter().skip(1).all(|t| t.starts_with('-'))
            } else {
                false
            }
        }
        _ => false,
    }) {
        let mut out = Vec::with_capacity(commands.len() - 1);
        out.extend_from_slice(&commands[..idx]);
        out.extend_from_slice(&commands[idx + 1..]);
        return Some(out);
    }

    None
}

/// Validates that this is a `sed -n 123,123p` command.
fn is_valid_sed_n_arg(arg: Option<&str>) -> bool {
    let s = match arg {
        Some(s) => s,
        None => return false,
    };
    let core = match s.strip_suffix('p') {
        Some(rest) => rest,
        None => return false,
    };
    let parts: Vec<&str> = core.split(',').collect();
    match parts.as_slice() {
        [num] => !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()),
        [a, b] => {
            !a.is_empty()
                && !b.is_empty()
                && a.chars().all(|c| c.is_ascii_digit())
                && b.chars().all(|c| c.is_ascii_digit())
        }
        _ => false,
    }
}

/// Normalize a command by:
/// - Removing `yes`/`no`/`bash -c`/`bash -lc` prefixes.
/// - Splitting on `|` and `&&`/`||`/`;
fn normalize_tokens(cmd: &[String]) -> Vec<String> {
    match cmd {
        [first, pipe, rest @ ..] if (first == "yes" || first == "y") && pipe == "|" => {
            // Do not re-shlex already-tokenized input; just drop the prefix.
            rest.to_vec()
        }
        [first, pipe, rest @ ..] if (first == "no" || first == "n") && pipe == "|" => {
            // Do not re-shlex already-tokenized input; just drop the prefix.
            rest.to_vec()
        }
        [shell, flag, script]
            if (shell == "bash" || shell == "zsh") && (flag == "-c" || flag == "-lc") =>
        {
            shlex_split(script).unwrap_or_else(|| vec![shell.clone(), flag.clone(), script.clone()])
        }
        _ => cmd.to_vec(),
    }
}

fn contains_connectors(tokens: &[String]) -> bool {
    tokens
        .iter()
        .any(|t| t == "&&" || t == "||" || t == "|" || t == ";")
}

fn split_on_connectors(tokens: &[String]) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    for t in tokens {
        if t == "&&" || t == "||" || t == "|" || t == ";" {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(t.clone());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn trim_at_connector(tokens: &[String]) -> Vec<String> {
    let idx = tokens
        .iter()
        .position(|t| t == "|" || t == "&&" || t == "||" || t == ";")
        .unwrap_or(tokens.len());
    tokens[..idx].to_vec()
}

/// Shorten a path to the last component, excluding `build`/`dist`/`node_modules`/`src`.
/// It also pulls out a useful path from a directory such as:
/// - webview/src -> webview
/// - foo/src/ -> foo
/// - packages/app/node_modules/ -> app
pub(crate) fn short_display_path(path: &str) -> String {
    // Normalize separators and drop any trailing slash for display.
    let normalized = path.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    let mut parts = trimmed.split('/').rev().filter(|p| {
        !p.is_empty() && *p != "build" && *p != "dist" && *p != "node_modules" && *p != "src"
    });
    parts
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| trimmed.to_string())
}

// Skip values consumed by specific flags and ignore --flag=value style arguments.
fn skip_flag_values<'a>(args: &'a [String], flags_with_vals: &[&str]) -> Vec<&'a String> {
    let mut out: Vec<&'a String> = Vec::new();
    let mut skip_next = false;
    for (i, a) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a == "--" {
            // From here on, everything is positional operands; push the rest and break.
            for rest in &args[i + 1..] {
                out.push(rest);
            }
            break;
        }
        if a.starts_with("--") && a.contains('=') {
            // --flag=value form: treat as a flag taking a value; skip entirely.
            continue;
        }
        if flags_with_vals.contains(&a.as_str()) {
            // This flag consumes the next argument as its value.
            if i + 1 < args.len() {
                skip_next = true;
            }
            continue;
        }
        out.push(a);
    }
    out
}

fn is_pathish(s: &str) -> bool {
    s == "."
        || s == ".."
        || s.starts_with("./")
        || s.starts_with("../")
        || s.contains('/')
        || s.contains('\\')
}

fn parse_fd_query_and_path(tail: &[String]) -> (Option<String>, Option<String>) {
    let args_no_connector = trim_at_connector(tail);
    // fd has several flags that take values (e.g., -t/--type, -e/--extension).
    // Skip those values when extracting positional operands.
    let candidates = skip_flag_values(
        &args_no_connector,
        &[
            "-t",
            "--type",
            "-e",
            "--extension",
            "-E",
            "--exclude",
            "--search-path",
        ],
    );
    let non_flags: Vec<&String> = candidates
        .into_iter()
        .filter(|p| !p.starts_with('-'))
        .collect();
    match non_flags.as_slice() {
        [one] => {
            if is_pathish(one) {
                (None, Some(short_display_path(one)))
            } else {
                (Some((*one).clone()), None)
            }
        }
        [q, p, ..] => (Some((*q).clone()), Some(short_display_path(p))),
        _ => (None, None),
    }
}

fn parse_find_query_and_path(tail: &[String]) -> (Option<String>, Option<String>) {
    let args_no_connector = trim_at_connector(tail);
    // First positional argument (excluding common unary operators) is the root path
    let mut path: Option<String> = None;
    for a in &args_no_connector {
        if !a.starts_with('-') && *a != "!" && *a != "(" && *a != ")" {
            path = Some(short_display_path(a));
            break;
        }
    }
    // Extract a common name/path/regex pattern if present
    let mut query: Option<String> = None;
    let mut i = 0;
    while i < args_no_connector.len() {
        let a = &args_no_connector[i];
        if a == "-name" || a == "-iname" || a == "-path" || a == "-regex" {
            if i + 1 < args_no_connector.len() {
                query = Some(args_no_connector[i + 1].clone());
            }
            break;
        }
        i += 1;
    }
    (query, path)
}

fn parse_bash_lc_commands(original: &[String]) -> Option<Vec<ParsedCommand>> {
    let [bash, flag, script] = original else {
        return None;
    };
    if bash != "bash" || flag != "-lc" {
        return None;
    }
    if let Some(tree) = try_parse_bash(script)
        && let Some(all_commands) = try_parse_word_only_commands_sequence(&tree, script)
        && !all_commands.is_empty()
    {
        let script_tokens = shlex_split(script)
            .unwrap_or_else(|| vec!["bash".to_string(), flag.clone(), script.clone()]);
        // Strip small formatting helpers (e.g., head/tail/awk/wc/etc) so we
        // bias toward the primary command when pipelines are present.
        // First, drop obvious small formatting helpers (e.g., wc/awk/etc).
        let had_multiple_commands = all_commands.len() > 1;
        // Commands arrive in source order; drop formatting helpers while preserving it.
        let filtered_commands = drop_small_formatting_commands(all_commands);
        if filtered_commands.is_empty() {
            return Some(vec![ParsedCommand::Unknown {
                cmd: script.clone(),
            }]);
        }
        // Build parsed commands, tracking `cd` segments to compute effective file paths.
        let mut commands: Vec<ParsedCommand> = Vec::new();
        let mut cwd: Option<String> = None;
        for tokens in filtered_commands.into_iter() {
            if let Some((head, tail)) = tokens.split_first()
                && head == "cd"
            {
                if let Some(dir) = tail.first() {
                    cwd = Some(match &cwd {
                        Some(base) => join_paths(base, dir),
                        None => dir.clone(),
                    });
                }
                continue;
            }
            let parsed = summarize_main_tokens(&tokens);
            let parsed = match parsed {
                ParsedCommand::Read { cmd, name, path } => {
                    if let Some(base) = &cwd {
                        let full = join_paths(base, &path.to_string_lossy());
                        ParsedCommand::Read {
                            cmd,
                            name,
                            path: PathBuf::from(full),
                        }
                    } else {
                        ParsedCommand::Read { cmd, name, path }
                    }
                }
                other => other,
            };
            commands.push(parsed);
        }
        if commands.len() > 1 {
            commands.retain(|pc| !matches!(pc, ParsedCommand::Unknown { cmd } if cmd == "true"));
            // Apply the same simplifications used for non-bash parsing, e.g., drop leading `cd`.
            while let Some(next) = simplify_once(&commands) {
                commands = next;
            }
        }
        if commands.len() == 1 {
            // If we reduced to a single command, attribute the full original script
            // for clearer UX in file-reading and listing scenarios, or when there were
            // no connectors in the original script. For search commands that came from
            // a pipeline (e.g. `rg --files | sed -n`), keep only the primary command.
            let had_connectors = had_multiple_commands
                || script_tokens
                    .iter()
                    .any(|t| t == "|" || t == "&&" || t == "||" || t == ";");
            commands = commands
                .into_iter()
                .map(|pc| match pc {
                    ParsedCommand::Read { name, cmd, path } => {
                        if had_connectors {
                            let has_pipe = script_tokens.iter().any(|t| t == "|");
                            let has_sed_n = script_tokens.windows(2).any(|w| {
                                w.first().map(String::as_str) == Some("sed")
                                    && w.get(1).map(String::as_str) == Some("-n")
                            });
                            if has_pipe && has_sed_n {
                                ParsedCommand::Read {
                                    cmd: script.clone(),
                                    name,
                                    path,
                                }
                            } else {
                                ParsedCommand::Read { cmd, name, path }
                            }
                        } else {
                            ParsedCommand::Read {
                                cmd: shlex_join(&script_tokens),
                                name,
                                path,
                            }
                        }
                    }
                    ParsedCommand::ListFiles { path, cmd, .. } => {
                        if had_connectors {
                            ParsedCommand::ListFiles { cmd, path }
                        } else {
                            ParsedCommand::ListFiles {
                                cmd: shlex_join(&script_tokens),
                                path,
                            }
                        }
                    }
                    ParsedCommand::Search {
                        query, path, cmd, ..
                    } => {
                        if had_connectors {
                            ParsedCommand::Search { cmd, query, path }
                        } else {
                            ParsedCommand::Search {
                                cmd: shlex_join(&script_tokens),
                                query,
                                path,
                            }
                        }
                    }
                    other => other,
                })
                .collect();
        }
        return Some(commands);
    }
    Some(vec![ParsedCommand::Unknown {
        cmd: script.clone(),
    }])
}

/// Return true if this looks like a small formatting helper in a pipeline.
/// Examples: `head -n 40`, `tail -n +10`, `wc -l`, `awk ...`, `cut ...`, `tr ...`.
/// We try to keep variants that clearly include a file path (e.g. `tail -n 30 file`).
fn is_small_formatting_command(tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return false;
    }
    let cmd = tokens[0].as_str();
    match cmd {
        // Always formatting; typically used in pipes.
        // `nl` is special-cased below to allow `nl <file>` to be treated as a read command.
        "wc" | "tr" | "cut" | "sort" | "uniq" | "xargs" | "tee" | "column" | "awk" | "yes"
        | "printf" => true,
        "head" => {
            // Treat as formatting when no explicit file operand is present.
            // Common forms: `head -n 40`, `head -c 100`.
            // Keep cases like `head -n 40 file`.
            tokens.len() < 3
        }
        "tail" => {
            // Treat as formatting when no explicit file operand is present.
            // Common forms: `tail -n +10`, `tail -n 30`.
            // Keep cases like `tail -n 30 file`.
            tokens.len() < 3
        }
        "sed" => {
            // Keep `sed -n <range> file` (treated as a file read elsewhere);
            // otherwise consider it a formatting helper in a pipeline.
            tokens.len() < 4
                || !(tokens[1] == "-n" && is_valid_sed_n_arg(tokens.get(2).map(String::as_str)))
        }
        _ => false,
    }
}

fn drop_small_formatting_commands(mut commands: Vec<Vec<String>>) -> Vec<Vec<String>> {
    commands.retain(|tokens| !is_small_formatting_command(tokens));
    commands
}

pub(crate) fn summarize_main_tokens(main_cmd: &[String]) -> ParsedCommand {
    match main_cmd.split_first() {
        Some((head, tail)) if head == "ls" => {
            // Avoid treating option values as paths (e.g., ls -I "*.test.js").
            let candidates = skip_flag_values(
                tail,
                &[
                    "-I",
                    "-w",
                    "--block-size",
                    "--format",
                    "--time-style",
                    "--color",
                    "--quoting-style",
                ],
            );
            let path = candidates
                .into_iter()
                .find(|p| !p.starts_with('-'))
                .map(|p| short_display_path(p));
            ParsedCommand::ListFiles {
                cmd: shlex_join(main_cmd),
                path,
            }
        }
        Some((head, tail)) if head == "rg" => {
            let args_no_connector = trim_at_connector(tail);
            let has_files_flag = args_no_connector.iter().any(|a| a == "--files");

            // Skip values for flags that take an argument (e.g., -g/--glob)
            // when identifying positional operands. We'll separately extract
            // the -g/--glob value if needed for the --files case.
            let candidates = skip_flag_values(&args_no_connector, &["-g", "--glob"]);
            let non_flags: Vec<&String> = candidates
                .into_iter()
                .filter(|p| !p.starts_with('-'))
                .collect();

            let (query, path) = if has_files_flag {
                // Prefer an explicit positional path operand if present (e.g.,
                // `rg --files some/dir`). Otherwise, fall back to the first
                // provided glob value (e.g., `-g '!target'`).
                let path = non_flags
                    .first()
                    .map(|s| short_display_path(s))
                    .or_else(|| {
                        // Extract first -g/--glob value (supporting both split and = forms).
                        let mut i = 0usize;
                        while i < args_no_connector.len() {
                            let a = &args_no_connector[i];
                            if a == "-g" || a == "--glob" {
                                if i + 1 < args_no_connector.len() {
                                    return Some(args_no_connector[i + 1].clone());
                                }
                            } else if let Some(eq_pos) = a.find('=') {
                                let (flag, val) = a.split_at(eq_pos);
                                if flag == "--glob" || flag == "-g" {
                                    return Some(val[1..].to_string());
                                }
                            }
                            i += 1;
                        }
                        None
                    });
                (None, path)
            } else {
                (
                    non_flags.first().cloned().map(String::from),
                    non_flags.get(1).map(|s| short_display_path(s)),
                )
            };
            ParsedCommand::Search {
                cmd: shlex_join(main_cmd),
                query,
                path,
            }
        }
        Some((head, tail)) if head == "fd" => {
            let (query, path) = parse_fd_query_and_path(tail);
            ParsedCommand::Search {
                cmd: shlex_join(main_cmd),
                query,
                path,
            }
        }
        Some((head, tail)) if head == "find" => {
            // Basic find support: capture path and common name filter
            let (query, path) = parse_find_query_and_path(tail);
            ParsedCommand::Search {
                cmd: shlex_join(main_cmd),
                query,
                path,
            }
        }
        Some((head, tail)) if head == "grep" => {
            let args_no_connector = trim_at_connector(tail);
            let non_flags: Vec<&String> = args_no_connector
                .iter()
                .filter(|p| !p.starts_with('-'))
                .collect();
            // Do not shorten the query: grep patterns may legitimately contain slashes
            // and should be preserved verbatim. Only paths should be shortened.
            let query = non_flags.first().cloned().map(String::from);
            let path = non_flags.get(1).map(|s| short_display_path(s));
            ParsedCommand::Search {
                cmd: shlex_join(main_cmd),
                query,
                path,
            }
        }
        Some((head, tail)) if head == "cat" => {
            // Support both `cat <file>` and `cat -- <file>` forms.
            let effective_tail: &[String] = if tail.first().map(String::as_str) == Some("--") {
                &tail[1..]
            } else {
                tail
            };
            if effective_tail.len() == 1 {
                let path = effective_tail[0].clone();
                let name = short_display_path(&path);
                ParsedCommand::Read {
                    cmd: shlex_join(main_cmd),
                    name,
                    path: PathBuf::from(path),
                }
            } else {
                ParsedCommand::Unknown {
                    cmd: shlex_join(main_cmd),
                }
            }
        }
        Some((head, tail)) if head == "head" => {
            // Support `head -n 50 file` and `head -n50 file` forms.
            let has_valid_n = match tail.split_first() {
                Some((first, rest)) if first == "-n" => rest
                    .first()
                    .is_some_and(|n| n.chars().all(|c| c.is_ascii_digit())),
                Some((first, _)) if first.starts_with("-n") => {
                    first[2..].chars().all(|c| c.is_ascii_digit())
                }
                _ => false,
            };
            if has_valid_n {
                // Build candidates skipping the numeric value consumed by `-n` when separated.
                let mut candidates: Vec<&String> = Vec::new();
                let mut i = 0;
                while i < tail.len() {
                    if i == 0 && tail[i] == "-n" && i + 1 < tail.len() {
                        let n = &tail[i + 1];
                        if n.chars().all(|c| c.is_ascii_digit()) {
                            i += 2;
                            continue;
                        }
                    }
                    candidates.push(&tail[i]);
                    i += 1;
                }
                if let Some(p) = candidates.into_iter().find(|p| !p.starts_with('-')) {
                    let path = p.clone();
                    let name = short_display_path(&path);
                    return ParsedCommand::Read {
                        cmd: shlex_join(main_cmd),
                        name,
                        path: PathBuf::from(path),
                    };
                }
            }
            ParsedCommand::Unknown {
                cmd: shlex_join(main_cmd),
            }
        }
        Some((head, tail)) if head == "tail" => {
            // Support `tail -n +10 file` and `tail -n+10 file` forms.
            let has_valid_n = match tail.split_first() {
                Some((first, rest)) if first == "-n" => rest.first().is_some_and(|n| {
                    let s = n.strip_prefix('+').unwrap_or(n);
                    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
                }),
                Some((first, _)) if first.starts_with("-n") => {
                    let v = &first[2..];
                    let s = v.strip_prefix('+').unwrap_or(v);
                    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
                }
                _ => false,
            };
            if has_valid_n {
                // Build candidates skipping the numeric value consumed by `-n` when separated.
                let mut candidates: Vec<&String> = Vec::new();
                let mut i = 0;
                while i < tail.len() {
                    if i == 0 && tail[i] == "-n" && i + 1 < tail.len() {
                        let n = &tail[i + 1];
                        let s = n.strip_prefix('+').unwrap_or(n);
                        if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
                            i += 2;
                            continue;
                        }
                    }
                    candidates.push(&tail[i]);
                    i += 1;
                }
                if let Some(p) = candidates.into_iter().find(|p| !p.starts_with('-')) {
                    let path = p.clone();
                    let name = short_display_path(&path);
                    return ParsedCommand::Read {
                        cmd: shlex_join(main_cmd),
                        name,
                        path: PathBuf::from(path),
                    };
                }
            }
            ParsedCommand::Unknown {
                cmd: shlex_join(main_cmd),
            }
        }
        Some((head, tail)) if head == "nl" => {
            // Avoid treating option values as paths (e.g., nl -s "  ").
            let candidates = skip_flag_values(tail, &["-s", "-w", "-v", "-i", "-b"]);
            if let Some(p) = candidates.into_iter().find(|p| !p.starts_with('-')) {
                let path = p.clone();
                let name = short_display_path(&path);
                ParsedCommand::Read {
                    cmd: shlex_join(main_cmd),
                    name,
                    path: PathBuf::from(path),
                }
            } else {
                ParsedCommand::Unknown {
                    cmd: shlex_join(main_cmd),
                }
            }
        }
        Some((head, tail))
            if head == "sed"
                && tail.len() >= 3
                && tail[0] == "-n"
                && is_valid_sed_n_arg(tail.get(1).map(String::as_str)) =>
        {
            if let Some(path) = tail.get(2) {
                let path = path.clone();
                let name = short_display_path(&path);
                ParsedCommand::Read {
                    cmd: shlex_join(main_cmd),
                    name,
                    path: PathBuf::from(path),
                }
            } else {
                ParsedCommand::Unknown {
                    cmd: shlex_join(main_cmd),
                }
            }
        }
        // Other commands
        _ => ParsedCommand::Unknown {
            cmd: shlex_join(main_cmd),
        },
    }
}

fn is_abs_like(path: &str) -> bool {
    if std::path::Path::new(path).is_absolute() {
        return true;
    }
    let mut chars = path.chars();
    match (chars.next(), chars.next(), chars.next()) {
        // Windows drive path like C:\
        (Some(d), Some(':'), Some('\\')) if d.is_ascii_alphabetic() => return true,
        // UNC path like \\server\share
        (Some('\\'), Some('\\'), _) => return true,
        _ => {}
    }
    false
}

fn join_paths(base: &str, rel: &str) -> String {
    if is_abs_like(rel) {
        return rel.to_string();
    }
    if base.is_empty() {
        return rel.to_string();
    }
    let mut buf = PathBuf::from(base);
    buf.push(rel);
    buf.to_string_lossy().to_string()
}
