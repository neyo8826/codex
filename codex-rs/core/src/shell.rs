use shlex;

#[derive(Debug, PartialEq, Eq)]
pub struct ZshShell {
    shell_path: String,
    zshrc_path: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Shell {
    Zsh(ZshShell),
    #[cfg(target_os = "windows")]
    PowerShell(PowerShellShell),
    #[cfg(target_os = "windows")]
    Cmd(CmdShell),
    Unknown,
}

impl Shell {
    pub fn format_default_shell_invocation(&self, command: Vec<String>) -> Option<Vec<String>> {
        match self {
            Shell::Zsh(zsh) => {
                if !std::path::Path::new(&zsh.zshrc_path).exists() {
                    return None;
                }

                let mut result = vec![zsh.shell_path.clone()];
                result.push("-lc".to_string());

                let joined = strip_bash_lc(&command)
                    .or_else(|| shlex::try_join(command.iter().map(|s| s.as_str())).ok());

                if let Some(joined) = joined {
                    result.push(format!("source {} && ({joined})", zsh.zshrc_path));
                } else {
                    return None;
                }
                Some(result)
            }
            #[cfg(target_os = "windows")]
            Shell::PowerShell(ps) => {
                let mut result = vec![ps.shell_path.clone()];
                // Do not use -NoProfile because we want to honor the user's profile.
                result.push("-NoLogo".to_string());
                result.push("-Command".to_string());

                // If the model wrapped with bash -lc, unwrap to the inner script.
                let joined = strip_bash_lc(&command)
                    .or_else(|| shlex::try_join(command.iter().map(|s| s.as_str())).ok());
                let joined = joined?;

                // Source the user's PowerShell profile if it exists, then run the command in a subshell.
                // Using a scriptblock in parentheses keeps semantics closer to zsh's (myecho) grouping.
                let script = format!("if (Test-Path $PROFILE) {{ . $PROFILE }}; ({joined})");
                result.push(script);
                Some(result)
            }
            #[cfg(target_os = "windows")]
            Shell::Cmd(cmd) => {
                let mut result = vec![cmd.shell_path.clone()];
                // /d: disable AutoRun from registry, /s: strip quotes, /c: execute and terminate
                result.extend(["/d".to_string(), "/s".to_string(), "/c".to_string()]);

                let joined = strip_bash_lc(&command)
                    .or_else(|| shlex::try_join(command.iter().map(|s| s.as_str())).ok());
                let joined = joined?;
                // For simplicity, pass the joined command as is; CMD will parse it.
                result.push(joined);
                Some(result)
            }
            Shell::Unknown => None,
        }
    }
}

fn strip_bash_lc(command: &Vec<String>) -> Option<String> {
    match command.as_slice() {
        // exactly three items
        [first, second, third]
            // first two must be "bash", "-lc"
            if first == "bash" && second == "-lc" =>
        {
            Some(third.clone())
        }
        _ => None,
    }
}

#[cfg(target_os = "macos")]
pub async fn default_user_shell() -> Shell {
    use tokio::process::Command;
    use whoami;

    let user = whoami::username();
    let home = format!("/Users/{user}");
    let output = Command::new("dscl")
        .args([".", "-read", &home, "UserShell"])
        .output()
        .await
        .ok();
    match output {
        Some(o) => {
            if !o.status.success() {
                return Shell::Unknown;
            }
            let stdout = String::from_utf8_lossy(&o.stdout);
            for line in stdout.lines() {
                if let Some(shell_path) = line.strip_prefix("UserShell: ") {
                    if shell_path.ends_with("/zsh") {
                        return Shell::Zsh(ZshShell {
                            shell_path: shell_path.to_string(),
                            zshrc_path: format!("{home}/.zshrc"),
                        });
                    }
                }
            }

            Shell::Unknown
        }
        _ => Shell::Unknown,
    }
}

#[cfg(not(target_os = "macos"))]
pub async fn default_user_shell() -> Shell {
    #[cfg(target_os = "windows")]
    {
        use std::env;
        use std::fs;
        use std::path::{Path, PathBuf};

        fn find_in_path(exe: &str) -> Option<String> {
            let path_os = env::var_os("PATH")?;
            for dir in env::split_paths(&path_os) {
                let candidate = dir.join(exe);
                if candidate.is_file() {
                    return Some(candidate.to_string_lossy().into_owned());
                }
            }
            None
        }

        fn find_pwsh() -> Option<String> {
            if let Some(p) = find_in_path("pwsh.exe") {
                return Some(p);
            }
            let program_files = env::var_os("ProgramFiles")?;
            let root = PathBuf::from(program_files).join("PowerShell");
            if let Ok(entries) = fs::read_dir(root) {
                // Prefer highest (latest) version directory
                let mut versions: Vec<PathBuf> =
                    entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
                versions.sort(); // lexicographic; good enough for version dir names
                versions.reverse();
                for v in versions {
                    let candidate = v.join("pwsh.exe");
                    if candidate.is_file() {
                        return Some(candidate.to_string_lossy().into_owned());
                    }
                }
            }
            None
        }

        fn find_windows_powershell() -> Option<String> {
            if let Some(p) = find_in_path("powershell.exe") {
                return Some(p);
            }
            let system_root = env::var_os("SystemRoot")?;
            let candidate = PathBuf::from(system_root)
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe");
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
            None
        }

        if let Some(pwsh_path) = find_pwsh() {
            return Shell::PowerShell(PowerShellShell {
                shell_path: pwsh_path,
            });
        }
        if let Some(ps_legacy) = find_windows_powershell() {
            return Shell::PowerShell(PowerShellShell {
                shell_path: ps_legacy,
            });
        }
        if let Some(comspec) = env::var_os("COMSPEC") {
            let comspec_str = comspec.to_string_lossy().into_owned();
            if Path::new(&comspec_str).is_file() {
                return Shell::Cmd(CmdShell {
                    shell_path: comspec_str,
                });
            }
        }
        Shell::Unknown
    }
    #[cfg(not(target_os = "windows"))]
    {
        Shell::Unknown
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests {
    use super::*;
    use std::process::Command;

    #[tokio::test]
    async fn test_current_shell_detects_zsh() {
        let shell = Command::new("sh")
            .arg("-c")
            .arg("echo $SHELL")
            .output()
            .unwrap();

        let home = std::env::var("HOME").unwrap();
        let shell_path = String::from_utf8_lossy(&shell.stdout).trim().to_string();
        if shell_path.ends_with("/zsh") {
            assert_eq!(
                default_user_shell().await,
                Shell::Zsh(ZshShell {
                    shell_path: shell_path.to_string(),
                    zshrc_path: format!("{home}/.zshrc",),
                })
            );
        }
    }

    #[tokio::test]
    async fn test_run_with_profile_zshrc_not_exists() {
        let shell = Shell::Zsh(ZshShell {
            shell_path: "/bin/zsh".to_string(),
            zshrc_path: "/does/not/exist/.zshrc".to_string(),
        });
        let actual_cmd = shell.format_default_shell_invocation(vec!["myecho".to_string()]);
        assert_eq!(actual_cmd, None);
    }

    #[tokio::test]
    async fn test_run_with_profile_escaping_and_execution() {
        let shell_path = "/bin/zsh";

        let cases = vec![
            (
                vec!["myecho"],
                vec![shell_path, "-lc", "source ZSHRC_PATH && (myecho)"],
                Some("It works!\n"),
            ),
            (
                vec!["myecho"],
                vec![shell_path, "-lc", "source ZSHRC_PATH && (myecho)"],
                Some("It works!\n"),
            ),
            (
                vec!["bash", "-c", "echo 'single' \"double\""],
                vec![
                    shell_path,
                    "-lc",
                    "source ZSHRC_PATH && (bash -c \"echo 'single' \\\"double\\\"\")",
                ],
                Some("single double\n"),
            ),
            (
                vec!["bash", "-lc", "echo 'single' \"double\""],
                vec![
                    shell_path,
                    "-lc",
                    "source ZSHRC_PATH && (echo 'single' \"double\")",
                ],
                Some("single double\n"),
            ),
        ];
        for (input, expected_cmd, expected_output) in cases {
            use std::collections::HashMap;
            use std::path::PathBuf;

            use crate::exec::ExecParams;
            use crate::exec::SandboxType;
            use crate::exec::process_exec_tool_call;
            use crate::protocol::SandboxPolicy;

            // create a temp directory with a zshrc file in it
            let temp_home = tempfile::tempdir().unwrap();
            let zshrc_path = temp_home.path().join(".zshrc");
            std::fs::write(
                &zshrc_path,
                r#"
                    set -x
                    function myecho {
                        echo 'It works!'
                    }
                    "#,
            )
            .unwrap();
            let shell = Shell::Zsh(ZshShell {
                shell_path: shell_path.to_string(),
                zshrc_path: zshrc_path.to_str().unwrap().to_string(),
            });

            let actual_cmd = shell
                .format_default_shell_invocation(input.iter().map(|s| s.to_string()).collect());
            let expected_cmd = expected_cmd
                .iter()
                .map(|s| {
                    s.replace("ZSHRC_PATH", zshrc_path.to_str().unwrap())
                        .to_string()
                })
                .collect();

            assert_eq!(actual_cmd, Some(expected_cmd));
            // Actually run the command and check output/exit code
            let output = process_exec_tool_call(
                ExecParams {
                    command: actual_cmd.unwrap(),
                    cwd: PathBuf::from(temp_home.path()),
                    timeout_ms: None,
                    env: HashMap::from([(
                        "HOME".to_string(),
                        temp_home.path().to_str().unwrap().to_string(),
                    )]),
                    with_escalated_permissions: None,
                    justification: None,
                },
                SandboxType::None,
                &SandboxPolicy::DangerFullAccess,
                &None,
                None,
            )
            .await
            .unwrap();

            assert_eq!(output.exit_code, 0, "input: {input:?} output: {output:?}");
            if let Some(expected) = expected_output {
                assert_eq!(
                    output.stdout.text, expected,
                    "input: {input:?} output: {output:?}"
                );
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg(target_os = "windows")]
pub struct PowerShellShell {
    shell_path: String,
}

#[derive(Debug, PartialEq, Eq)]
#[cfg(target_os = "windows")]
pub struct CmdShell {
    shell_path: String,
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod windows_tests {
    use super::*;

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_pwsh_wraps_with_profile_and_joins() {
        let shell = Shell::PowerShell(PowerShellShell {
            shell_path: "pwsh".to_string(),
        });
        let input = vec!["echo".to_string(), "hello".to_string()];
        let out = shell.format_default_shell_invocation(input).unwrap();
        assert_eq!(out[0], "pwsh");
        assert_eq!(out[1], "-NoLogo");
        assert_eq!(out[2], "-Command");
        assert!(out[3].starts_with("if (Test-Path $PROFILE) { . $PROFILE }"));
        assert!(out[3].contains("(echo hello)"));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_powershell_wraps_with_profile_and_joins_bash() {
        let shell = Shell::PowerShell(PowerShellShell {
            shell_path: "powershell".to_string(),
        });
        let input = vec!["echo".to_string(), "hello".to_string()];
        let out = shell.format_default_shell_invocation(input).unwrap();
        assert_eq!(out[0], "powershell");
        assert_eq!(out[1], "-NoLogo");
        assert_eq!(out[2], "-Command");
        assert!(out[3].starts_with("if (Test-Path $PROFILE) { . $PROFILE }"));
        assert!(out[3].contains("(echo hello)"));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn test_cmd_wraps_c_simple() {
        let shell = Shell::Cmd(CmdShell {
            shell_path: "cmd.exe".to_string(),
        });
        let input = vec!["dir".to_string(), ".".to_string()];
        let out = shell.format_default_shell_invocation(input).unwrap();
        assert_eq!(out[..4], ["cmd.exe", "/d", "/s", "/c"]);
        assert!(out[4].contains("dir ."));
    }
}
