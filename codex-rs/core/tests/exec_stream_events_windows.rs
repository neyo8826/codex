#![cfg(windows)]

use std::collections::HashMap;
use std::path::PathBuf;

use async_channel::Receiver;
use codex_core::exec::ExecParams;
use codex_core::exec::SandboxType;
use codex_core::exec::StdoutStream;
use codex_core::exec::process_exec_tool_call;
use codex_core::protocol::Event;
use codex_core::protocol::EventMsg;
use codex_core::protocol::ExecCommandOutputDeltaEvent;
use codex_core::protocol::ExecOutputStream;
use codex_core::protocol::SandboxPolicy;

fn collect_stdout_events(rx: Receiver<Event>) -> Vec<u8> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
            stream: ExecOutputStream::Stdout,
            chunk,
            ..
        }) = ev.msg
        {
            out.extend_from_slice(&chunk);
        }
    }
    out
}

#[tokio::test]
async fn test_exec_stdout_stream_events_echo_cmd() {
    let (tx, rx) = async_channel::unbounded::<Event>();

    let stdout_stream = StdoutStream {
        sub_id: "test-sub".to_string(),
        call_id: "call-1".to_string(),
        tx_event: tx,
    };

    // On Windows, use cmd.exe to print a predictable line
    let cmd = vec![
        "cmd".to_string(),
        "/C".to_string(),
        "echo hello-world".to_string(),
    ];

    let params = ExecParams {
        command: cmd,
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        timeout_ms: Some(5_000),
        env: HashMap::new(),
        with_escalated_permissions: None,
        justification: None,
    };

    let policy = SandboxPolicy::new_read_only_policy();

    let result = process_exec_tool_call(
        params,
        SandboxType::None,
        &policy,
        &None,
        Some(stdout_stream),
    )
    .await
    .unwrap_or_else(|e| panic!("process_exec_tool_call failed: {e}"));

    assert_eq!(result.exit_code, 0);
    // `echo` on Windows appends CRLF by default; normalize to LF for comparison
    let stdout = result.stdout.text.replace("\r\n", "\n");
    assert_eq!(stdout, "hello-world\n");

    let streamed = String::from_utf8_lossy(&collect_stdout_events(rx)).replace("\r\n", "\n");
    assert_eq!(streamed, "hello-world\n");
}

#[tokio::test]
async fn test_exec_stderr_stream_events_cmd() {
    let (tx, rx) = async_channel::unbounded::<Event>();

    let stdout_stream = StdoutStream {
        sub_id: "test-sub".to_string(),
        call_id: "call-2".to_string(),
        tx_event: tx,
    };

    // Write to stderr using cmd redirection
    let cmd = vec![
        "cmd".to_string(),
        "/C".to_string(),
        "echo oops 1>&2".to_string(),
    ];

    let params = ExecParams {
        command: cmd,
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        timeout_ms: Some(5_000),
        env: HashMap::new(),
        with_escalated_permissions: None,
        justification: None,
    };

    let policy = SandboxPolicy::new_read_only_policy();

    let result = process_exec_tool_call(
        params,
        SandboxType::None,
        &policy,
        &None,
        Some(stdout_stream),
    )
    .await
    .unwrap_or_else(|e| panic!("process_exec_tool_call failed: {e}"));

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.text, "");
    assert_eq!(result.stderr.text.trim(), "oops");

    // Collect only stderr delta events
    let mut err = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
            stream: ExecOutputStream::Stderr,
            chunk,
            ..
        }) = ev.msg
        {
            err.extend_from_slice(&chunk);
        }
    }
    let streamed_err = String::from_utf8_lossy(&err);
    assert_eq!(streamed_err.trim(), "oops");
}

// Resolve a usable PowerShell executable and its fixed arguments. Prefer pwsh
// (PowerShell Core), fall back to Windows PowerShell if available. Returns None
// if neither is present, in which case tests should be skipped.
fn resolve_powershell() -> Option<Vec<String>> {
    use std::process::Command as StdCommand;
    // Try pwsh first
    if let Ok(out) = StdCommand::new("pwsh")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "$PSVersionTable.PSVersion.ToString()",
        ])
        .output()
        && out.status.success()
    {
        return Some(vec![
            "pwsh".to_string(),
            "-NoLogo".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
        ]);
    }
    // Fall back to Windows PowerShell
    if let Ok(out) = StdCommand::new("powershell")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "$PSVersionTable.PSVersion.ToString()",
        ])
        .output()
        && out.status.success()
    {
        return Some(vec![
            "powershell".to_string(),
            "-NoLogo".to_string(),
            "-NoProfile".to_string(),
            "-Command".to_string(),
        ]);
    }
    None
}

#[tokio::test]
async fn test_exec_stdout_stream_events_powershell() {
    let Some(mut ps) = resolve_powershell() else {
        eprintln!("Skipping PowerShell test: neither pwsh nor powershell found on PATH");
        return;
    };

    let (tx, rx) = async_channel::unbounded::<Event>();
    let stdout_stream = StdoutStream {
        sub_id: "test-sub".to_string(),
        call_id: "call-ps-1".to_string(),
        tx_event: tx,
    };

    // Append the script to the fixed arguments
    ps.push("Write-Output 'hello-world'".to_string());

    let params = ExecParams {
        command: ps,
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        timeout_ms: Some(5_000),
        env: HashMap::new(),
        with_escalated_permissions: None,
        justification: None,
    };

    let policy = SandboxPolicy::new_read_only_policy();

    let result = process_exec_tool_call(
        params,
        SandboxType::None,
        &policy,
        &None,
        Some(stdout_stream),
    )
    .await
    .unwrap_or_else(|e| panic!("process_exec_tool_call failed: {e}"));

    assert_eq!(result.exit_code, 0);
    let stdout = result.stdout.text.replace("\r\n", "\n");
    assert_eq!(stdout, "hello-world\n");

    let streamed = String::from_utf8_lossy(&collect_stdout_events(rx)).replace("\r\n", "\n");
    assert_eq!(streamed, "hello-world\n");
}

#[tokio::test]
async fn test_exec_stderr_stream_events_powershell() {
    let Some(mut ps) = resolve_powershell() else {
        eprintln!("Skipping PowerShell test: neither pwsh nor powershell found on PATH");
        return;
    };

    let (tx, rx) = async_channel::unbounded::<Event>();
    let stdout_stream = StdoutStream {
        sub_id: "test-sub".to_string(),
        call_id: "call-ps-2".to_string(),
        tx_event: tx,
    };

    // Write a clean line to stderr via .NET
    ps.push("[Console]::Error.WriteLine('oops')".to_string());

    let params = ExecParams {
        command: ps,
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        timeout_ms: Some(5_000),
        env: HashMap::new(),
        with_escalated_permissions: None,
        justification: None,
    };

    let policy = SandboxPolicy::new_read_only_policy();

    let result = process_exec_tool_call(
        params,
        SandboxType::None,
        &policy,
        &None,
        Some(stdout_stream),
    )
    .await
    .unwrap_or_else(|e| panic!("process_exec_tool_call failed: {e}"));

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout.text, "");
    let stderr = result.stderr.text.replace("\r\n", "\n");
    assert_eq!(stderr, "oops\n");

    // Collect only stderr delta events
    let mut err = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let EventMsg::ExecCommandOutputDelta(ExecCommandOutputDeltaEvent {
            stream: ExecOutputStream::Stderr,
            chunk,
            ..
        }) = ev.msg
        {
            err.extend_from_slice(&chunk);
        }
    }
    let streamed_err = String::from_utf8_lossy(&err).replace("\r\n", "\n");
    assert_eq!(streamed_err, "oops\n");
}
