// Multi-threaded flavor: the mock collector's `rx.recv_timeout` below is a
// genuine blocking call. Under the default single-threaded test runtime it
// would starve the daemon's own spawned tasks (export loop, IPC accept
// loop, ...), which share that one thread, and the test would deadlock
// until the timeout.
#[tokio::test(flavor = "multi_thread")]
async fn hook_event_flows_to_mock_collector() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
    std::env::set_var(
        "LLM_MONITOR_SOCKET",
        std::env::temp_dir().join(format!("lm-e2e-{}.sock", std::process::id())),
    );

    // Mock OTLP collector.
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_string();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);
            let _ = tx.send(body);
            let _ = req.respond(tiny_http::Response::empty(200));
        }
    });

    // Local config pointing at the mock collector, fast flush.
    std::fs::create_dir_all(dir.path()).unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        format!("[export]\notlp_endpoint = \"http://{addr}\"\nflush_interval_secs = 1\n"),
    )
    .unwrap();

    tokio::spawn(async { llm_monitor::daemon::run().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Simulate a Claude Code hook firing, including a secret to test redaction.
    llm_monitor::hook::deliver(
        "claude-code",
        None,
        r#"{"hook_event_name":"PreToolUse","session_id":"e2e","tool_name":"Bash",
            "tool_input":{"command":"curl -H 'Authorization: Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789' https://api.internal.example.com/v1"}}"#,
    );

    let body = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    assert!(body.contains("api.internal.example.com"), "fqdn extracted");
    assert!(body.contains("tool.name"), "otlp attributes present");
    assert!(
        !body.contains("ghp_AbCdEf"),
        "secret redacted before export"
    );

    // Copilot flow through the same daemon (merged into this test because
    // both flows set process-global env vars and would race as separate
    // #[tokio::test] functions).
    llm_monitor::hook::deliver(
        "copilot",
        Some("postToolUse"),
        r#"{"sessionId":"cp-e2e","cwd":"/repo","toolName":"bash",
            "toolArgs":{"command":"curl https://api.copilot-test.example.com/v1"},
            "toolResult":{"resultType":"success","textResultForLlm":"ok"}}"#,
    );

    let body = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    assert!(
        body.contains("api.copilot-test.example.com"),
        "copilot fqdn extracted"
    );
    assert!(
        body.contains("\"tool_use\"") || body.contains("tool.name"),
        "copilot tool event exported"
    );
}
