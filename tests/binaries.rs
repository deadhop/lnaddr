//! The two binaries, run as a user would: a command, and serving until a signal.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A command with a clean environment, keeping only what coverage needs.
fn clean(bin: &str) -> Command {
    let mut c = Command::new(bin);
    c.env_clear();
    if let Ok(p) = std::env::var("LLVM_PROFILE_FILE") {
        c.env("LLVM_PROFILE_FILE", p);
    }
    c
}

fn run(bin: &str, args: &[&str]) -> (bool, String) {
    let out = clean(bin).args(args).output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn both_binaries_print_their_version() {
    let (ok, out) = run(env!("CARGO_BIN_EXE_lnaddr-node"), &["version"]);
    assert!(ok && out.starts_with("lnaddr-node "));
    let (ok, out) = run(env!("CARGO_BIN_EXE_lnaddr-gateway"), &["version"]);
    assert!(ok && out.starts_with("lnaddr-gateway "));
}

/// Serve until `signal`, and check the process exits cleanly and promptly.
fn serves_until(bin: &str, envs: &[(&str, String)], signal: i32) {
    let mut child = clean(bin).envs(envs.iter().map(|(k, v)| (*k, v.as_str()))).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    // Wait for the "is serving" log line, then keep draining the log.
    let (tx, rx) = std::sync::mpsc::channel();
    let stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.contains("is serving") {
                let _ = tx.send(());
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(30)).expect("the service never said it is serving");
    assert!(child.try_wait().unwrap().is_none(), "{bin} exited before the signal");
    assert_eq!(unsafe { kill(child.id() as i32, signal) }, 0);
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{bin}: {status:?}");
            return;
        }
        assert!(started.elapsed() < Duration::from_secs(10), "{bin} did not stop");
        std::thread::sleep(Duration::from_millis(50));
    }
}

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

#[test]
fn both_binaries_serve_until_a_signal() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = vec![
        ("LNADDR_GATEWAY_DATA_DIR", dir.path().join("gw").display().to_string()),
        ("LNADDR_GATEWAY_DOMAIN", "pay.example".to_string()),
        ("LNADDR_GATEWAY_NODE", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string()),
        ("LNADDR_GATEWAY_RELAYS", "ws://127.0.0.1:9".to_string()),
        ("LNADDR_GATEWAY_LISTEN", "127.0.0.1:0".to_string()),
    ];
    serves_until(env!("CARGO_BIN_EXE_lnaddr-gateway"), &gateway, SIGTERM);
    let node = vec![
        ("LNADDR_NODE_DATA_DIR", dir.path().join("node").display().to_string()),
        ("LNADDR_NODE_RELAYS", "ws://127.0.0.1:9".to_string()),
        ("LNADDR_NODE_GATEWAYS", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string()),
        ("LNADDR_NODE_BACKEND", "phoenixd".to_string()),
        ("LNADDR_NODE_BACKEND_SECRET", "x".to_string()),
        ("LNADDR_NODE_ADDRESSES", "alice".to_string()),
    ];
    serves_until(env!("CARGO_BIN_EXE_lnaddr-node"), &node, SIGINT);
}
