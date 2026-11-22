//! lnaddr-gateway: runs on a public host. All logic is in the library.

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let shutdown = deadhop_lnaddr::shutdown_signal();
    deadhop_lnaddr::gateway::app::command(&args, |k| std::env::var(k).ok(), shutdown, &mut std::io::stdout()).await
}
