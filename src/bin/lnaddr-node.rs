//! lnaddr-node: runs next to the Lightning node. All logic is in the library.

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let shutdown = Box::pin(deadhop_lnaddr::shutdown_signal());
    deadhop_lnaddr::node::app::command(
        &args,
        Box::new(|k| std::env::var(k).ok()),
        shutdown,
        &mut std::io::stdout(),
    )
    .await
}
