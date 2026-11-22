//! Accepting HTTP connections on TCP or a Unix socket, with a bound on open
//! connections and on how long a client may take to send its headers, so a
//! slow or flooding client cannot exhaust the gateway.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use crate::gateway::config::Listen;

/// The address a request came from: an IP for TCP, `None` for a Unix socket
/// (whose peer is a reverse proxy on this host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer(pub Option<IpAddr>);

pub enum Bound {
    Tcp(tokio::net::TcpListener),
    Unix(tokio::net::UnixListener, std::path::PathBuf),
}

impl Bound {
    /// The bound address (with the real port when 0 was asked for).
    pub fn local(&self) -> Listen {
        match self {
            Bound::Tcp(l) => Listen::Tcp(l.local_addr().expect("a bound socket has an address")),
            Bound::Unix(_, p) => Listen::Unix(p.clone()),
        }
    }
}

pub async fn bind(listen: &Listen) -> Result<Bound, String> {
    match listen {
        Listen::Tcp(addr) => tokio::net::TcpListener::bind(addr)
            .await
            .map(Bound::Tcp)
            .map_err(|e| format!("cannot listen on {addr}: {e}")),
        Listen::Unix(path) => {
            // A socket left by an earlier run would block the bind; anything else is kept.
            if std::fs::symlink_metadata(path).is_ok_and(|m| std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()))
            {
                let _ = std::fs::remove_file(path);
            }
            let l = tokio::net::UnixListener::bind(path)
                .map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
            Ok(Bound::Unix(l, path.clone()))
        }
    }
}

/// How long a client may take to send a request's headers.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection of either kind.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn spawn_conn(io: Box<dyn Io>, peer: Peer, app: Router, permit: tokio::sync::OwnedSemaphorePermit) {
    tokio::spawn(async move {
        let svc = tower::service_fn(move |mut req: axum::http::Request<hyper::body::Incoming>| {
            req.extensions_mut().insert(peer);
            app.clone().oneshot(req.map(axum::body::Body::new))
        });
        let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        b.http1()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT)
            .max_buf_size(16 * 1024);
        let _ = b
            .http1_only()
            .serve_connection(TokioIo::new(io), TowerToHyperService::new(svc))
            .await;
        drop(permit);
    });
}

/// Serve `app` until `stop` is cancelled, with at most `max_conns` open connections.
pub async fn serve(bound: Bound, app: Router, max_conns: u32, stop: CancellationToken) {
    serve_from(&bound, app, max_conns, stop).await;
    if let Bound::Unix(_, path) = &bound {
        let _ = std::fs::remove_file(path);
    }
}

type Accepting<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Conn>> + Send + 'a>>;

trait Accept: Sync {
    fn accept(&self) -> Accepting<'_>;
}

impl Accept for Bound {
    fn accept(&self) -> Accepting<'_> {
        Box::pin(async move {
            match self {
                Bound::Tcp(l) => l.accept().await.map(|(s, a)| Conn::Tcp(s, a.ip())),
                Bound::Unix(l, _) => l.accept().await.map(|(s, _)| Conn::Unix(s)),
            }
        })
    }
}

async fn serve_from(bound: &(dyn Accept + Sync), app: Router, max_conns: u32, stop: CancellationToken) {
    let permits = Arc::new(Semaphore::new(max_conns as usize));
    loop {
        let permit = tokio::select! {
            _ = stop.cancelled() => break,
            p = permits.clone().acquire_owned() => p.expect("the semaphore is never closed"),
        };
        tokio::select! {
            _ = stop.cancelled() => break,
            conn = bound.accept() => match conn {
                Ok(Conn::Tcp(s, ip)) => spawn_conn(Box::new(s), Peer(Some(ip)), app.clone(), permit),
                Ok(Conn::Unix(s)) => spawn_conn(Box::new(s), Peer(None), app.clone(), permit),
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
        }
    }
}

enum Conn {
    Tcp(tokio::net::TcpStream, IpAddr),
    Unix(tokio::net::UnixStream),
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Extension;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn app() -> Router {
        Router::new().route(
            "/",
            get(|Extension(p): Extension<Peer>| async move { format!("{:?}", p.0) }),
        )
    }

    #[tokio::test]
    async fn tcp_and_unix_peers_are_told_apart() {
        let stop = CancellationToken::new();
        let tcp = bind(&Listen::Tcp("127.0.0.1:0".parse().unwrap())).await.unwrap();
        let Listen::Tcp(addr) = tcp.local() else { unreachable!() };
        tokio::spawn(serve(tcp, app(), 16, stop.clone()));
        let body = crate::tls::http_client(Duration::from_secs(5))
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "Some(127.0.0.1)");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.sock");
        // A stale socket from an earlier run is replaced.
        let _stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let unix = bind(&Listen::Unix(path.clone())).await.unwrap();
        assert_eq!(unix.local(), Listen::Unix(path.clone()));
        let task = tokio::spawn(serve(unix, app(), 16, stop.clone()));
        let mut s = tokio::net::UnixStream::connect(&path).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.ends_with("None"), "{out}");
        stop.cancel();
        task.await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn binding_fails_are_explained_and_other_files_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-socket");
        std::fs::write(&file, "keep me").unwrap();
        let e = bind(&Listen::Unix(file.clone())).await.err().unwrap();
        assert!(e.contains("cannot listen on"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep me");
        let taken = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let e = bind(&Listen::Tcp(taken.local_addr().unwrap())).await.err().unwrap();
        assert!(e.contains("cannot listen on"));
    }

    #[tokio::test]
    async fn connections_beyond_the_limit_wait_and_slow_headers_are_dropped() {
        let stop = CancellationToken::new();
        let tcp = bind(&Listen::Tcp("127.0.0.1:0".parse().unwrap())).await.unwrap();
        let Listen::Tcp(addr) = tcp.local() else { unreachable!() };
        tokio::spawn(serve(tcp, app(), 1, stop.clone()));
        // One idle connection holds the only slot...
        let idle = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let quick = crate::tls::http_client(Duration::from_millis(500));
        assert!(quick.get(format!("http://{addr}/")).send().await.is_err());
        // ...until the header timeout drops it.
        drop(idle);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let ok = crate::tls::http_client(Duration::from_secs(5))
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        assert!(ok.status().is_success());
        stop.cancel();
    }

    struct Broken;
    impl Accept for Broken {
        fn accept(&self) -> Accepting<'_> {
            Box::pin(async { Err(std::io::Error::other("too many open files")) })
        }
    }

    #[tokio::test]
    async fn accept_errors_back_off_and_keep_the_loop_alive() {
        let stop = CancellationToken::new();
        let task = tokio::spawn({
            let stop = stop.clone();
            async move { serve_from(&Broken, app(), 4, stop).await }
        });
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(!task.is_finished());
        stop.cancel();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_stop_while_waiting_for_a_slot_ends_the_loop() {
        let stop = CancellationToken::new();
        let tcp = bind(&Listen::Tcp("127.0.0.1:0".parse().unwrap())).await.unwrap();
        let Listen::Tcp(addr) = tcp.local() else { unreachable!() };
        let task = tokio::spawn(serve(tcp, app(), 1, stop.clone()));
        let _held = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.cancel();
        task.await.unwrap();
    }
}
