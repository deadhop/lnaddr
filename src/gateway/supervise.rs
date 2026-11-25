//! Keeping the gateway's relay connections where its network says: the
//! console's server on the admin key, and the pools open to nodes.
//!
//! As on the node: a relay change remakes the connections and goes back to
//! the previous relays if the console's server connects on none of the new
//! ones; a move of the proxy pool moves only the relays whose route changed
//! (`Pool::reroute`); and saved relays with nothing connected for
//! [`RELAY_DEAD_AFTER`] give way to the configured ones. Both lanes are
//! judged: the console's server must reach a relay (when it runs), and the
//! gateway key at least one node. Unlike the node, a server that cannot be
//! started or brought back does not stop the gateway: the LNURL side keeps
//! serving, `get_health` says why, and the server is tried again on the next
//! look.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use contextvm_sdk::transport::server::{NostrServerTransport, NostrServerTransportConfig};
use contextvm_sdk::{EncryptionMode, GiftWrapMode, ServerInfo};
use deadhop_netengine::netruntime::{route_specs, same_relays, Routes};
use nostr_sdk::prelude::Keys;
use rmcp::transport::IntoTransport;
use rmcp::{RoleServer, ServiceExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::gateway::mcp::GatewayServer;
use crate::gateway::network::{Network, ADMIN_LANE};
use crate::gateway::nodes::Directory;
use crate::pool::Pool;

/// How long new relays get to connect before the previous ones come back.
#[cfg(not(test))]
pub const RELAY_CHECK: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const RELAY_CHECK: Duration = Duration::from_secs(3);
/// How often the supervisor looks at the live relays.
#[cfg(not(test))]
const RELAY_WATCH_EVERY: Duration = Duration::from_secs(30);
#[cfg(test)]
const RELAY_WATCH_EVERY: Duration = Duration::from_millis(250);
/// How long no relay may be connected before the gateway goes back to the
/// configured relays.
#[cfg(not(test))]
const RELAY_DEAD_AFTER: Duration = Duration::from_secs(600);
#[cfg(test)]
const RELAY_DEAD_AFTER: Duration = Duration::from_secs(2);
/// Pause before connections are remade, so the reply to the request that
/// caused it is published on the old ones first.
#[cfg(not(test))]
const RESTART_GRACE: Duration = Duration::from_millis(1500);
#[cfg(test)]
const RESTART_GRACE: Duration = Duration::from_millis(200);
/// How often every live relay is checked end to end.
#[cfg(not(test))]
pub const RELAY_HEALTH_EVERY: Duration = Duration::from_secs(300);
#[cfg(test)]
pub const RELAY_HEALTH_EVERY: Duration = Duration::from_secs(1);
/// Audit-log reasons for going back to the configured relays.
pub const DEAD_RELAYS: &str = "no relay was connected for 10 minutes; back to the configured relays";
pub const DEAD_AT_START: &str = "no saved relay connected at startup; using the configured relays";

/// The console's server identity and who may call it.
#[derive(Clone)]
pub struct Ident {
    pub keys: Keys,
    pub allowed: Vec<String>,
}

/// One generation of the console server's relay connections and its request loop.
pub struct Link {
    net: Arc<Network>,
    routes: Routes,
    pool: Arc<Pool>,
    cancel: CancellationToken,
    /// Cancelled by the request loop when it ends, for whatever reason.
    ended: CancellationToken,
    task: JoinHandle<()>,
}

impl Link {
    async fn up(id: &Ident, routes: Routes, net: &Arc<Network>, dir: &Arc<Directory>) -> Result<Link, String> {
        let sink: deadhop_net::relay::RelaySink = {
            let net = net.clone();
            Arc::new(move |relay, ok, ms| net.runtime.record_relay_event(&*net, relay, "send", ok, Some(ms)))
        };
        let specs = route_specs(&routes).map_err(crate::why)?;
        let pool = Arc::new(Pool::routed(id.keys.clone(), specs).with_sink(sink));
        let transport_config = NostrServerTransportConfig::default()
            .with_relay_urls(routes.iter().map(|(r, _)| r.clone()).collect())
            .with_encryption_mode(EncryptionMode::Required)
            // Ephemeral gift wraps (kind 21059): relays forward them and keep
            // nothing, so no stored reply can ever be replayed to a client.
            .with_gift_wrap_mode(GiftWrapMode::Ephemeral)
            // Never announced and never listed: nothing public leads to it.
            .with_announced_server(false)
            .with_publish_relay_list(false)
            .with_bootstrap_relay_urls(Vec::new())
            // Requests from keys not listed are dropped before they are parsed.
            .with_allowed_public_keys(id.allowed.clone())
            .with_oversized_enabled(false)
            .with_server_info(ServerInfo::default().with_name("deadhop lnaddr gateway".to_string()));
        let transport = NostrServerTransport::with_relay_pool(transport_config, pool.clone())
            .await
            .map_err(crate::why)?;
        let transport = crate::handshake::local(IntoTransport::<RoleServer, _, _>::into_transport(transport));
        let cancel = CancellationToken::new();
        let ended = CancellationToken::new();
        let task = tokio::spawn({
            let (server, cancel, ended) = (
                GatewayServer::new(net.clone(), dir.clone()),
                cancel.clone(),
                ended.clone(),
            );
            async move {
                let outcome: Result<String, String> = async {
                    let running = server.serve_with_ct(transport, cancel).await.map_err(crate::why)?;
                    Ok(format!("{:?}", running.waiting().await))
                }
                .await;
                tracing::info!(?outcome, "console request loop ended");
                ended.cancel();
            }
        });
        net.set_server_pool(Some(pool.clone()));
        Ok(Link {
            net: net.clone(),
            routes,
            pool,
            cancel,
            ended,
            task,
        })
    }

    /// Move the relays whose route changed; the others keep their
    /// connections, and the request loop runs on.
    async fn reroute(&mut self, routes: Routes) -> Result<(), String> {
        let specs = route_specs(&routes).map_err(crate::why)?;
        self.pool.reroute(specs).await.map_err(crate::why)?;
        self.routes = routes;
        Ok(())
    }

    async fn close(self) {
        self.cancel.cancel();
        let _ = self.task.await;
        self.pool.client().disconnect().await;
        self.net.set_server_pool(None);
    }

    /// Whether any relay is connected right now.
    async fn connected(&self) -> bool {
        crate::pool::connected(&self.pool).await > 0
    }

    /// Whether any relay connects within `limit`.
    async fn connects_within(&self, limit: Duration) -> bool {
        let wait = async {
            while !self.connected().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        tokio::time::timeout(limit, wait).await.is_ok()
    }
}

/// Connect the console's server the way the network is set now: each relay
/// of the admin lane through its route, or (no server, kill switch, every
/// relay blocked) not at all. Why it is not running is kept for `get_health`.
pub async fn connect(id: &Option<Ident>, net: &Arc<Network>, dir: &Arc<Directory>) -> Result<Option<Link>, String> {
    let Some(id) = id else { return Ok(None) };
    let out = match net.runtime.lane_routes(&**net, ADMIN_LANE) {
        Some(routes) => Link::up(id, routes, net, dir).await.map(Some),
        None => Ok(None),
    };
    net.set_server_error(match &out {
        Ok(Some(_)) => None,
        Ok(None) => Some(NO_ROUTE.into()),
        Err(e) => Some(e.clone()),
    });
    out
}

/// Why the console's server is down when the admin key may not connect.
pub const NO_ROUTE: &str = "no relay of the admin key has a route now (kill switch, blocked, or its proxy is down)";

type RelaySetup = (Vec<String>, BTreeMap<String, Vec<String>>);

/// The relays and which lanes use them, as the gateway is set to now.
pub fn relay_setup(net: &Network) -> RelaySetup {
    let s = net.settings();
    (s.relays, s.relay_keys)
}

pub async fn close(link: &mut Option<Link>) {
    if let Some(l) = link.take() {
        l.close().await;
    }
}

/// Whether the link (if there is one) has no relay connected within `limit`.
pub async fn dead(link: &Option<Link>, limit: Duration) -> bool {
    match link {
        Some(l) => !l.connects_within(limit).await,
        None => false,
    }
}

/// Connect again with the live relays. If a new relay setup cannot connect,
/// go back to the previous one so the console can still reach the gateway.
async fn relink(
    id: &Option<Ident>,
    net: &Arc<Network>,
    dir: &Arc<Directory>,
    previous: RelaySetup,
) -> Result<Option<Link>, String> {
    if relay_setup(net) == previous {
        return connect(id, net, dir).await;
    }
    // New connections that cannot even start count as connections that do
    // not connect. The console's server must reach a relay, and the gateway
    // key at least one node.
    if let Ok(mut link) = connect(id, net, dir).await {
        if !dead(&link, RELAY_CHECK).await && dir.any_connects_within(RELAY_CHECK).await {
            return Ok(link);
        }
        close(&mut link).await;
    }
    tracing::warn!("no relay connected with the new settings; going back to the previous ones");
    net.revert_connection(previous.0, previous.1, "no relay connected with the new relays")?;
    net.drop_conns().await;
    connect(id, net, dir).await
}

/// Drop the saved relays and connect with the configured ones: they are
/// under the host's control, so they are the way back in.
pub async fn fall_back(
    id: &Option<Ident>,
    net: &Arc<Network>,
    dir: &Arc<Directory>,
    why: &str,
) -> Result<Option<Link>, String> {
    net.revert_connection(net.baseline().relays.clone(), BTreeMap::new(), why)?;
    net.drop_conns().await;
    connect(id, net, dir).await
}

/// What the watchdog does about the relays, given what it sees.
#[derive(Debug, PartialEq, Eq)]
enum Watch {
    /// A relay is connected.
    Fine,
    /// None is, but not for long enough to act.
    Wait,
    /// None has been for long, and the configured relays are in use already.
    Retry,
    /// None has been for long: go back to the configured relays.
    FallBack,
}

fn watch_action(connected: bool, silent_for: Duration, on_configured_relays: bool) -> Watch {
    if connected {
        Watch::Fine
    } else if silent_for < RELAY_DEAD_AFTER {
        Watch::Wait
    } else if on_configured_relays {
        Watch::Retry
    } else {
        Watch::FallBack
    }
}

/// The value, or (after logging why, and keeping it for `get_health`) no
/// connection: the gateway carries on serving and the next look tries again.
pub fn or_log(net: &Network, result: Result<Option<Link>, String>, what: &str) -> Option<Link> {
    result.unwrap_or_else(|e| {
        tracing::error!(error = %e, "{what}");
        net.set_server_error(Some(format!("{what}: {e}")));
        None
    })
}

/// What the supervisor works on.
pub struct Supervised {
    pub net: Arc<Network>,
    pub dir: Arc<Directory>,
    pub id: Option<Ident>,
    pub current: Arc<std::sync::Mutex<CancellationToken>>,
}

/// Keep the relay connections where the network says: remake them when the
/// relays change, move them when the proxy pool decides another way, go
/// back to the configured relays when saved ones have had nothing connected
/// for [`RELAY_DEAD_AFTER`], and bring the console's server back when its
/// request loop ends.
pub async fn supervise(s: Supervised, mut link: Option<Link>, stop: CancellationToken) {
    let Supervised { net, dir, id, current } = s;
    let mut watch = tokio::time::interval(RELAY_WATCH_EVERY);
    watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_connected = tokio::time::Instant::now();
    let mut live = relay_setup(&net);
    loop {
        *current.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            link.as_ref().map_or_else(CancellationToken::new, |l| l.cancel.clone());
        let ended = link.as_ref().map(|l| l.ended.clone());
        let request_loop_ended = async {
            match &ended {
                Some(t) => t.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        };
        // In this order: a change of relays is remade (and checked) by the
        // restart arm, never by a move of routes that happens to come first.
        tokio::select! {
            biased;
            _ = stop.cancelled() => {
                close(&mut link).await;
                return;
            }
            _ = net.restart_requested() => {
                tokio::time::sleep(RESTART_GRACE).await;
                close(&mut link).await;
                net.drop_conns().await;
                link = or_log(&net, relink(&id, &net, &dir, live.clone()).await, "could not remake the relay connections");
                live = relay_setup(&net);
                net.restarted();
                last_connected = tokio::time::Instant::now();
                tracing::info!(console = link.is_some(), "relay connections remade");
            }
            _ = request_loop_ended => {
                tracing::warn!("the console's request loop stopped; it is brought back on the next look");
                close(&mut link).await;
                net.set_server_error(Some("its request loop stopped; it is brought back shortly".into()));
            }
            _ = net.runtime.pool_changed() => {
                tokio::time::sleep(RESTART_GRACE).await;
                // Other relays are the restart arm's: it checks that they
                // connect and goes back if not. (Looked at after the pause,
                // so a relay change made meanwhile is left to it too.)
                if relay_setup(&net) != live {
                    continue;
                }
                net.move_conns().await;
                let want = net.runtime.lane_routes(&*net, ADMIN_LANE);
                if id.is_none() || want.as_ref() == link.as_ref().map(|l| &l.routes) {
                    continue;
                }
                match (&mut link, want) {
                    (Some(l), Some(routes)) if same_relays(&l.routes, &routes) => {
                        if let Err(e) = l.reroute(routes).await {
                            tracing::error!(error = %e, "could not move the console's relay connections");
                            close(&mut link).await;
                        }
                    }
                    _ => {
                        close(&mut link).await;
                        link = or_log(&net, connect(&id, &net, &dir).await, "could not move the console's relay connections");
                    }
                }
                last_connected = tokio::time::Instant::now();
                tracing::info!(console = link.is_some(), "relay connections moved");
            }
            _ = watch.tick() => {
                // No server: bring it back if it should run and may connect.
                if id.is_some() && link.is_none() && net.runtime.lane_routes(&*net, ADMIN_LANE).is_some() {
                    link = or_log(&net, connect(&id, &net, &dir).await, "could not bring the console's server back");
                    last_connected = tokio::time::Instant::now();
                    continue;
                }
                // The console's server (if it should run) and the gateway key
                // must each reach a relay; a server with no route at all
                // counts as one that reaches none.
                let console = match (&id, &link) {
                    (None, _) => true,
                    (Some(_), Some(l)) => l.connected().await,
                    (Some(_), None) => false,
                };
                let connected = console && dir.any_connected().await;
                let on_configured = {
                    let s = net.settings();
                    s.relays == net.baseline().relays && s.relay_keys.is_empty()
                };
                match watch_action(connected, last_connected.elapsed(), on_configured) {
                    Watch::Fine => last_connected = tokio::time::Instant::now(),
                    Watch::Wait => {}
                    Watch::Retry => {
                        last_connected = tokio::time::Instant::now();
                        tracing::warn!("no relay has been connected for a while; still retrying them");
                    }
                    Watch::FallBack => {
                        last_connected = tokio::time::Instant::now();
                        tracing::warn!("no relay has been connected for a while; going back to the configured relays");
                        close(&mut link).await;
                        link = or_log(&net, fall_back(&id, &net, &dir, DEAD_RELAYS).await, "could not go back to the configured relays");
                        live = relay_setup(&net);
                        net.restarted();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::network::GATEWAY_LANE;
    use crate::gateway::tests::{console_keys, stack, stack_with, Stack};
    use crate::node::backend::Kind;
    use crate::node::network::{read_network, write_network, NetworkFile, AUDIT_FILE, NETWORK_FILE};
    use crate::node::service::tests::caller;
    use deadhop_netengine::proxypool::{Applied, PoolState};
    use nostr_relay_builder::MockRelay;
    use serde_json::json;

    async fn eventually(what: &str, limit: Duration, f: impl Fn() -> bool) {
        let wait = async {
            while !f() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        assert!(
            tokio::time::timeout(limit, wait).await.is_ok(),
            "timed out waiting for {what}"
        );
    }

    fn last_audit(s: &Stack) -> (String, String) {
        let text = std::fs::read_to_string(s.cfg.data_dir.join(AUDIT_FILE)).unwrap();
        let v: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        (
            v["action"].as_str().unwrap().into(),
            v["detail"].as_str().unwrap().into(),
        )
    }

    fn update(net: &Network, patch: serde_json::Value) {
        let p = serde_json::from_value(json!({ "patch": patch })).unwrap();
        net.update_network(&caller(&console_keys()), p, None).unwrap();
    }

    /// Whether the console's server answers on `relay` within a few seconds.
    async fn console_answers(s: &Stack, relay: &str) -> bool {
        let server = s.gw().console.as_ref().unwrap().public_key();
        let c = crate::cvm::NodeClient::connect(
            console_keys(),
            &server,
            &[relay.to_string()],
            None,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let ok = c.call_value("get_info", json!({})).await.is_ok();
        c.close().await;
        ok
    }

    fn plan(net: &Network, lane: &str, url: &str) {
        net.runtime.pool.lock().unwrap().applied.insert(
            lane.into(),
            Applied {
                active: Some("socks5".into()),
                active_url: Some(url.into()),
                state: PoolState::Active,
                next_switch_at: None,
                reachable: 1,
            },
        );
    }

    #[test]
    fn the_watchdog_waits_retries_or_falls_back() {
        let long = RELAY_DEAD_AFTER + Duration::from_secs(1);
        assert_eq!(watch_action(true, long, false), Watch::Fine);
        assert_eq!(watch_action(false, Duration::ZERO, false), Watch::Wait);
        assert_eq!(watch_action(false, long, true), Watch::Retry);
        assert_eq!(watch_action(false, long, false), Watch::FallBack);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_relays_take_over_and_ones_that_do_not_connect_are_reverted() {
        let s = stack().await;
        let net = s.gw().net.clone();
        let second = MockRelay::run().await.unwrap();
        let second_url = second.url().await.to_string();
        // Asked to restart with nothing changed: the same relays again.
        net.schedule_restart();
        eventually("the restart", Duration::from_secs(10), || !net.restart_pending()).await;
        let both = vec![s.node_rig.relay_url.clone(), second_url.clone()];
        update(&net, json!({ "relays": both }));
        eventually("the new relays", Duration::from_secs(15), || !net.restart_pending()).await;
        assert_eq!(net.settings().relays, both);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            console_answers(&s, &second_url).await,
            "the console reaches it on the new relay"
        );
        // The node connections were remade: invoices still come.
        assert!(s.gw().dir.nodes[0].refresh().await.is_ok());
        // Relays nothing answers on (saved before the shared-relay rule): back.
        net.revert_connection(vec!["ws://127.0.0.1:9".into()], BTreeMap::new(), "test")
            .unwrap();
        net.schedule_restart();
        eventually("the revert", Duration::from_secs(15), || {
            last_audit(&s).1 == "no relay connected with the new relays"
        })
        .await;
        assert_eq!(net.settings().relays, both);
        assert_eq!(read_network(&s.cfg.data_dir).unwrap().relays, Some(both));
        s.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_route_move_leaves_new_relays_to_the_restart_that_checks_them() {
        let s = stack().await;
        let net = s.gw().net.clone();
        let mut moved = net.settings();
        moved.relays = vec!["ws://127.0.0.1:9".into()];
        net.set(moved);
        net.runtime.pool_switch.notify_one();
        tokio::time::sleep(RESTART_GRACE + Duration::from_millis(500)).await;
        // Still answering on the old relay: the move left the new ones alone.
        // Retried, since a loaded machine (the coverage run) can be slow to answer.
        let answers = async { while !console_answers(&s, &s.node_rig.relay_url).await {} };
        let answered = tokio::time::timeout(Duration::from_secs(10), answers).await;
        assert!(answered.is_ok(), "the console still reaches the old relay");
        net.schedule_restart();
        eventually("the revert", Duration::from_secs(15), || {
            net.settings().relays == [s.node_rig.relay_url.clone()]
        })
        .await;
        s.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relays_that_die_give_way_to_the_configured_ones() {
        let s = stack().await;
        let net = s.gw().net.clone();
        let second = MockRelay::run().await.unwrap();
        // Saved relays (from before the shared-relay rule): the console on a
        // second relay alone, the gateway key on the node's.
        let first = s.node_rig.relay_url.clone();
        let both = vec![first.clone(), second.url().await.to_string()];
        let keys = BTreeMap::from([(first, vec![GATEWAY_LANE.to_string()])]);
        net.revert_connection(both.clone(), keys, "test").unwrap();
        net.schedule_restart();
        eventually("the restart", Duration::from_secs(15), || !net.restart_pending()).await;
        assert_eq!(net.settings().relays, both, "kept: both lanes connect");
        second.shutdown();
        eventually("the fallback", Duration::from_secs(20), || {
            last_audit(&s).1 == DEAD_RELAYS
        })
        .await;
        assert_eq!(net.settings().relays, net.baseline().relays);
        s.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dead_configured_relays_are_only_retried() {
        let s = stack().await;
        s.node_rig.relay.shutdown();
        tokio::time::sleep(RELAY_DEAD_AFTER * 2 + Duration::from_secs(2)).await;
        assert_eq!(s.gw().net.settings().relays, s.gw().net.baseline().relays);
        s.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn saved_relays_that_are_dead_at_startup_give_way_to_the_configured_ones() {
        let s = stack_with(Kind::Lnd, |c| {
            let saved = NetworkFile {
                relays: Some(vec!["ws://127.0.0.1:9".into()]),
                ..Default::default()
            };
            write_network(&c.data_dir, &saved).unwrap();
        })
        .await;
        assert_eq!(s.gw().net.settings().relays, s.gw().net.baseline().relays);
        assert_eq!(last_audit(&s).1, DEAD_AT_START);
        // Saved settings that cannot be read do not stop the gateway: it runs
        // on its configuration and says so.
        std::fs::write(s.cfg.data_dir.join(NETWORK_FILE), "junk").unwrap();
        let again = crate::gateway::app::start(s.cfg.clone()).await.unwrap();
        assert!(again.net.warnings()[0].contains(NETWORK_FILE));
        assert_eq!(again.net.settings(), *again.net.baseline());
        again.until(Box::pin(async {})).await;
        s.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_proxy_pool_moves_the_relays_and_the_kill_switch_cuts_them() {
        let s = stack().await;
        let net = s.gw().net.clone();
        let (port, proxy) = deadhop_net::testing::socks5_proxy(None).await;
        // Woken with nothing to change: nothing moves.
        net.runtime.pool_switch.notify_one();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let url = format!("socks5://127.0.0.1:{port}");
        update(&net, json!({ "proxies": { "list": [{ "id": "p", "url": url }] } }));
        update(&net, json!({ "proxies": { "default": { "proxy": "p" } } }));
        let want = vec![(s.node_rig.relay_url.clone(), url.clone())];
        eventually("the move to the proxy", Duration::from_secs(10), || {
            net.runtime.lane_routes(&*net, ADMIN_LANE) == Some(want.clone())
                && net.runtime.lane_routes(&*net, GATEWAY_LANE) == Some(want.clone())
        })
        .await;
        tokio::time::sleep(RESTART_GRACE + Duration::from_millis(500)).await;
        assert!(console_answers(&s, &s.node_rig.relay_url).await);
        assert!(
            s.gw().dir.nodes[0].refresh().await.is_ok(),
            "invoices go through the proxy"
        );
        // The proxy goes away: the kill switch disconnects every relay.
        proxy.abort();
        eventually("the kill switch", Duration::from_secs(15), || {
            net.runtime.lane_routes(&*net, ADMIN_LANE).is_none()
        })
        .await;
        tokio::time::sleep(RESTART_GRACE + Duration::from_secs(1)).await;
        let states = deadhop_netengine::netruntime::NetworkHost::relay_states(&*net).await;
        assert!(states.iter().all(|r| !r.connected), "{states:?}");
        // The closed server's pool is not reported, and health says why.
        assert!(!net.has_server_pool());
        let w = net.warnings();
        assert!(w.iter().any(|w| w.contains(NO_ROUTE)), "{w:?}");
        assert!(
            s.gw().dir.nodes[0].refresh().await.is_err(),
            "no invoice request leaves"
        );
        s.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_console_whose_loop_ends_or_cannot_move_comes_back() {
        let (port, _proxy) = deadhop_net::testing::socks5_proxy(None).await;
        let url = format!("socks5://127.0.0.1:{port}");
        let s = stack_with(Kind::Lnd, |c| c.socks5 = Some(url.clone())).await;
        let net = s.gw().net.clone();
        let relay = s.node_rig.relay_url.clone();
        assert!(console_answers(&s, &relay).await);
        // The request loop ends: brought back on the next look.
        s.gw().current.lock().unwrap().cancel();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(console_answers(&s, &relay).await);
        // A route that cannot be used: the console goes, and stays away until
        // the route can be used again; the gateway serves on.
        s.gw().probe.abort();
        plan(&net, ADMIN_LANE, "unusable");
        net.runtime.pool_switch.notify_one();
        tokio::time::sleep(RESTART_GRACE + Duration::from_secs(1)).await;
        assert!(!console_answers(&s, &relay).await);
        let (status, _) = s.get("/.well-known/lnurlp/alice").await;
        assert_eq!(status, 200);
        plan(&net, ADMIN_LANE, &url);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(console_answers(&s, &relay).await);
        // New relays that cannot start, and no way back saved: the console
        // is gone, the gateway carries on.
        plan(&net, ADMIN_LANE, "unusable");
        let mut moved = net.settings();
        moved.relays = vec![relay.clone(), "ws://127.0.0.1:9".into()];
        net.set(moved);
        std::fs::create_dir(s.cfg.data_dir.join("network.tmp")).unwrap();
        net.schedule_restart();
        eventually("the restart", Duration::from_secs(15), || !net.restart_pending()).await;
        let (status, _) = s.get("/.well-known/lnurlp/alice").await;
        assert_eq!(status, 200);
        s.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn without_admins_no_console_runs_but_the_relays_are_still_kept() {
        let s = stack_with(Kind::Lnd, |c| c.admins.clear()).await;
        let net = s.gw().net.clone();
        assert!(s.gw().console.is_none() && net.key_infos()[1].tools.is_empty());
        net.runtime.pool_switch.notify_one();
        net.schedule_restart();
        eventually("the restart", Duration::from_secs(10), || !net.restart_pending()).await;
        tokio::time::sleep(RELAY_WATCH_EVERY * 2).await;
        assert!(s.gw().dir.nodes[0].refresh().await.is_ok());
        s.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn saved_relays_the_admin_key_has_no_route_on_give_way_to_the_configured_ones() {
        let s = stack().await;
        let net = s.gw().net.clone();
        let first = s.node_rig.relay_url.clone();
        // Saved: the only relay is the gateway key's; the console has none.
        let keys = BTreeMap::from([(first.clone(), vec![GATEWAY_LANE.to_string()])]);
        net.revert_connection(vec![first], keys, "test").unwrap();
        net.schedule_restart();
        eventually("the fallback", Duration::from_secs(20), || {
            last_audit(&s).1 == DEAD_RELAYS
        })
        .await;
        assert!(net.settings().relay_keys.is_empty());
        eventually("the console", Duration::from_secs(10), || net.has_server_pool()).await;
        s.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_relay_change_that_leaves_the_gateway_key_no_node_is_undone() {
        let s = stack_with(Kind::Lnd, |c| c.nodes[0].relays.push("ws://127.0.0.1:9".into())).await;
        let net = s.gw().net.clone();
        let first = s.node_rig.relay_url.clone();
        // The live relay for the admin key only: the gateway key keeps the
        // node's dead one, which the rules allow but nothing answers on.
        update(&net, json!({ "relay_keys": { first.clone(): ["admin"] } }));
        eventually("the revert", Duration::from_secs(20), || {
            last_audit(&s).1 == "no relay connected with the new relays"
        })
        .await;
        assert!(net.settings().relay_keys.is_empty());
        assert!(s.gw().dir.nodes[0].refresh().await.is_ok());
        s.stop().await;
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    #[tokio::test]
    async fn no_link_is_never_dead() {
        // Without a console server there is nothing to watch, so nothing to fall back from.
        assert!(!dead(&None, Duration::ZERO).await);
    }
}
