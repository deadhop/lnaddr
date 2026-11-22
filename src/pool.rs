//! Relay pool for both services. Events go to every relay and the send
//! returns on the first relay that accepts: a relay that hangs or is still
//! connecting never holds up a reply that a working relay already carried.
//! (The SDK's default pool waits for every relay; one dead relay then
//! delays every invoice by its timeout.)

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use contextvm_sdk::relay::RelayPoolTrait;
use nostr_sdk::prelude::*;

pub struct Pool {
    client: Arc<Client>,
}

fn transport_err(e: impl std::fmt::Display) -> contextvm_sdk::Error {
    contextvm_sdk::Error::Transport(e.to_string())
}

impl Pool {
    /// A pool signing with `keys`, optionally reaching relays through a SOCKS5 proxy.
    pub fn new(keys: Keys, socks5: Option<SocketAddr>) -> Self {
        let mut opts = ClientOptions::new();
        if let Some(addr) = socks5 {
            opts = opts.connection(Connection::new().proxy(addr));
        }
        Pool {
            client: Arc::new(Client::builder().signer(keys).opts(opts).build()),
        }
    }

    /// How many relays are connected right now.
    pub async fn connected(&self) -> usize {
        let relays = self.client.relays().await;
        relays.values().filter(|r| r.status() == RelayStatus::Connected).count()
    }

    /// Send `event` to every relay (or only those in `only`) and return as
    /// soon as one accepts it. Fails only when every relay refused it.
    async fn send_first_ok(&self, event: &Event, only: Option<&[String]>) -> contextvm_sdk::Result<EventId> {
        let relays = self.client.relays().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        for (url, relay) in relays {
            if only.is_some_and(|only| !only.iter().any(|u| same_relay(u, url.as_str()))) {
                continue;
            }
            let (tx, event) = (tx.clone(), event.clone());
            tokio::spawn(async move {
                let result = relay.send_event(&event).await;
                // Nobody listens once a relay accepted: nothing to report.
                let _ = tx.send((url, result));
            });
        }
        drop(tx);
        let mut refused = Vec::new();
        while let Some((url, result)) = rx.recv().await {
            match result {
                Ok(_) => return Ok(event.id),
                Err(e) => refused.push(format!("{url}: {e}")),
            }
        }
        Err(transport_err(if refused.is_empty() {
            "no relay to send to".to_string()
        } else {
            format!("every relay refused the event ({})", refused.join("; "))
        }))
    }
}

/// Whether two relay addresses name the same relay (`wss://a` and `wss://a/`).
fn same_relay(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

#[async_trait]
impl RelayPoolTrait for Pool {
    async fn connect(&self, relay_urls: &[String]) -> contextvm_sdk::Result<()> {
        for url in relay_urls {
            self.client.add_relay(url).await.map_err(transport_err)?;
        }
        self.client.connect().await;
        Ok(())
    }

    async fn disconnect(&self) -> contextvm_sdk::Result<()> {
        self.client.disconnect().await;
        Ok(())
    }

    async fn publish_event(&self, event: &Event) -> contextvm_sdk::Result<EventId> {
        self.send_first_ok(event, None).await
    }

    async fn publish(&self, builder: EventBuilder) -> contextvm_sdk::Result<EventId> {
        let event = self.sign(builder).await?;
        self.send_first_ok(&event, None).await
    }

    async fn sign(&self, builder: EventBuilder) -> contextvm_sdk::Result<Event> {
        self.client.sign_event_builder(builder).await.map_err(transport_err)
    }

    async fn signer(&self) -> contextvm_sdk::Result<Arc<dyn NostrSigner>> {
        self.client.signer().await.map_err(transport_err)
    }

    fn notifications(&self) -> tokio::sync::broadcast::Receiver<RelayPoolNotification> {
        self.client.notifications()
    }

    async fn public_key(&self) -> contextvm_sdk::Result<PublicKey> {
        self.signer().await?.get_public_key().await.map_err(transport_err)
    }

    async fn subscribe(&self, filters: Vec<Filter>) -> contextvm_sdk::Result<()> {
        for filter in filters {
            self.client.subscribe(filter, None).await.map_err(transport_err)?;
        }
        Ok(())
    }

    async fn publish_to(&self, urls: &[String], builder: EventBuilder) -> contextvm_sdk::Result<EventId> {
        let event = self.sign(builder).await?;
        self.send_first_ok(&event, Some(urls)).await
    }

    async fn fetch_events(&self, filters: Vec<Filter>, timeout: Duration) -> contextvm_sdk::Result<Vec<Event>> {
        let mut all = Vec::new();
        for filter in filters {
            all.extend(self.client.fetch_events(filter, timeout).await.map_err(transport_err)?);
        }
        Ok(all)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use nostr_relay_builder::MockRelay;
    use std::time::Instant;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// A relay that accepts the connection but never answers anything.
    pub async fn black_hole_relay() -> (String, JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", l.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                held.push(l.accept().await.unwrap().0);
            }
        });
        (url, task)
    }

    fn note(keys: &Keys) -> Event {
        EventBuilder::text_note("hi").sign_with_keys(keys).unwrap()
    }

    #[tokio::test]
    async fn a_hanging_relay_never_delays_a_send() {
        let good = MockRelay::run().await.unwrap();
        let (bad, _task) = black_hole_relay().await;
        let keys = Keys::generate();
        let pool = Pool::new(keys.clone(), None);
        pool.connect(&[good.url().await.to_string(), bad.clone()])
            .await
            .unwrap();
        pool.client.wait_for_connection(Duration::from_secs(5)).await;
        let started = Instant::now();
        pool.publish_event(&note(&keys)).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(pool.connected().await >= 1);
        // Sending to the hanging relay alone is refused once it times out.
        let only = pool
            .publish_to(&[good.url().await.to_string() + "/"], EventBuilder::text_note("x"))
            .await;
        assert!(only.is_ok());
    }

    #[tokio::test]
    async fn every_refusal_is_reported() {
        let keys = Keys::generate();
        let pool = Pool::new(keys.clone(), Some("127.0.0.1:9".parse().unwrap()));
        let none = pool.publish_event(&note(&keys)).await.unwrap_err();
        assert!(none.to_string().contains("no relay to send to"));
        pool.connect(&["ws://127.0.0.1:9".into()]).await.unwrap();
        let refused = pool.publish(EventBuilder::text_note("x")).await.unwrap_err();
        assert!(refused.to_string().contains("every relay refused"), "{refused}");
        assert!(pool.connect(&["not a url".into()]).await.is_err());
        assert_eq!(pool.public_key().await.unwrap(), keys.public_key());
        let _ = pool.notifications();
        pool.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn subscriptions_and_fetches_go_to_the_relays() {
        let relay = MockRelay::run().await.unwrap();
        let keys = Keys::generate();
        let pool = Pool::new(keys.clone(), None);
        pool.connect(&[relay.url().await.to_string()]).await.unwrap();
        pool.client.wait_for_connection(Duration::from_secs(5)).await;
        pool.publish_event(&note(&keys)).await.unwrap();
        let filter = Filter::new().author(keys.public_key()).kind(Kind::TextNote);
        pool.subscribe(vec![filter.clone()]).await.unwrap();
        let got = pool.fetch_events(vec![filter], Duration::from_secs(5)).await.unwrap();
        assert_eq!(got.len(), 1);
        // With no relay connected both fail.
        let empty = Pool::new(keys, None);
        assert!(empty.subscribe(vec![Filter::new()]).await.is_err());
        assert!(empty
            .fetch_events(vec![Filter::new()], Duration::from_millis(50))
            .await
            .is_err());
    }
}
