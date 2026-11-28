//! The invoices this node made, so it can say later whether one was paid and
//! which LUD-12 comment came with it.
//!
//! Kept in `invoices.jsonl` in the data directory: one line per invoice made
//! and one per settlement seen, owner-only, rewritten in full when it has
//! grown to twice what it holds. A gateway decides how many invoices are made,
//! so what is kept is bounded: an unpaid invoice is dropped an hour after it
//! expired, and past [`MAX_RECORDS`] the unpaid and then the oldest go first.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const FILE: &str = "invoices.jsonl";
/// How long an unpaid invoice is kept after it expired.
pub const KEEP_EXPIRED_SECS: u64 = 3600;
/// How long after expiry the backend is still asked: a payment can be in
/// flight when the invoice expires.
pub const LATE_SECS: u64 = 300;
/// Most invoices kept.
pub const MAX_RECORDS: usize = 100_000;

/// One invoice this node made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub payment_hash: String,
    pub name: String,
    pub domain: String,
    pub amount_msat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub pr: String,
    pub created_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
}

impl Record {
    /// `settled`, `pending` or `expired`.
    pub fn state(&self, now: u64) -> &'static str {
        if self.settled_at.is_some() {
            "settled"
        } else if now > self.expires_at {
            "expired"
        } else {
            "pending"
        }
    }

    /// Whether the backend may still report it paid.
    pub fn open(&self, now: u64) -> bool {
        self.settled_at.is_none() && now <= self.expires_at + LATE_SECS
    }

    fn kept(&self, now: u64) -> bool {
        self.settled_at.is_some() || now <= self.expires_at + KEEP_EXPIRED_SECS
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Line {
    Made(Record),
    Settled {
        payment_hash: String,
        settled_at: u64,
        preimage: String,
    },
}

pub struct Ledger {
    path: PathBuf,
    records: HashMap<String, Record>,
    /// Lines in the file now.
    lines: usize,
    file: Option<File>,
    /// Why the file could not be read; nothing is written over it then.
    broken: Option<String>,
}

impl Ledger {
    /// What `dir` holds. A file that cannot be read is left alone, and the
    /// node goes on making invoices without recording them.
    pub fn open(dir: &Path, now: u64) -> Ledger {
        let path = dir.join(FILE);
        let mut l = Ledger {
            path,
            records: HashMap::new(),
            lines: 0,
            file: None,
            broken: None,
        };
        match crate::files::read_private(&l.path) {
            Ok(text) => {
                for line in text.unwrap_or_default().lines() {
                    // A line cut short by a crash is skipped.
                    if let Ok(line) = serde_json::from_str::<Line>(line) {
                        l.apply(line);
                    }
                }
                l.prune(now);
                l.compact();
            }
            Err(e) => {
                tracing::error!(error = %e, "the invoice record cannot be read; invoices are not recorded");
                l.broken = Some(e);
            }
        }
        l
    }

    fn apply(&mut self, line: Line) {
        match line {
            Line::Made(r) => {
                self.records.insert(r.payment_hash.clone(), r);
            }
            Line::Settled {
                payment_hash,
                settled_at,
                preimage,
            } => {
                if let Some(r) = self.records.get_mut(&payment_hash) {
                    r.settled_at = Some(settled_at);
                    r.preimage = Some(preimage);
                }
            }
        }
    }

    /// Why invoices are not recorded, if they are not.
    pub fn broken(&self) -> Option<&str> {
        self.broken.as_deref()
    }

    pub fn get(&self, payment_hash: &str) -> Option<&Record> {
        self.records.get(payment_hash)
    }

    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.values()
    }

    /// Hold a record without writing it.
    #[cfg(test)]
    pub fn insert(&mut self, r: Record) {
        self.records.insert(r.payment_hash.clone(), r);
    }

    /// Record an invoice just made.
    pub fn add(&mut self, r: Record, now: u64) -> Result<(), String> {
        let line = Line::Made(r);
        self.write(&line)?;
        self.apply(line);
        if self.lines > 2 * self.records.len() + 1024 || self.records.len() > MAX_RECORDS {
            self.prune(now);
            self.compact();
        }
        Ok(())
    }

    /// Record that an invoice was paid.
    pub fn settle(&mut self, payment_hash: &str, settled_at: u64, preimage: &str) -> Result<(), String> {
        let line = Line::Settled {
            payment_hash: payment_hash.into(),
            settled_at,
            preimage: preimage.into(),
        };
        self.write(&line)?;
        self.apply(line);
        Ok(())
    }

    fn write(&mut self, line: &Line) -> Result<(), String> {
        if let Some(e) = &self.broken {
            return Err(e.clone());
        }
        let text = serde_json::to_string(line).expect("a record always serialises") + "\n";
        let append = |slot: &mut Option<File>, path: &Path| -> std::io::Result<()> {
            if slot.is_none() {
                *slot = Some(OpenOptions::new().append(true).create(true).mode(0o600).open(path)?);
            }
            let f = slot.as_mut().expect("opened above");
            f.write_all(text.as_bytes())?;
            f.sync_data()
        };
        append(&mut self.file, &self.path).map_err(|e| {
            self.file = None;
            format!("{}: {e}", self.path.display())
        })?;
        self.lines += 1;
        Ok(())
    }

    fn prune(&mut self, now: u64) {
        self.records.retain(|_, r| r.kept(now));
        if self.records.len() > MAX_RECORDS {
            // Unpaid ones go first, then the oldest.
            let mut by_age: Vec<(bool, u64, String)> = self
                .records
                .values()
                .map(|r| (r.settled_at.is_some(), r.created_at, r.payment_hash.clone()))
                .collect();
            by_age.sort();
            for (_, _, h) in &by_age[..by_age.len() - MAX_RECORDS] {
                self.records.remove(h);
            }
        }
    }

    /// Rewrite the file with what is kept now.
    fn compact(&mut self) {
        let mut all: Vec<&Record> = self.records.values().collect();
        all.sort_by(|a, b| (a.created_at, &a.payment_hash).cmp(&(b.created_at, &b.payment_hash)));
        let mut text = String::new();
        for r in &all {
            text += &serde_json::to_string(&Line::Made((*r).clone())).expect("a record always serialises");
            text.push('\n');
        }
        self.file = None;
        match crate::files::write_private(&self.path, &text) {
            Ok(()) => self.lines = all.len(),
            Err(e) => tracing::warn!(error = %e, "could not rewrite the invoice record"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub fn record(hash: &str, created_at: u64) -> Record {
        Record {
            payment_hash: hash.into(),
            name: "alice".into(),
            domain: "pay.example".into(),
            amount_msat: 21_000,
            comment: Some("thanks".into()),
            pr: "lnbcrt1".into(),
            created_at,
            expires_at: created_at + 600,
            settled_at: None,
            preimage: None,
        }
    }

    #[test]
    fn states_follow_the_clock() {
        let mut r = record("a", 1000);
        assert_eq!(r.state(1000), "pending");
        assert!(r.open(1600 + LATE_SECS));
        assert_eq!(r.state(1601), "expired");
        assert!(!r.open(1601 + LATE_SECS));
        assert!(r.kept(1600 + KEEP_EXPIRED_SECS) && !r.kept(1601 + KEEP_EXPIRED_SECS));
        r.settled_at = Some(1200);
        assert_eq!(r.state(9999), "settled");
        assert!(!r.open(1200) && r.kept(u64::MAX));
    }

    #[test]
    fn records_survive_a_restart_and_old_unpaid_ones_go() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = Ledger::open(dir.path(), 1000);
        assert!(l.broken().is_none() && l.records().next().is_none());
        l.add(record("a", 1000), 1000).unwrap();
        l.add(record("b", 1001), 1001).unwrap();
        l.settle("b", 1100, "pre").unwrap();
        // A settlement for an invoice not made here changes nothing.
        l.settle("zz", 1100, "pre").unwrap();
        drop(l);
        let path = dir.path().join(FILE);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // A line cut short by a crash.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"made\":{\"payment").unwrap();

        let l = Ledger::open(dir.path(), 1100);
        assert_eq!(l.get("a").unwrap().comment.as_deref(), Some("thanks"));
        let b = l.get("b").unwrap();
        assert_eq!((b.settled_at, b.preimage.as_deref()), (Some(1100), Some("pre")));
        assert_eq!(l.lines, 2, "rewritten on open");
        drop(l);

        let l = Ledger::open(dir.path(), 1600 + KEEP_EXPIRED_SECS + 1);
        assert!(l.get("a").is_none(), "unpaid and long expired");
        assert!(l.get("b").is_some(), "paid ones stay");
    }

    #[test]
    fn the_file_is_rewritten_when_it_grows_and_the_oldest_go_past_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = Ledger::open(dir.path(), 0);
        l.add(record("a", 0), 0).unwrap();
        for _ in 0..1030 {
            l.settle("a", 1, "p").unwrap();
        }
        assert_eq!(l.lines, 1031);
        l.add(record("b", 0), 0).unwrap();
        assert_eq!(l.lines, 2, "rewritten");

        for i in 0..MAX_RECORDS as u64 + 5 {
            l.records.insert(format!("y{i}"), record(&format!("y{i}"), 100 + i));
        }
        l.prune(0);
        assert_eq!(l.records.len(), MAX_RECORDS);
        assert!(l.get("a").is_some(), "paid ones are kept the longest");
        assert!(l.get("b").is_none() && l.get("y5").is_none() && l.get("y6").is_some());
    }

    #[test]
    fn an_unreadable_file_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE);
        std::fs::write(&path, "{}\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut l = Ledger::open(dir.path(), 0);
        assert!(l.broken().unwrap().contains("readable by other users"));
        assert!(l.add(record("a", 0), 0).is_err());
        assert!(l.settle("a", 0, "p").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}\n");
    }

    #[test]
    fn write_failures_are_reported_and_retried() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = Ledger::open(dir.path(), 0);
        l.path = dir.path().join("missing").join(FILE);
        assert!(l.add(record("a", 0), 0).unwrap_err().contains("missing"));
        assert!(l.file.is_none());
        // A rewrite that fails keeps the old count and logs.
        l.lines = 7;
        l.compact();
        assert_eq!(l.lines, 7);
    }
}
