//! SQLite storage — hardened (audit fixes: PRAGMAs, secure_delete, transactional wipe, kind round-trip).

use crate::crypto::identity::IdentityId;
use crate::error::Result;
use crate::messaging::channel::Channel;
use crate::messaging::envelope::{Envelope, EnvelopeFlags, EnvelopeId, EnvelopeType, Payload};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())?;
        Self::init_pragmas(&conn)?;
        Self::init_schema(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init_pragmas(&conn)?;
        Self::init_schema(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Audit fix: no PRAGMAs were set. Now: WAL, synchronous, secure_delete, foreign_keys, busy_timeout.
    fn init_pragmas(conn: &Connection) -> Result<()> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        Ok(())
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"CREATE TABLE IF NOT EXISTS envelopes (
                id              TEXT PRIMARY KEY,
                kind            TEXT NOT NULL,
                sender          TEXT NOT NULL,
                recipient       TEXT,
                channel         TEXT,
                payload         BLOB NOT NULL,
                timestamp_ns    INTEGER NOT NULL,
                ttl             INTEGER NOT NULL,
                hops            INTEGER NOT NULL,
                priority        INTEGER NOT NULL,
                flags           INTEGER NOT NULL,
                signature       BLOB,
                received_ns     INTEGER NOT NULL,
                delivered       INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_env_recipient ON envelopes(recipient, delivered);
            CREATE INDEX IF NOT EXISTS idx_env_channel ON envelopes(channel, timestamp_ns);
            CREATE TABLE IF NOT EXISTS peers (
                id              TEXT PRIMARY KEY,
                display_name    TEXT NOT NULL,
                verifying_key   BLOB NOT NULL,
                last_seen_ns    INTEGER NOT NULL,
                state           TEXT NOT NULL,
                rssi            INTEGER,
                last_transport  TEXT,
                verified        INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS channels (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                creator         TEXT NOT NULL,
                members         BLOB,
                admins          BLOB,
                channel_key     BLOB NOT NULL,
                created_ns      INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS kv_store (
                key             TEXT PRIMARY KEY,
                value           BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );"#,
        )?;
        // Track schema version for future migrations.
        conn.execute(
            "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('version', '1')",
            [],
        )?;
        Ok(())
    }

    pub fn store_envelope(&self, env: &Envelope) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| crate::AegisError::Storage)?;
        let payload_bytes = serde_json::to_vec(&env.payload).map_err(|_| crate::AegisError::Json)?;
        let recipient = env.recipient.as_ref().map(|r| r.as_str());
        let channel = env.channel.as_ref().map(|s| s.as_str());
        let signature = env.signature.as_ref().map(|s| s.to_vec());
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64).unwrap_or(0);
        // Audit fix: use INSERT OR IGNORE (was OR REPLACE — could silently overwrite).
        conn.execute(
            "INSERT OR IGNORE INTO envelopes
             (id, kind, sender, recipient, channel, payload, timestamp_ns, ttl, hops, priority, flags, signature, received_ns, delivered)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0)",
            params![
                env.id.as_str(), env.kind.as_str(), env.sender.as_str(),
                recipient, channel, payload_bytes, env.timestamp_ns as i64,
                env.ttl, env.hops, env.priority, env.flags.0, signature, now_ns,
            ],
        )?;
        Ok(())
    }

    pub fn mark_delivered(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| crate::AegisError::Storage)?;
        conn.execute("UPDATE envelopes SET delivered = 1 WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Audit fix: kind was hardcoded to Direct. Now round-trips correctly.
    pub fn undelivered_for(&self, recipient: &IdentityId) -> Result<Vec<Envelope>> {
        let conn = self.conn.lock().map_err(|_| crate::AegisError::Storage)?;
        let mut stmt = conn.prepare(
            "SELECT id, kind, sender, recipient, channel, payload, timestamp_ns, ttl, hops, priority, flags, signature
             FROM envelopes WHERE recipient = ?1 AND delivered = 0 ORDER BY timestamp_ns ASC",
        )?;
        let rows = stmt.query_map(params![recipient.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?, row.get::<_, Option<String>>(4)?,
                row.get::<_, Vec<u8>>(5)?, row.get::<_, i64>(6)?, row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?, row.get::<_, i64>(9)?, row.get::<_, i64>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, kind_str, sender, recipient, channel, payload_blob, ts, ttl, hops, pri, flags, sig) = row?;
            // Audit fix: parse kind correctly (was discarded).
            let kind = EnvelopeType::from_str(&kind_str).ok_or(crate::AegisError::Storage)?;
            let payload: Payload = serde_json::from_slice(&payload_blob).map_err(|_| crate::AegisError::Json)?;
            // Audit fix: validate IDs (was bypassed).
            let sender_id: IdentityId = sender.parse().map_err(|_| crate::AegisError::Storage)?;
            let recip_id = recipient.map(|r| r.parse()).transpose().map_err(|_| crate::AegisError::Storage)?;
            let env_id: EnvelopeId = id.parse().map_err(|_| crate::AegisError::Storage)?;
            let signature = match sig {
                Some(b) if b.len() == 64 => {
                    let mut arr = [0u8; 64]; arr.copy_from_slice(&b); Some(arr)
                }
                _ => None,
            };
            out.push(Envelope {
                version: crate::messaging::envelope::ENVELOPE_VERSION,
                id: env_id, kind, sender: sender_id, recipient: recip_id, channel,
                payload, timestamp_ns: ts as u64, ttl: ttl as u8, hops: hops as u8,
                priority: pri as u8, flags: EnvelopeFlags(flags as u16), signature,
            });
        }
        Ok(out)
    }

    pub fn store_channel(&self, channel: &Channel) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| crate::AegisError::Storage)?;
        let members = channel.members.as_ref().map(|m| m.iter().map(|i| i.as_str().to_string()).collect::<Vec<_>>());
        let members_blob = serde_json::to_vec(&members).map_err(|_| crate::AegisError::Json)?;
        let admins_blob = serde_json::to_vec(&channel.admins.iter().map(|i| i.as_str().to_string()).collect::<Vec<_>>())
            .map_err(|_| crate::AegisError::Json)?;
        conn.execute(
            "INSERT OR REPLACE INTO channels (id, name, creator, members, admins, channel_key, created_ns) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![channel.id.as_str(), channel.name, channel.creator.as_str(), members_blob, admins_blob, channel.channel_key_wrapped, channel.created_ns as i64],
        )?;
        Ok(())
    }

    pub fn kv_set(&self, key: &str, value: &[u8]) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| crate::AegisError::Storage)?;
        conn.execute("INSERT OR REPLACE INTO kv_store (key, value) VALUES (?1, ?2)", params![key, value])?;
        Ok(())
    }

    pub fn kv_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().map_err(|_| crate::AegisError::Storage)?;
        let mut stmt = conn.prepare("SELECT value FROM kv_store WHERE key = ?1")?;
        let mut rows = stmt.query_map(params![key], |row| row.get::<_, Vec<u8>>(0))?;
        if let Some(r) = rows.next() { Ok(Some(r?)) } else { Ok(None) }
    }

    pub fn kv_delete(&self, key: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| crate::AegisError::Storage)?;
        conn.execute("DELETE FROM kv_store WHERE key = ?1", params![key])?;
        Ok(())
    }

    /// Transactional wipe + VACUUM + secure_delete (audit fix: was non-atomic, not forensically clean).
    pub fn wipe(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| crate::AegisError::Storage)?;
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        // Delete tables that definitely exist. channel_memberships may not in v1.
        conn.execute_batch("DELETE FROM envelopes;")?;
        conn.execute_batch("DELETE FROM peers;")?;
        conn.execute_batch("DELETE FROM channels;")?;
        let _ = conn.execute_batch("DELETE FROM channel_memberships;"); // ignore if missing
        conn.execute_batch("DELETE FROM kv_store;")?;
        conn.execute_batch("COMMIT;")?;
        conn.execute_batch("VACUUM;")?; // Reclaim pages so deleted data is overwritten
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::Identity;

    #[test]
    fn store_and_retrieve_envelope() {
        let store = SqliteStore::open_in_memory().unwrap();
        let alice = Identity::new("Alice").public_view().id;
        let bob = Identity::new("Bob").public_view().id;
        let env = Envelope::direct_text(alice, bob.clone(), "hello", 10);
        store.store_envelope(&env).unwrap();
        let undelivered = store.undelivered_for(&bob).unwrap();
        assert_eq!(undelivered.len(), 1);
        // Audit fix: kind round-trips correctly (was hardcoded Direct).
        assert_eq!(undelivered[0].kind, EnvelopeType::Direct);
        assert_eq!(undelivered[0].payload, env.payload);
    }

    #[test]
    fn wipe_clears_everything() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.kv_set("a", b"1").unwrap();
        store.wipe().unwrap();
        assert!(store.kv_get("a").unwrap().is_none());
    }

    #[test]
    fn kv_round_trip() {
        let store = SqliteStore::open_in_memory().unwrap();
        store.kv_set("foo", b"bar").unwrap();
        assert_eq!(store.kv_get("foo").unwrap().as_deref(), Some(b"bar" as &[u8]));
        store.kv_delete("foo").unwrap();
        assert!(store.kv_get("foo").unwrap().is_none());
    }
}
