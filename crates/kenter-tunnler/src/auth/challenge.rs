use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

struct PendingChallenge {
    challenge_value: String,
    client_ip: IpAddr,
    created_at: Instant,
}

pub struct ChallengeStore {
    pending: DashMap<String, PendingChallenge>,
    used: DashMap<String, Instant>,
    ttl: Duration,
}

impl ChallengeStore {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            pending: DashMap::new(),
            used: DashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Generate a new challenge for the given client IP.
    /// Returns (challenge_id, challenge_value).
    pub fn generate(&self, client_ip: IpAddr) -> (String, String) {
        let challenge_id = hex::encode(rand::random::<[u8; 16]>());
        let challenge_value = hex::encode(rand::random::<[u8; 32]>());

        self.pending.insert(
            challenge_id.clone(),
            PendingChallenge {
                challenge_value: challenge_value.clone(),
                client_ip,
                created_at: Instant::now(),
            },
        );

        (challenge_id, challenge_value)
    }

    /// Verify and consume a challenge.
    /// Returns Ok(()) if the challenge is valid, single-use, not expired, and IP matches.
    pub fn verify(
        &self,
        challenge_id: &str,
        challenge_value: &str,
        client_ip: IpAddr,
    ) -> Result<(), String> {
        // Check if already used (replay prevention)
        if self.used.contains_key(challenge_id) {
            return Err("challenge already used".into());
        }

        // Remove from pending (single-use)
        let (_, pending) = self
            .pending
            .remove(challenge_id)
            .ok_or("unknown challenge_id")?;

        // Check expiration
        if pending.created_at.elapsed() > self.ttl {
            return Err("challenge expired".into());
        }

        // Check IP binding
        if pending.client_ip != client_ip {
            return Err("challenge IP mismatch".into());
        }

        // Check value
        if pending.challenge_value != challenge_value {
            return Err("challenge value mismatch".into());
        }

        // Mark as used
        self.used.insert(challenge_id.to_string(), Instant::now());

        Ok(())
    }

    /// Remove expired entries (call periodically).
    pub fn cleanup(&self) {
        let now = Instant::now();
        let ttl = self.ttl;

        self.pending.retain(|_, v| now.duration_since(v.created_at) < ttl);
        // Used challenges kept for 2x TTL to prevent replay
        let double_ttl = ttl * 2;
        self.used.retain(|_, v| now.duration_since(*v) < double_ttl);
    }
}
