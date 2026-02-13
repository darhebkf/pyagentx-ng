use std::fmt;
use std::time::Instant;

// Engine discovery state (RFC 3414 Section 4)
#[derive(Debug, Clone)]
pub struct EngineDiscovery {
    pub engine_id: Vec<u8>,
    pub engine_boots: i32,
    pub engine_time: i32,
    pub discovered_at: Instant,
}

impl EngineDiscovery {
    pub fn new(engine_id: Vec<u8>, engine_boots: i32, engine_time: i32) -> Self {
        Self {
            engine_id,
            engine_boots,
            engine_time,
            discovered_at: Instant::now(),
        }
    }

    // Estimated current engine time based on elapsed wall clock
    pub fn current_engine_time(&self) -> i32 {
        let elapsed = self.discovered_at.elapsed().as_secs() as i32;
        self.engine_time.saturating_add(elapsed)
    }

    // Check if time synchronization needed (RFC 3414 Section 2.3)
    //
    // Re-sync if outside 150 second window
    pub fn needs_time_sync(&self) -> bool {
        self.discovered_at.elapsed().as_secs() > 150
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    NoResponse,
    InvalidResponse,
    UnknownEngineId,
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::NoResponse => write!(f, "no response to discovery request"),
            DiscoveryError::InvalidResponse => write!(f, "invalid discovery response"),
            DiscoveryError::UnknownEngineId => write!(f, "unknown engine ID"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_discovery_new() {
        let discovery = EngineDiscovery::new(vec![0x80, 0x00, 0x01], 5, 1000);
        assert_eq!(discovery.engine_id, vec![0x80, 0x00, 0x01]);
        assert_eq!(discovery.engine_boots, 5);
        assert_eq!(discovery.engine_time, 1000);
    }

    #[test]
    fn test_current_engine_time() {
        let discovery = EngineDiscovery::new(vec![0x80], 0, 1000);
        // Should be at least 1000 (just created)
        assert!(discovery.current_engine_time() >= 1000);
    }

    #[test]
    fn test_needs_time_sync_fresh() {
        let discovery = EngineDiscovery::new(vec![0x80], 0, 0);
        // Just created, should not need sync
        assert!(!discovery.needs_time_sync());
    }
}
