use std::path::{Path, PathBuf};

use eva::data;

const MIB: u64 = 1024 * 1024;

/// Ceilings the machine enforces, and the fence around which paths it will
/// touch. Sent to the client in the handshake so it can refuse locally instead
/// of round-tripping a request that would only be denied.
#[data]
#[serde(default)]
pub struct Limits {
    pub max_read: u64,
    pub max_write: u64,
    pub max_hits: u64,
    pub max_output: u64,
    pub exec: bool,
    pub exec_timeout_secs: u64,
    pub exec_max_timeout_secs: u64,
    /// Paths the hands may reach. Empty means the whole filesystem.
    pub roots: Vec<PathBuf>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_read: 64 * MIB,
            max_write: 256 * MIB,
            max_hits: 4096,
            max_output: MIB,
            exec: true,
            exec_timeout_secs: 60,
            exec_max_timeout_secs: 3600,
            roots: Vec::new(),
        }
    }
}

impl Limits {
    /// Largest frame the wire will carry: the biggest body either side may send,
    /// plus room for the header.
    pub fn max_frame(&self) -> usize {
        (self.max_write.max(self.max_read) + 64 * 1024) as usize
    }

    /// A rough lexical fence, not a sandbox: `..` is folded before this runs, but
    /// symlinks are not resolved.
    pub fn allows(&self, path: &Path) -> bool {
        self.roots.is_empty() || self.roots.iter().any(|root| path.starts_with(root))
    }
}
