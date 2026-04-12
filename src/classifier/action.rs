use serde::Deserialize;

/// Action to take when a classifier rule matches.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum MatchAction {
    /// Accept and record as a finding with the rule's triage severity.
    Snaffle,
    /// Reject and stop processing further rules for this item.
    Discard,
    /// Forward to relay_targets for further evaluation.
    Relay,
}

impl MatchAction {
    /// Sort key for rule evaluation ordering: Discard first, then Snaffle,
    /// then Relay. Matches Snaffler's discard-first optimization so cheap
    /// rejection fires before expensive content scans.
    #[must_use]
    pub const fn sort_ordinal(&self) -> u8 {
        match self {
            Self::Discard => 0,
            Self::Snaffle => 1,
            Self::Relay => 2,
        }
    }
}
