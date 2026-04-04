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
    /// Parse the file as key material (SSH, X.509).
    CheckForKeys,
}

impl MatchAction {
    /// Sort key for rule evaluation ordering: Discard first, then Snaffle,
    /// then Relay, then CheckForKeys. Matches Snaffler's discard-first
    /// optimization so cheap rejection fires before expensive content scans.
    pub fn sort_ordinal(&self) -> u8 {
        match self {
            MatchAction::Discard => 0,
            MatchAction::Snaffle => 1,
            MatchAction::Relay => 2,
            MatchAction::CheckForKeys => 3,
        }
    }
}
