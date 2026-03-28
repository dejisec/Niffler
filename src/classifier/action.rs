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
