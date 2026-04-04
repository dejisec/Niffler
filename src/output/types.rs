use crate::pipeline::ResultMsg;

/// Composite key for deduplicating findings in the output sink.
///
/// Two findings are considered duplicates if they match the same rule
/// on the same file at the same export on the same host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeduplicationKey {
    pub host: String,
    pub export_path: String,
    pub file_path: String,
    pub rule_name: String,
}

impl DeduplicationKey {
    pub fn from_result(msg: &ResultMsg) -> Self {
        Self {
            host: msg.host.clone(),
            export_path: msg.export_path.clone(),
            file_path: msg.file_path.clone(),
            rule_name: msg.rule_name.clone(),
        }
    }
}

/// Convert Unix file permission bits to a 3-character owner permission string.
///
/// Extracts the owner (user) bits from a standard Unix mode and returns
/// an uppercase `"RWX"`-style string (e.g., `"RW-"` for mode 0o644).
pub fn file_mode_to_rwx(mode: u32) -> String {
    let owner = (mode >> 6) & 0o7;
    let r = if owner & 0o4 != 0 { 'R' } else { '-' };
    let w = if owner & 0o2 != 0 { 'W' } else { '-' };
    let x = if owner & 0o1 != 0 { 'X' } else { '-' };
    format!("{r}{w}{x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::Triage;
    use crate::pipeline::ResultMsg;
    use chrono::Utc;

    #[test]
    fn dedup_key_from_result_extracts_correct_fields() {
        let msg = ResultMsg {
            timestamp: Utc::now(),
            host: "nfs-server".into(),
            export_path: "/exports/home".into(),
            file_path: "user1/.ssh/id_rsa".into(),
            triage: Triage::Black,
            rule_name: "SSHPrivateKey".into(),
            matched_pattern: "id_rsa".into(),
            context: Some("key data".into()),
            file_size: 1700,
            file_mode: 0o644,
            file_uid: 1001,
            file_gid: 1001,
            last_modified: Utc::now(),
        };
        let key = DeduplicationKey::from_result(&msg);
        assert_eq!(key.host, "nfs-server");
        assert_eq!(key.export_path, "/exports/home");
        assert_eq!(key.file_path, "user1/.ssh/id_rsa");
        assert_eq!(key.rule_name, "SSHPrivateKey");
    }

    #[test]
    fn rwx_read_write_no_execute() {
        assert_eq!(file_mode_to_rwx(0o644), "RW-");
    }

    #[test]
    fn rwx_read_only() {
        assert_eq!(file_mode_to_rwx(0o444), "R--");
    }

    #[test]
    fn rwx_all_permissions() {
        assert_eq!(file_mode_to_rwx(0o755), "RWX");
    }

    #[test]
    fn rwx_no_permissions() {
        assert_eq!(file_mode_to_rwx(0o000), "---");
    }

    #[test]
    fn rwx_execute_only() {
        assert_eq!(file_mode_to_rwx(0o100), "--X");
    }

    #[test]
    fn rwx_write_execute() {
        assert_eq!(file_mode_to_rwx(0o310), "-WX");
    }
}
