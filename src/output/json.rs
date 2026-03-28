use std::io::{self, Write};

use crate::pipeline::ResultMsg;

/// Write a single finding as a JSON Lines entry (one JSON object per line).
///
/// Uses `serde_json::to_string` on the `ResultMsg` (which derives `Serialize`),
/// then writes the resulting JSON followed by a newline. No wrapping array —
/// each call produces exactly one line suitable for `jq` piping and SIEM ingestion.
pub fn write_json(msg: &ResultMsg, writer: &mut dyn Write) -> io::Result<()> {
    let json = serde_json::to_string(msg).map_err(io::Error::other)?;
    writeln!(writer, "{json}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::Triage;
    use chrono::Utc;
    use serde_json::Value;

    fn make_msg(triage: Triage, context: Option<String>) -> ResultMsg {
        ResultMsg {
            timestamp: Utc::now(),
            host: "nfs-server".into(),
            export_path: "/exports/home".into(),
            file_path: "user1/.ssh/id_rsa".into(),
            triage,
            rule_name: "SSHPrivateKey".into(),
            matched_pattern: "id_rsa".into(),
            context,
            file_size: 1700,
            file_mode: 0o644,
            file_uid: 1001,
            file_gid: 1001,
            last_modified: Utc::now(),
        }
    }

    #[test]
    fn json_valid_json() {
        let msg = make_msg(
            Triage::Black,
            Some("-----BEGIN OPENSSH PRIVATE KEY-----".into()),
        );
        let mut buf = Vec::new();
        write_json(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: Result<Value, _> = serde_json::from_str(output.trim());
        assert!(parsed.is_ok(), "output should be valid JSON: {output}");
    }

    #[test]
    fn json_has_expected_fields() {
        let msg = make_msg(Triage::Red, Some("DB_PASSWORD=hunter2".into()));
        let mut buf = Vec::new();
        write_json(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let v: Value = serde_json::from_str(output.trim()).unwrap();
        let obj = v.as_object().expect("should be a JSON object");

        for key in [
            "timestamp",
            "host",
            "export_path",
            "file_path",
            "triage",
            "rule_name",
            "matched_pattern",
            "context",
            "file_size",
            "file_mode",
            "file_uid",
            "file_gid",
            "last_modified",
        ] {
            assert!(obj.contains_key(key), "JSON should contain key \"{key}\"");
        }
    }

    #[test]
    fn json_null_context() {
        let msg = make_msg(Triage::Yellow, None);
        let mut buf = Vec::new();
        write_json(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("\"context\":null"),
            "None context should serialize as null: {output}"
        );
    }

    #[test]
    fn json_triage_as_string() {
        let msg = make_msg(Triage::Black, None);
        let mut buf = Vec::new();
        write_json(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let v: Value = serde_json::from_str(output.trim()).unwrap();
        assert!(
            v["triage"].is_string(),
            "triage should serialize as a string, not integer: {:?}",
            v["triage"]
        );
        assert_eq!(v["triage"].as_str().unwrap(), "Black");
    }

    #[test]
    fn json_single_line() {
        let msg = make_msg(Triage::Green, Some("some context".into()));
        let mut buf = Vec::new();
        write_json(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let trimmed = output.trim();
        assert!(
            !trimmed.contains('\n'),
            "JSON output should be a single line: {trimmed}"
        );
    }
}
