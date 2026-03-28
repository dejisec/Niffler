use std::io::{self, Write};

use crate::pipeline::ResultMsg;

use super::types::file_mode_to_rwx;

/// Replace tabs, newlines, and carriage returns with spaces to preserve TSV row structure.
fn sanitize_tsv_field(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || c == '\r' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Write a single finding as a tab-separated line.
///
/// Column order:
/// ```text
/// {timestamp}\t{triage}\t{rule}\t{perms}\t{pattern}\t{size}\t{host}:{export}/{path}\t{context}
/// ```
///
/// No header row is emitted. Context column contains the content snippet (empty if none).
/// Tabs and newlines in all fields are replaced with spaces to preserve row structure.
pub fn write_tsv(msg: &ResultMsg, writer: &mut dyn Write) -> io::Result<()> {
    let timestamp = msg.timestamp.format("%Y-%m-%d %H:%M:%S");
    let perms = file_mode_to_rwx(msg.file_mode);
    let context = msg.context.as_deref().unwrap_or("");

    writeln!(
        writer,
        "{timestamp}\t{triage}\t{rule}\t{perms}\t{pattern}\t{size}\t{host}:{export}/{path}\t{context}",
        triage = msg.triage,
        rule = sanitize_tsv_field(&msg.rule_name),
        pattern = sanitize_tsv_field(&msg.matched_pattern),
        size = msg.file_size,
        host = sanitize_tsv_field(&msg.host),
        export = sanitize_tsv_field(&msg.export_path),
        path = sanitize_tsv_field(&msg.file_path),
        context = sanitize_tsv_field(context),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::Triage;
    use chrono::Utc;

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
    fn tsv_eight_columns() {
        let msg = make_msg(Triage::Black, None);
        let mut buf = Vec::new();
        write_tsv(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.trim_end_matches('\n').split('\t').collect();
        assert_eq!(
            fields.len(),
            8,
            "TSV should have exactly 8 columns: {output}"
        );
    }

    #[test]
    fn tsv_column_order() {
        let msg = make_msg(Triage::Black, Some("some context".into()));
        let mut buf = Vec::new();
        write_tsv(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.trim().split('\t').collect();

        // Column 0: timestamp (date + time format)
        assert!(
            fields[0].contains(':') && fields[0].contains('-'),
            "column 0 should be a timestamp: {}",
            fields[0]
        );
        // Column 1: triage name
        assert_eq!(fields[1], "Black");
        // Column 2: rule name
        assert_eq!(fields[2], "SSHPrivateKey");
        // Column 3: permissions in RWX format
        assert_eq!(fields[3], "RW-");
        // Column 4: matched pattern
        assert_eq!(fields[4], "id_rsa");
        // Column 5: file size (numeric)
        assert_eq!(fields[5], "1700");
        // Column 6: full path as host:export/path
        assert_eq!(fields[6], "nfs-server:/exports/home/user1/.ssh/id_rsa");
        // Column 7: context snippet
        assert_eq!(fields[7], "some context");
    }

    #[test]
    fn tsv_no_header() {
        let msg = make_msg(Triage::Green, None);
        let mut buf = Vec::new();
        write_tsv(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            !output.to_lowercase().starts_with("timestamp"),
            "TSV should NOT have a header row: {output}"
        );
    }

    #[test]
    fn tsv_perms_format() {
        let mut msg = make_msg(Triage::Red, None);
        msg.file_mode = 0o644;
        let mut buf = Vec::new();
        write_tsv(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.trim().split('\t').collect();
        assert_eq!(
            fields[3], "RW-",
            "perms column should be RW- for mode 0o644"
        );
    }

    #[test]
    fn tsv_empty_context_when_none() {
        let msg = make_msg(Triage::Yellow, None);
        let mut buf = Vec::new();
        write_tsv(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.trim_end_matches('\n').split('\t').collect();
        assert_eq!(fields[7], "", "context column should be empty when None");
    }

    #[test]
    fn tsv_context_sanitizes_tabs_and_newlines() {
        let msg = make_msg(Triage::Red, Some("line1\tvalue\nline2\rline3".into()));
        let mut buf = Vec::new();
        write_tsv(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.trim().split('\t').collect();
        assert_eq!(fields.len(), 8, "should still be 8 columns: {output}");
        assert_eq!(
            fields[7], "line1 value line2 line3",
            "tabs and newlines should be replaced with spaces"
        );
    }

    #[test]
    fn tsv_sanitizes_pattern_with_tab() {
        let mut msg = make_msg(Triage::Red, None);
        msg.matched_pattern = "pat\tern".into();
        let mut buf = Vec::new();
        write_tsv(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.trim_end_matches('\n').split('\t').collect();
        assert_eq!(
            fields.len(),
            8,
            "tab in pattern must not break column count: {output}"
        );
    }

    #[test]
    fn tsv_sanitizes_rule_name_with_newline() {
        let mut msg = make_msg(Triage::Red, None);
        msg.rule_name = "rule\nname".into();
        let mut buf = Vec::new();
        write_tsv(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let line_count = output.trim_end().lines().count();
        assert_eq!(
            line_count, 1,
            "newline in rule_name must not break row structure"
        );
    }

    #[test]
    fn tsv_path_includes_host_export() {
        let msg = make_msg(Triage::Yellow, None);
        let mut buf = Vec::new();
        write_tsv(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let fields: Vec<&str> = output.trim().split('\t').collect();
        assert_eq!(
            fields[6], "nfs-server:/exports/home/user1/.ssh/id_rsa",
            "last column should be host:export/path"
        );
    }
}
