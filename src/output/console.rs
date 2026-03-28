use std::io::{self, Write};

use bytesize::ByteSize;
use colored::Colorize;

use crate::classifier::Triage;
use crate::pipeline::ResultMsg;

use super::types::file_mode_to_rwx;

/// Write a single finding to the given writer in colored console format.
///
/// Format:
/// ```text
/// [{timestamp}] [{TRIAGE}] [{rule_name}] [{perms}] {host}:{export}/{path} ({size}, uid:{uid}, {date})
///     Context: "{context}"
/// ```
pub fn write_console(msg: &ResultMsg, writer: &mut dyn Write) -> io::Result<()> {
    let timestamp = msg.timestamp.format("%Y-%m-%d %H:%M:%S");
    let triage_upper = msg.triage.to_string().to_uppercase();
    let triage_colored = match msg.triage {
        Triage::Black => triage_upper.bright_red().bold().to_string(),
        Triage::Red => triage_upper.red().to_string(),
        Triage::Yellow => triage_upper.yellow().to_string(),
        Triage::Green => triage_upper.green().to_string(),
    };
    let perms = file_mode_to_rwx(msg.file_mode);
    let size = ByteSize(msg.file_size);
    let modified = msg.last_modified.format("%Y-%m-%d");

    writeln!(
        writer,
        "[{timestamp}] [{triage_colored}] [{}] [{perms}] {}:{}/{} ({size}, uid:{}, gid:{}, {modified})",
        msg.rule_name, msg.host, msg.export_path, msg.file_path, msg.file_uid, msg.file_gid,
    )?;

    if let Some(ref ctx) = msg.context {
        writeln!(writer, "    Context: \"{ctx}\"")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
            file_mode: 0o600,
            file_uid: 1001,
            file_gid: 1001,
            last_modified: Utc::now(),
        }
    }

    #[test]
    fn console_black_finding_format() {
        let msg = make_msg(Triage::Black, None);
        let mut buf = Vec::new();
        write_console(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("BLACK"), "should contain BLACK: {output}");
        assert!(output.contains("SSHPrivateKey"), "should contain rule name");
        assert!(output.contains("nfs-server"), "should contain host");
        assert!(
            output.contains("/exports/home"),
            "should contain export path"
        );
        assert!(output.contains("id_rsa"), "should contain file path");
        assert!(output.contains("uid:1001"), "should contain uid");
    }

    #[test]
    fn console_red_with_context() {
        let msg = make_msg(Triage::Red, Some("DB_PASSWORD=s3cretP@ss123".into()));
        let mut buf = Vec::new();
        write_console(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("RED"), "should contain RED: {output}");
        assert!(output.contains("Context:"), "should contain Context line");
        assert!(
            output.contains("DB_PASSWORD=s3cretP@ss123"),
            "should contain context string"
        );
        // Context line should be indented with 4 spaces
        let context_line = output.lines().find(|l| l.contains("Context:")).unwrap();
        assert!(
            context_line.starts_with("    "),
            "context line should be indented 4 spaces: {context_line:?}"
        );
    }

    #[test]
    fn console_green_no_context() {
        let msg = make_msg(Triage::Green, None);
        let mut buf = Vec::new();
        write_console(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("GREEN"), "should contain GREEN: {output}");
        assert!(
            !output.contains("Context:"),
            "should NOT contain Context when None"
        );
    }

    #[test]
    fn console_includes_rwx_perms() {
        let mut msg = make_msg(Triage::Green, None);
        msg.file_mode = 0o644;
        let mut buf = Vec::new();
        write_console(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("RW-"),
            "should contain RW- for mode 0o644: {output}"
        );
    }

    #[test]
    fn console_includes_human_readable_size() {
        let msg = make_msg(Triage::Green, None);
        let mut buf = Vec::new();
        write_console(&msg, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("1.7 KiB"),
            "should contain human-readable size '1.7 KiB': {output}"
        );
    }
}
