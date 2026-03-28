/// Extract context around a match position, sanitizing control characters.
pub fn extract_context(
    content: &str,
    match_start: usize,
    match_end: usize,
    context_bytes: usize,
) -> String {
    if content.is_empty() {
        return String::new();
    }

    let mut start = match_start.saturating_sub(context_bytes);
    while start > 0 && !content.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (match_end + context_bytes).min(content.len());
    while end < content.len() && !content.is_char_boundary(end) {
        end += 1;
    }
    let raw = &content[start..end];

    raw.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Extract context around a match position in raw bytes, hex-escaping non-printable bytes.
pub fn extract_context_bytes(
    content: &[u8],
    match_start: usize,
    match_end: usize,
    context_bytes: usize,
) -> String {
    if content.is_empty() {
        return String::new();
    }

    let start = match_start.saturating_sub(context_bytes);
    let end = (match_end + context_bytes).min(content.len());
    let raw = &content[start..end];

    raw.iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\t' {
                (b as char).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_match_at_middle() {
        let content = "before PASSWORD=secret after";
        let match_start = content.find("PASSWORD=secret").unwrap();
        let match_end = match_start + "PASSWORD=secret".len();
        let ctx = extract_context(content, match_start, match_end, 200);
        assert!(ctx.contains("PASSWORD=secret"));
        assert!(ctx.contains("before"));
        assert!(ctx.contains("after"));
    }

    #[test]
    fn context_match_at_start() {
        let content = "SECRET=val rest of file";
        let ctx = extract_context(content, 0, 10, 10);
        assert!(ctx.starts_with("SECRET=val"));
    }

    #[test]
    fn context_match_at_end() {
        let content = "preamble API_KEY=abc123";
        let match_start = content.find("API_KEY=abc123").unwrap();
        let match_end = content.len();
        let ctx = extract_context(content, match_start, match_end, 10);
        assert!(ctx.contains("API_KEY=abc123"));
        assert!(ctx.contains("preamble"));
    }

    #[test]
    fn context_clips_to_content_boundaries() {
        let content = "short content here!!";
        let ctx = extract_context(content, 5, 10, 1000);
        assert!(ctx.len() <= content.len());
    }

    #[test]
    fn context_strips_control_characters() {
        let content = "pass=\x01\x02value\x03";
        let ctx = extract_context(content, 0, content.len(), 200);
        assert!(ctx.contains("pass="));
        assert!(ctx.contains("value"));
        assert!(!ctx.contains('\x01'));
        assert!(!ctx.contains('\x02'));
        assert!(!ctx.contains('\x03'));
    }

    #[test]
    fn context_empty_content() {
        let ctx = extract_context("", 0, 0, 200);
        assert!(ctx.is_empty());
    }

    #[test]
    fn context_snaps_to_char_boundary() {
        // "café" — 'é' is 2 bytes (0xC3 0xA9), starts at byte index 3
        let content = "café=secret here";
        // context_bytes=2 from match_start=5 would land at byte 3, mid-char
        let match_start = content.find("=secret").unwrap(); // byte 5
        let match_end = match_start + "=secret".len();
        let ctx = extract_context(content, match_start, match_end, 2);
        assert!(ctx.contains("=secret"));
        // Should not panic, and should include 'é' since boundary snaps back
        assert!(ctx.contains('é'));
    }

    #[test]
    fn context_bytes_null_bytes_escaped() {
        let content: &[u8] = &[0x00, 0x41, 0x00];
        let ctx = extract_context_bytes(content, 0, 3, 0);
        assert!(ctx.contains("\\x00"));
        assert!(ctx.contains('A'));
    }

    #[test]
    fn context_bytes_empty_content() {
        let ctx = extract_context_bytes(&[], 0, 0, 200);
        assert!(ctx.is_empty());
    }

    #[test]
    fn context_bytes_extracts_around_match() {
        let content: &[u8] = &[0x41, 0x42, 0x30, 0x82, 0x03, 0x45, 0x43, 0x44];
        // match is bytes 2..4 (0x30, 0x82), context_bytes=1
        let ctx = extract_context_bytes(content, 2, 4, 1);
        // Should include B (0x42) before and \x03 after
        assert!(ctx.contains('B'));
        assert!(ctx.contains("\\x82"));
        assert!(ctx.contains("\\x03"));
    }

    #[test]
    fn context_bytes_printable_preserved() {
        let ctx = extract_context_bytes(b"hello world", 0, 5, 0);
        assert_eq!(ctx, "hello");
    }
}
