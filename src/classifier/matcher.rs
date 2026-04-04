use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::bytes::{Regex as BytesRegex, RegexSet as BytesRegexSet};
use regex::{Regex, RegexSet};

use super::rule::MatchType;

/// Compile-once, match-many pattern matcher supporting all 6 match types.
pub struct TextMatcher {
    inner: MatcherInner,
}

enum MatcherInner {
    Exact(Vec<String>),
    Contains {
        ac: AhoCorasick,
        sources: Vec<String>,
    },
    StartsWith(Vec<String>),
    EndsWith(Vec<String>),
    Regex {
        set: RegexSet,
        patterns: Vec<Regex>,
        sources: Vec<String>,
        bytes_set: BytesRegexSet,
        bytes_patterns: Vec<BytesRegex>,
    },
    Glob {
        set: GlobSet,
        sources: Vec<String>,
    },
}

impl TextMatcher {
    /// Compile patterns into an efficient matcher for the given match type.
    ///
    /// All patterns are compiled at construction time — no per-match compilation.
    pub fn new(match_type: &MatchType, patterns: &[String]) -> Result<Self> {
        let inner = match match_type {
            MatchType::Exact => MatcherInner::Exact(patterns.to_vec()),
            MatchType::Contains => {
                let ac = AhoCorasick::new(patterns)
                    .context("failed to compile AhoCorasick automaton")?;
                MatcherInner::Contains {
                    ac,
                    sources: patterns.to_vec(),
                }
            }
            MatchType::StartsWith => MatcherInner::StartsWith(patterns.to_vec()),
            MatchType::EndsWith => MatcherInner::EndsWith(patterns.to_vec()),
            MatchType::Regex => {
                let set = RegexSet::new(patterns).context("failed to compile regex set")?;
                let individual: Vec<Regex> = patterns
                    .iter()
                    .map(|p| Regex::new(p))
                    .collect::<Result<_, _>>()
                    .context("failed to compile individual regex patterns")?;
                // Prepend (?-u) to disable Unicode mode for byte-level matching.
                // This ensures \xHH matches raw byte values, not UTF-8 encoded
                // Unicode codepoints (e.g. \x82 matches byte 0x82, not U+0082).
                let byte_patterns: Vec<String> =
                    patterns.iter().map(|p| format!("(?-u){p}")).collect();
                let bytes_set = BytesRegexSet::new(&byte_patterns)
                    .context("failed to compile byte regex set")?;
                let bytes_individual: Vec<BytesRegex> = byte_patterns
                    .iter()
                    .map(|p| BytesRegex::new(p))
                    .collect::<Result<_, _>>()
                    .context("failed to compile individual byte regex patterns")?;
                MatcherInner::Regex {
                    set,
                    patterns: individual,
                    sources: patterns.to_vec(),
                    bytes_set,
                    bytes_patterns: bytes_individual,
                }
            }
            MatchType::Glob => {
                let mut builder = GlobSetBuilder::new();
                for pat in patterns {
                    let glob = Glob::new(pat)
                        .with_context(|| format!("failed to parse glob pattern: {pat}"))?;
                    builder.add(glob);
                }
                let set = builder.build().context("failed to build glob set")?;
                MatcherInner::Glob {
                    set,
                    sources: patterns.to_vec(),
                }
            }
        };
        Ok(Self { inner })
    }

    /// Returns true if any compiled pattern matches the input.
    pub fn is_match(&self, input: &str) -> bool {
        match &self.inner {
            MatcherInner::Exact(patterns) => patterns.iter().any(|p| p == input),
            MatcherInner::Contains { ac, .. } => ac.is_match(input),
            MatcherInner::StartsWith(patterns) => {
                patterns.iter().any(|p| input.starts_with(p.as_str()))
            }
            MatcherInner::EndsWith(patterns) => {
                patterns.iter().any(|p| input.ends_with(p.as_str()))
            }
            MatcherInner::Regex { set, .. } => set.is_match(input),
            MatcherInner::Glob { set, .. } => set.is_match(input),
        }
    }

    /// Returns the byte `(start, end)` of the first match, or `None`.
    pub fn find_match(&self, input: &str) -> Option<(usize, usize)> {
        match &self.inner {
            MatcherInner::Exact(patterns) => {
                for p in patterns {
                    if let Some(pos) = input.find(p.as_str()) {
                        return Some((pos, pos + p.len()));
                    }
                }
                None
            }
            MatcherInner::Contains { ac, .. } => ac.find(input).map(|m| (m.start(), m.end())),
            MatcherInner::StartsWith(patterns) => {
                for p in patterns {
                    if input.starts_with(p.as_str()) {
                        return Some((0, p.len()));
                    }
                }
                None
            }
            MatcherInner::EndsWith(patterns) => {
                for p in patterns {
                    if input.ends_with(p.as_str()) {
                        return Some((input.len() - p.len(), input.len()));
                    }
                }
                None
            }
            MatcherInner::Regex { set, patterns, .. } => {
                for idx in set.matches(input) {
                    if let Some(m) = patterns[idx].find(input) {
                        return Some((m.start(), m.end()));
                    }
                }
                None
            }
            MatcherInner::Glob { set, .. } => {
                if set.is_match(input) {
                    Some((0, input.len()))
                } else {
                    None
                }
            }
        }
    }

    /// Returns true if any compiled pattern matches the byte input.
    pub fn is_match_bytes(&self, input: &[u8]) -> bool {
        match &self.inner {
            MatcherInner::Exact(patterns) => patterns.iter().any(|p| p.as_bytes() == input),
            MatcherInner::Contains { ac, .. } => ac.is_match(input),
            MatcherInner::StartsWith(patterns) => {
                patterns.iter().any(|p| input.starts_with(p.as_bytes()))
            }
            MatcherInner::EndsWith(patterns) => {
                patterns.iter().any(|p| input.ends_with(p.as_bytes()))
            }
            MatcherInner::Regex { bytes_set, .. } => bytes_set.is_match(input),
            MatcherInner::Glob { set, .. } => {
                let lossy = String::from_utf8_lossy(input);
                set.is_match(lossy.as_ref())
            }
        }
    }

    /// Returns the byte `(start, end)` of the first match on byte input, or `None`.
    pub fn find_match_bytes(&self, input: &[u8]) -> Option<(usize, usize)> {
        match &self.inner {
            MatcherInner::Exact(patterns) => {
                for p in patterns {
                    let pb = p.as_bytes();
                    if let Some(pos) = input.windows(pb.len()).position(|w| w == pb) {
                        return Some((pos, pos + pb.len()));
                    }
                }
                None
            }
            MatcherInner::Contains { ac, .. } => ac.find(input).map(|m| (m.start(), m.end())),
            MatcherInner::StartsWith(patterns) => {
                for p in patterns {
                    if input.starts_with(p.as_bytes()) {
                        return Some((0, p.len()));
                    }
                }
                None
            }
            MatcherInner::EndsWith(patterns) => {
                for p in patterns {
                    let pb = p.as_bytes();
                    if input.ends_with(pb) {
                        return Some((input.len() - pb.len(), input.len()));
                    }
                }
                None
            }
            MatcherInner::Regex {
                bytes_set,
                bytes_patterns,
                ..
            } => {
                for idx in bytes_set.matches(input) {
                    if let Some(m) = bytes_patterns[idx].find(input) {
                        return Some((m.start(), m.end()));
                    }
                }
                None
            }
            MatcherInner::Glob { set, .. } => {
                let lossy = String::from_utf8_lossy(input);
                if set.is_match(lossy.as_ref()) {
                    Some((0, input.len()))
                } else {
                    None
                }
            }
        }
    }

    /// Returns the source pattern string of the first matching pattern on byte input, or `None`.
    pub fn matched_pattern_str_bytes(&self, input: &[u8]) -> Option<String> {
        match &self.inner {
            MatcherInner::Exact(patterns) => {
                patterns.iter().find(|p| p.as_bytes() == input).cloned()
            }
            MatcherInner::Contains { ac, sources } => ac
                .find(input)
                .map(|m| sources[m.pattern().as_usize()].clone()),
            MatcherInner::StartsWith(patterns) => patterns
                .iter()
                .find(|p| input.starts_with(p.as_bytes()))
                .cloned(),
            MatcherInner::EndsWith(patterns) => patterns
                .iter()
                .find(|p| input.ends_with(p.as_bytes()))
                .cloned(),
            MatcherInner::Regex {
                bytes_set, sources, ..
            } => bytes_set
                .matches(input)
                .iter()
                .next()
                .map(|idx| sources[idx].clone()),
            MatcherInner::Glob { set, sources } => {
                let lossy = String::from_utf8_lossy(input);
                set.matches(lossy.as_ref())
                    .first()
                    .map(|&idx| sources[idx].clone())
            }
        }
    }

    /// Returns the source pattern string of the first matching pattern, or `None`.
    pub fn matched_pattern_str(&self, input: &str) -> Option<String> {
        match &self.inner {
            MatcherInner::Exact(patterns) => patterns.iter().find(|p| *p == input).cloned(),
            MatcherInner::Contains { ac, sources } => ac
                .find(input)
                .map(|m| sources[m.pattern().as_usize()].clone()),
            MatcherInner::StartsWith(patterns) => patterns
                .iter()
                .find(|p| input.starts_with(p.as_str()))
                .cloned(),
            MatcherInner::EndsWith(patterns) => patterns
                .iter()
                .find(|p| input.ends_with(p.as_str()))
                .cloned(),
            MatcherInner::Regex { set, sources, .. } => set
                .matches(input)
                .iter()
                .next()
                .map(|idx| sources[idx].clone()),
            MatcherInner::Glob { set, sources } => {
                set.matches(input).first().map(|&idx| sources[idx].clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_case_insensitive() {
        let m = TextMatcher::new(&MatchType::Regex, &[s(r"(?i)password\s*[=:]")]).unwrap();
        assert!(m.is_match("PASSWORD = secret"));
    }

    #[test]
    fn find_match_regex_returns_position() {
        let m = TextMatcher::new(&MatchType::Regex, &[s(r"(?i)password\s*=\s*\S+")]).unwrap();
        let input = "some config\nPASSWORD = secret\nmore stuff";
        let (start, end) = m.find_match(input).unwrap();
        assert_eq!(&input[start..end], "PASSWORD = secret");
    }

    #[test]
    fn find_match_contains_returns_position() {
        let m = TextMatcher::new(&MatchType::Contains, &[s("secret")]).unwrap();
        let input = "prefix_secret_suffix";
        let (start, end) = m.find_match(input).unwrap();
        assert_eq!(&input[start..end], "secret");
    }

    #[test]
    fn find_match_starts_with_returns_position() {
        let m = TextMatcher::new(&MatchType::StartsWith, &[s("BEGIN")]).unwrap();
        let input = "BEGIN RSA PRIVATE KEY";
        let (start, end) = m.find_match(input).unwrap();
        assert_eq!(start, 0);
        assert_eq!(&input[start..end], "BEGIN");
    }

    #[test]
    fn find_match_ends_with_returns_position() {
        let m = TextMatcher::new(&MatchType::EndsWith, &[s(".pem")]).unwrap();
        let input = "server.pem";
        let (start, end) = m.find_match(input).unwrap();
        assert_eq!(&input[start..end], ".pem");
        assert_eq!(end, input.len());
    }

    #[test]
    fn find_match_exact_returns_position() {
        let m = TextMatcher::new(&MatchType::Exact, &[s("id_rsa")]).unwrap();
        let input = "id_rsa";
        let (start, end) = m.find_match(input).unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, input.len());
    }

    #[test]
    fn find_match_glob_returns_full_input_range() {
        let m = TextMatcher::new(&MatchType::Glob, &[s("**/.ssh/*")]).unwrap();
        let input = ".ssh/id_rsa";
        assert_eq!(m.find_match(input), Some((0, input.len())));
    }

    #[test]
    fn bytes_exact_match_with_null_bytes() {
        let m = TextMatcher::new(&MatchType::Exact, &[s("\x00\x01\x02")]).unwrap();
        assert!(m.is_match_bytes(&[0x00, 0x01, 0x02]));
    }

    #[test]
    fn bytes_contains_magic_number() {
        let m = TextMatcher::new(&MatchType::Contains, &[s("%PDF")]).unwrap();
        assert!(m.is_match_bytes(b"\x00\x00%PDF-1.4\x00"));
    }

    #[test]
    fn bytes_starts_with_positive() {
        let m = TextMatcher::new(&MatchType::StartsWith, &[s("MZ")]).unwrap();
        assert!(m.is_match_bytes(b"MZ\x90\x00"));
    }

    #[test]
    fn bytes_regex_hex_escape_pattern() {
        let m = TextMatcher::new(&MatchType::Regex, &[s(r"\x30\x82")]).unwrap();
        assert!(m.is_match_bytes(&[0x30, 0x82, 0x03, 0x45]));
    }

    #[test]
    fn bytes_glob_falls_back_to_lossy() {
        let m = TextMatcher::new(&MatchType::Glob, &[s("*.pem")]).unwrap();
        assert!(m.is_match_bytes(b"cert.pem"));
    }

    #[test]
    fn find_bytes_contains_returns_position() {
        let m = TextMatcher::new(&MatchType::Contains, &[s("magic")]).unwrap();
        let input = b"\x00\x00magic\x00\x00";
        let (start, end) = m.find_match_bytes(input).unwrap();
        assert_eq!(&input[start..end], b"magic");
    }

    #[test]
    fn find_bytes_regex_returns_position() {
        let m = TextMatcher::new(&MatchType::Regex, &[s(r"\x30\x82..")]).unwrap();
        let input: &[u8] = &[0x00, 0x30, 0x82, 0x03, 0x45, 0x00];
        let (start, end) = m.find_match_bytes(input).unwrap();
        assert_eq!(&input[start..end], &[0x30, 0x82, 0x03, 0x45]);
    }

    #[test]
    fn matched_pattern_bytes_regex_returns_source() {
        let m = TextMatcher::new(&MatchType::Regex, &[s(r"\x30\x82")]).unwrap();
        let input: &[u8] = &[0x30, 0x82, 0x03, 0x45];
        assert_eq!(m.matched_pattern_str_bytes(input), Some(s(r"\x30\x82")));
    }

    #[test]
    fn matched_pattern_bytes_contains_returns_source() {
        let m = TextMatcher::new(&MatchType::Contains, &[s("magic")]).unwrap();
        assert_eq!(
            m.matched_pattern_str_bytes(b"\x00magic\x00"),
            Some(s("magic"))
        );
    }

    /// Helper to create owned strings for pattern slices.
    fn s(val: &str) -> String {
        val.to_string()
    }
}
