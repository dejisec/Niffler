use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail};

use crate::scanner::is_likely_binary;

use super::action::MatchAction;
use super::matcher::TextMatcher;
use super::rule::{ClassifierRule, EnumerationScope, MatchLocation};
use super::triage::Triage;

/// Maximum relay chain depth before truncation.
const MAX_RELAY_DEPTH: usize = 5;

/// Lightweight file metadata for classifier evaluation.
///
/// Not the full `FileMsg` — contains only the metadata fields needed for rule matching.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub extension: String,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// A classifier finding — a rule matched with a severity.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub triage: Triage,
    pub rule_name: String,
    pub matched_pattern: String,
    pub context: Option<String>,
}

/// Result of evaluating a single rule against an entry.
#[derive(Debug)]
pub enum RuleResult {
    Snaffle(Finding),
    Discard,
    Relay(Vec<String>),
    CheckForKeys,
    NoMatch,
}

/// Compiled rule engine with scope-partitioned rules and pre-compiled matchers.
///
/// Built via [`RuleEngine::compile()`], which partitions rules by scope,
/// compiles a [`TextMatcher`] for each rule, and builds a name-to-rule index
/// for relay target resolution.
pub struct RuleEngine {
    share_rules: Vec<ClassifierRule>,
    dir_rules: Vec<ClassifierRule>,
    file_rules: Vec<ClassifierRule>,
    content_rules: Vec<ClassifierRule>,

    /// Name -> Rule for relay target resolution.
    rule_index: HashMap<String, ClassifierRule>,

    /// Compiled matchers keyed by rule name.
    matchers: HashMap<String, TextMatcher>,
}

impl RuleEngine {
    /// Compile rules into a partitioned, matcher-ready engine.
    ///
    /// Partitions rules by [`EnumerationScope`], builds a name-to-rule index,
    /// and compiles a [`TextMatcher`] for each rule's patterns.
    pub fn compile(rules: Vec<ClassifierRule>) -> Result<Self> {
        let mut share_rules = Vec::new();
        let mut dir_rules = Vec::new();
        let mut file_rules = Vec::new();
        let mut content_rules = Vec::new();
        let mut rule_index = HashMap::new();
        let mut matchers = HashMap::new();

        for rule in rules {
            let matcher = TextMatcher::new(&rule.match_type, &rule.patterns)
                .with_context(|| format!("failed to compile matcher for rule '{}'", rule.name))?;
            matchers.insert(rule.name.clone(), matcher);
            if rule_index.contains_key(&rule.name) {
                bail!("duplicate rule name: '{}'", rule.name);
            }
            rule_index.insert(rule.name.clone(), rule.clone());

            match rule.scope {
                EnumerationScope::ShareEnumeration => share_rules.push(rule),
                EnumerationScope::DirectoryEnumeration => dir_rules.push(rule),
                EnumerationScope::FileEnumeration => file_rules.push(rule),
                EnumerationScope::ContentsEnumeration => content_rules.push(rule),
            }
        }

        share_rules.sort_by_key(|r| r.action.sort_ordinal());
        dir_rules.sort_by_key(|r| r.action.sort_ordinal());
        file_rules.sort_by_key(|r| r.action.sort_ordinal());
        content_rules.sort_by_key(|r| r.action.sort_ordinal());

        Ok(Self {
            share_rules,
            dir_rules,
            file_rules,
            content_rules,
            rule_index,
            matchers,
        })
    }

    /// Verify that every relay target references a rule that exists.
    pub fn validate_relay_targets(&self) -> Result<()> {
        for rule in self.rule_index.values() {
            if rule.action != MatchAction::Relay {
                continue;
            }
            if let Some(targets) = &rule.relay_targets {
                for target in targets {
                    if !self.rule_index.contains_key(target) {
                        bail!(
                            "rule '{}' has dangling relay target '{}'",
                            rule.name,
                            target
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Detect circular relay chains via depth-first traversal.
    pub fn detect_relay_cycles(&self) -> Result<()> {
        for rule in self.rule_index.values() {
            if rule.action != MatchAction::Relay {
                continue;
            }
            let mut visited = HashSet::new();
            self.check_cycle(&rule.name, &mut visited)?;
        }
        Ok(())
    }

    fn check_cycle(&self, name: &str, visited: &mut HashSet<String>) -> Result<()> {
        if !visited.insert(name.to_string()) {
            bail!("relay cycle detected involving rule '{name}'");
        }
        if let Some(rule) = self.rule_index.get(name)
            && rule.action == MatchAction::Relay
            && let Some(targets) = &rule.relay_targets
        {
            for target in targets {
                self.check_cycle(target, visited)?;
            }
        }
        visited.remove(name);
        Ok(())
    }

    /// Verify that every rule's scope/match_location combination is valid.
    pub fn validate_scope_location(&self) -> Result<()> {
        for rule in self.rule_index.values() {
            if !is_valid_scope_location(&rule.scope, &rule.match_location) {
                bail!(
                    "rule '{}' has invalid scope/location combination: {:?}/{:?}",
                    rule.name,
                    rule.scope,
                    rule.match_location
                );
            }
        }
        Ok(())
    }

    pub fn share_rules(&self) -> &[ClassifierRule] {
        &self.share_rules
    }

    pub fn dir_rules(&self) -> &[ClassifierRule] {
        &self.dir_rules
    }

    pub fn file_rules(&self) -> &[ClassifierRule] {
        &self.file_rules
    }

    pub fn content_rules(&self) -> &[ClassifierRule] {
        &self.content_rules
    }

    pub fn rule_count(&self) -> usize {
        self.rule_index.len()
    }

    pub fn matcher(&self, rule_name: &str) -> Option<&TextMatcher> {
        self.matchers.get(rule_name)
    }

    /// Returns the `context_bytes` setting for a rule, if defined.
    pub fn context_bytes(&self, rule_name: &str) -> Option<usize> {
        self.rule_index.get(rule_name).and_then(|r| r.context_bytes)
    }

    /// Returns the match location for a rule, if defined.
    pub fn match_location(&self, rule_name: &str) -> Option<&MatchLocation> {
        self.rule_index.get(rule_name).map(|r| &r.match_location)
    }

    /// Evaluate file enumeration rules, then follow relay chains.
    ///
    /// If the file has a `.bak` extension, a second pass re-evaluates
    /// extension-based rules using the underlying extension (e.g.,
    /// `secrets.kdbx.bak` is also evaluated as extension `kdbx`).
    pub fn evaluate_file(&self, entry: &FileEntry, content: Option<&[u8]>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for rule in &self.file_rules {
            match self.eval_rule(rule, entry, content) {
                RuleResult::Snaffle(finding) => findings.push(finding),
                RuleResult::Discard => return findings,
                RuleResult::Relay(targets) => {
                    self.follow_relay(&targets, entry, content, &mut findings, 1);
                }
                RuleResult::CheckForKeys | RuleResult::NoMatch => {}
            }
        }

        if entry.extension == "bak"
            && let Some(underlying) = strip_bak_extension(&entry.name)
        {
            let mut alt = entry.clone();
            alt.extension = underlying;
            for rule in &self.file_rules {
                if rule.match_location != MatchLocation::FileExtension {
                    continue;
                }
                match self.eval_rule(rule, &alt, content) {
                    RuleResult::Snaffle(finding) => findings.push(finding),
                    RuleResult::Discard => return findings,
                    RuleResult::Relay(targets) => {
                        self.follow_relay(&targets, &alt, content, &mut findings, 1);
                    }
                    RuleResult::CheckForKeys | RuleResult::NoMatch => {}
                }
            }
        }

        findings
    }

    /// Check whether an export path should be skipped during discovery.
    pub fn should_discard_export(&self, export_path: &str) -> bool {
        for rule in &self.share_rules {
            if rule.action != MatchAction::Discard {
                continue;
            }
            if let Some(matcher) = self.matchers.get(&rule.name)
                && matcher.is_match(export_path)
            {
                return true;
            }
        }
        false
    }

    /// Check whether a directory should be pruned during tree walking.
    pub fn should_discard_dir(&self, dir_name: &str, dir_path: &str) -> bool {
        for rule in &self.dir_rules {
            if rule.action != MatchAction::Discard {
                continue;
            }
            if let Some(matcher) = self.matchers.get(&rule.name) {
                let input = match rule.match_location {
                    MatchLocation::FileName => dir_name,
                    MatchLocation::FilePath => dir_path,
                    _ => continue,
                };
                if matcher.is_match(input) {
                    return true;
                }
            }
        }
        false
    }

    fn eval_rule(
        &self,
        rule: &ClassifierRule,
        entry: &FileEntry,
        content: Option<&[u8]>,
    ) -> RuleResult {
        if let Some(max) = rule.max_size
            && entry.size > max
        {
            return RuleResult::NoMatch;
        }

        let matcher = match self.matchers.get(&rule.name) {
            Some(m) => m,
            None => return RuleResult::NoMatch,
        };

        // FileContentAsBytes: match directly on raw &[u8] without lossy conversion.
        if rule.match_location == MatchLocation::FileContentAsBytes {
            let data = match content {
                Some(d) => d,
                None => return RuleResult::NoMatch,
            };
            if !matcher.is_match_bytes(data) {
                return RuleResult::NoMatch;
            }
            return match &rule.action {
                MatchAction::Snaffle => {
                    let pat = matcher
                        .matched_pattern_str_bytes(data)
                        .unwrap_or_else(|| rule.name.clone());
                    RuleResult::Snaffle(Finding {
                        triage: rule.triage.unwrap_or(Triage::Yellow),
                        rule_name: rule.name.clone(),
                        matched_pattern: pat,
                        context: None,
                    })
                }
                MatchAction::Discard => RuleResult::Discard,
                MatchAction::Relay => {
                    RuleResult::Relay(rule.relay_targets.clone().unwrap_or_default())
                }
                MatchAction::CheckForKeys => RuleResult::CheckForKeys,
            };
        }

        // Extract the input string based on match_location.
        // Owned values are needed for numeric-to-string conversions.
        let owned;
        let input: &str = match rule.match_location {
            MatchLocation::FileName => &entry.name,
            MatchLocation::FileExtension => &entry.extension,
            MatchLocation::FilePath | MatchLocation::ExportPath => &entry.path,
            MatchLocation::FileLength => {
                owned = entry.size.to_string();
                &owned
            }
            MatchLocation::FileOwnerUid => {
                owned = entry.uid.to_string();
                &owned
            }
            MatchLocation::FileOwnerGid => {
                owned = entry.gid.to_string();
                &owned
            }
            MatchLocation::FileMode => {
                owned = format!("{:o}", entry.mode & 0o7777);
                &owned
            }
            MatchLocation::FileContentAsString => match content {
                Some(data) if !is_likely_binary(data) => {
                    owned = String::from_utf8_lossy(data).into_owned();
                    &owned
                }
                _ => return RuleResult::NoMatch,
            },
            // FileContentAsBytes is handled above via early return.
            MatchLocation::FileContentAsBytes => unreachable!(),
        };

        if !matcher.is_match(input) {
            return RuleResult::NoMatch;
        }

        match &rule.action {
            MatchAction::Snaffle => {
                let pat = matcher
                    .matched_pattern_str(input)
                    .unwrap_or_else(|| rule.name.clone());
                RuleResult::Snaffle(Finding {
                    triage: rule.triage.unwrap_or(Triage::Yellow),
                    rule_name: rule.name.clone(),
                    matched_pattern: pat,
                    context: None,
                })
            }
            MatchAction::Discard => RuleResult::Discard,
            MatchAction::Relay => RuleResult::Relay(rule.relay_targets.clone().unwrap_or_default()),
            MatchAction::CheckForKeys => RuleResult::CheckForKeys,
        }
    }

    fn follow_relay(
        &self,
        targets: &[String],
        entry: &FileEntry,
        content: Option<&[u8]>,
        findings: &mut Vec<Finding>,
        depth: usize,
    ) {
        if depth > MAX_RELAY_DEPTH {
            tracing::debug!(
                "relay chain depth limit ({}) reached for {}",
                MAX_RELAY_DEPTH,
                entry.path,
            );
            return;
        }

        for target_name in targets {
            if let Some(target_rule) = self.rule_index.get(target_name) {
                match self.eval_rule(target_rule, entry, content) {
                    RuleResult::Snaffle(f) => findings.push(f),
                    RuleResult::Discard => return,
                    RuleResult::Relay(more) => {
                        self.follow_relay(&more, entry, content, findings, depth + 1);
                    }
                    RuleResult::CheckForKeys | RuleResult::NoMatch => {}
                }
            }
        }
    }
}

/// Extract the underlying extension from a `.bak` filename.
///
/// `"secrets.kdbx.bak"` → `Some("kdbx")`, `"notes.bak"` → `None`.
fn strip_bak_extension(filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".bak")?;
    let dot_pos = stem.rfind('.')?;
    Some(stem[dot_pos + 1..].to_string())
}

fn is_valid_scope_location(scope: &EnumerationScope, location: &MatchLocation) -> bool {
    matches!(
        (scope, location),
        (
            EnumerationScope::ShareEnumeration,
            MatchLocation::ExportPath
        ) | (
            EnumerationScope::DirectoryEnumeration,
            MatchLocation::FilePath | MatchLocation::FileName
        ) | (
            EnumerationScope::FileEnumeration,
            MatchLocation::FileName
                | MatchLocation::FileExtension
                | MatchLocation::FilePath
                | MatchLocation::FileLength
                | MatchLocation::FileOwnerUid
                | MatchLocation::FileOwnerGid
                | MatchLocation::FileMode
        ) | (
            EnumerationScope::ContentsEnumeration,
            MatchLocation::FileContentAsString | MatchLocation::FileContentAsBytes
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::rule::MatchType;
    use crate::classifier::triage::Triage;

    #[allow(clippy::too_many_arguments)]
    fn make_rule(
        name: &str,
        scope: EnumerationScope,
        match_location: MatchLocation,
        match_type: MatchType,
        patterns: Vec<String>,
        action: MatchAction,
        triage: Option<Triage>,
        relay_targets: Option<Vec<String>>,
    ) -> ClassifierRule {
        ClassifierRule {
            name: name.to_string(),
            scope,
            match_location,
            match_type,
            patterns,
            action,
            triage,
            relay_targets,
            max_size: None,
            context_bytes: None,
            description: None,
        }
    }

    fn s(val: &str) -> String {
        val.to_string()
    }

    #[test]
    fn strip_bak_extracts_underlying_extension() {
        assert_eq!(
            super::strip_bak_extension("secrets.kdbx.bak"),
            Some("kdbx".to_string())
        );
        assert_eq!(
            super::strip_bak_extension("web.config.bak"),
            Some("config".to_string())
        );
        assert_eq!(super::strip_bak_extension("notes.bak"), None);
        assert_eq!(super::strip_bak_extension("data"), None);
        assert_eq!(super::strip_bak_extension(".bak"), None);
    }

    #[test]
    fn compile_sorts_discard_before_snaffle() {
        // Insert in wrong order: Snaffle, Relay, Discard
        let rules = vec![
            make_rule(
                "SnaffleFirst",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("foo")],
                MatchAction::Snaffle,
                Some(Triage::Green),
                None,
            ),
            make_rule(
                "RelaySecond",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("bar")],
                MatchAction::Relay,
                None,
                Some(vec![s("SnaffleFirst")]),
            ),
            make_rule(
                "DiscardThird",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileExtension,
                MatchType::Exact,
                vec![s("jpg")],
                MatchAction::Discard,
                None,
                None,
            ),
        ];

        let engine = RuleEngine::compile(rules).unwrap();
        let file_rules = engine.file_rules();

        assert_eq!(
            file_rules[0].action,
            MatchAction::Discard,
            "Discard should be first"
        );
        assert_eq!(
            file_rules[1].action,
            MatchAction::Snaffle,
            "Snaffle should be second"
        );
        assert_eq!(
            file_rules[2].action,
            MatchAction::Relay,
            "Relay should be third"
        );
    }

    #[test]
    fn compile_partitions_rules_by_scope() {
        let rules = vec![
            make_rule(
                "Share",
                EnumerationScope::ShareEnumeration,
                MatchLocation::ExportPath,
                MatchType::Contains,
                vec![s("/home")],
                MatchAction::Snaffle,
                Some(Triage::Green),
                None,
            ),
            make_rule(
                "Dir",
                EnumerationScope::DirectoryEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s(".git")],
                MatchAction::Discard,
                None,
                None,
            ),
            make_rule(
                "File",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("id_rsa")],
                MatchAction::Snaffle,
                Some(Triage::Black),
                None,
            ),
            make_rule(
                "Content",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Regex,
                vec![s(r"(?i)password\s*=")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];

        let engine = RuleEngine::compile(rules).unwrap();

        assert_eq!(engine.share_rules().len(), 1);
        assert_eq!(engine.share_rules()[0].name, "Share");
        assert_eq!(engine.dir_rules().len(), 1);
        assert_eq!(engine.dir_rules()[0].name, "Dir");
        assert_eq!(engine.file_rules().len(), 1);
        assert_eq!(engine.file_rules()[0].name, "File");
        assert_eq!(engine.content_rules().len(), 1);
        assert_eq!(engine.content_rules()[0].name, "Content");
        assert_eq!(engine.rule_count(), 4);
    }

    #[test]
    fn compile_builds_matchers() {
        let rules = vec![make_rule(
            "Test",
            EnumerationScope::FileEnumeration,
            MatchLocation::FileName,
            MatchType::Exact,
            vec![s("id_rsa")],
            MatchAction::Snaffle,
            Some(Triage::Black),
            None,
        )];

        let engine = RuleEngine::compile(rules).unwrap();
        assert!(engine.matcher("Test").is_some());
        assert!(engine.matcher("Test").unwrap().is_match("id_rsa"));
        assert!(engine.matcher("Nonexistent").is_none());
    }

    #[test]
    fn validate_relay_rejects_dangling() {
        let rules = vec![make_rule(
            "Relayer",
            EnumerationScope::FileEnumeration,
            MatchLocation::FileName,
            MatchType::Exact,
            vec![s(".env")],
            MatchAction::Relay,
            None,
            Some(vec![s("NonexistentRule")]),
        )];

        let engine = RuleEngine::compile(rules).unwrap();
        let err = engine.validate_relay_targets().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dangling relay target"), "got: {msg}");
        assert!(msg.contains("NonexistentRule"), "got: {msg}");
    }

    #[test]
    fn validate_relay_accepts_valid() {
        let rules = vec![
            make_rule(
                "Relayer",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s(".env")],
                MatchAction::Relay,
                None,
                Some(vec![s("Target")]),
            ),
            make_rule(
                "Target",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Regex,
                vec![s(r"password")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];

        let engine = RuleEngine::compile(rules).unwrap();
        assert!(engine.validate_relay_targets().is_ok());
    }

    #[test]
    fn detect_cycles_rejects_direct() {
        let rules = vec![
            make_rule(
                "A",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("a")],
                MatchAction::Relay,
                None,
                Some(vec![s("B")]),
            ),
            make_rule(
                "B",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("b")],
                MatchAction::Relay,
                None,
                Some(vec![s("A")]),
            ),
        ];

        let engine = RuleEngine::compile(rules).unwrap();
        let err = engine.detect_relay_cycles().unwrap_err();
        assert!(
            err.to_string().contains("relay cycle detected"),
            "got: {}",
            err
        );
    }

    #[test]
    fn detect_cycles_rejects_indirect() {
        let rules = vec![
            make_rule(
                "A",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("a")],
                MatchAction::Relay,
                None,
                Some(vec![s("B")]),
            ),
            make_rule(
                "B",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("b")],
                MatchAction::Relay,
                None,
                Some(vec![s("C")]),
            ),
            make_rule(
                "C",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("c")],
                MatchAction::Relay,
                None,
                Some(vec![s("A")]),
            ),
        ];

        let engine = RuleEngine::compile(rules).unwrap();
        let err = engine.detect_relay_cycles().unwrap_err();
        assert!(
            err.to_string().contains("relay cycle detected"),
            "got: {}",
            err
        );
    }

    #[test]
    fn detect_cycles_accepts_acyclic() {
        let rules = vec![
            make_rule(
                "A",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("a")],
                MatchAction::Relay,
                None,
                Some(vec![s("B")]),
            ),
            make_rule(
                "B",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("b")],
                MatchAction::Relay,
                None,
                Some(vec![s("C")]),
            ),
            make_rule(
                "C",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Regex,
                vec![s("secret")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];

        let engine = RuleEngine::compile(rules).unwrap();
        assert!(engine.detect_relay_cycles().is_ok());
    }

    #[test]
    fn validate_scope_loc_rejects_share_filename() {
        let rules = vec![make_rule(
            "BadShare",
            EnumerationScope::ShareEnumeration,
            MatchLocation::FileName,
            MatchType::Exact,
            vec![s("foo")],
            MatchAction::Snaffle,
            Some(Triage::Green),
            None,
        )];

        let engine = RuleEngine::compile(rules).unwrap();
        let err = engine.validate_scope_location().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid scope/location"), "got: {msg}");
        assert!(msg.contains("BadShare"), "got: {msg}");
    }

    #[test]
    fn validate_scope_loc_rejects_contents_extension() {
        let rules = vec![make_rule(
            "BadContent",
            EnumerationScope::ContentsEnumeration,
            MatchLocation::FileExtension,
            MatchType::Exact,
            vec![s("txt")],
            MatchAction::Snaffle,
            Some(Triage::Green),
            None,
        )];

        let engine = RuleEngine::compile(rules).unwrap();
        let err = engine.validate_scope_location().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid scope/location"), "got: {msg}");
        assert!(msg.contains("BadContent"), "got: {msg}");
    }

    #[test]
    fn validate_scope_loc_accepts_valid() {
        let rules = vec![
            make_rule(
                "ValidFile",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("id_rsa")],
                MatchAction::Snaffle,
                Some(Triage::Black),
                None,
            ),
            make_rule(
                "ValidContent",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Regex,
                vec![s("password")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];

        let engine = RuleEngine::compile(rules).unwrap();
        assert!(engine.validate_scope_location().is_ok());
    }

    fn mock_file_entry(name: &str) -> FileEntry {
        let extension = std::path::Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();
        FileEntry {
            name: name.to_string(),
            path: format!("/export/{name}"),
            extension,
            size: 1024,
            uid: 1000,
            gid: 1000,
            mode: 0o644,
        }
    }

    #[test]
    fn eval_snaffle_filename_exact_match() {
        let rules = vec![make_rule(
            "SshKeys",
            EnumerationScope::FileEnumeration,
            MatchLocation::FileName,
            MatchType::Exact,
            vec![s("id_rsa")],
            MatchAction::Snaffle,
            Some(Triage::Black),
            None,
        )];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("id_rsa");
        let findings = engine.evaluate_file(&entry, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].triage, Triage::Black);
        assert_eq!(findings[0].rule_name, "SshKeys");
    }

    #[test]
    fn eval_discard_stops_processing() {
        let rules = vec![
            make_rule(
                "SkipImages",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileExtension,
                MatchType::Exact,
                vec![s("jpg")],
                MatchAction::Discard,
                None,
                None,
            ),
            make_rule(
                "CatchAll",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Contains,
                vec![s("photo")],
                MatchAction::Snaffle,
                Some(Triage::Green),
                None,
            ),
        ];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("photo.jpg");
        let findings = engine.evaluate_file(&entry, None);
        assert!(findings.is_empty(), "Discard should prevent Snaffle");
    }

    #[test]
    fn eval_relay_to_content_rule_with_content() {
        let rules = vec![
            make_rule(
                "EnvFiles",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s(".env")],
                MatchAction::Relay,
                None,
                Some(vec![s("CredentialPatterns")]),
            ),
            make_rule(
                "CredentialPatterns",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Regex,
                vec![s(r"(?i)password\s*=")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry(".env");
        let content = b"PASSWORD=secret123";
        let findings = engine.evaluate_file(&entry, Some(content));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].triage, Triage::Red);
        assert_eq!(findings[0].rule_name, "CredentialPatterns");
    }

    #[test]
    fn eval_relay_no_content_yields_no_match() {
        let rules = vec![
            make_rule(
                "EnvFiles",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s(".env")],
                MatchAction::Relay,
                None,
                Some(vec![s("CredentialPatterns")]),
            ),
            make_rule(
                "CredentialPatterns",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Regex,
                vec![s(r"(?i)password\s*=")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry(".env");
        let findings = engine.evaluate_file(&entry, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn eval_relay_multi_target_second_matches() {
        let rules = vec![
            make_rule(
                "EnvFiles",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s(".env")],
                MatchAction::Relay,
                None,
                Some(vec![s("CloudKeys"), s("CredentialPatterns")]),
            ),
            make_rule(
                "CloudKeys",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Regex,
                vec![s(r"AKIA[0-9A-Z]{16}")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
            make_rule(
                "CredentialPatterns",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Regex,
                vec![s(r"(?i)password\s*=")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry(".env");
        let content = b"DB_PASSWORD=hunter2";
        let findings = engine.evaluate_file(&entry, Some(content));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "CredentialPatterns");
    }

    #[test]
    fn eval_relay_depth_limit_truncates_chain() {
        // R0 (FileEnumeration) -> R1 -> R2 -> R3 -> R4 -> R5 -> R6 (Snaffle)
        // R1-R6 are ContentsEnumeration (only reachable via relay, not as file_rules).
        // follow_relay: depth 1 (R1), 2 (R2), 3 (R3), 4 (R4), 5 (R5), 6 (R6).
        // At depth 6 > MAX_RELAY_DEPTH(5), R6 never evaluates.
        let mut rules = vec![make_rule(
            "R0",
            EnumerationScope::FileEnumeration,
            MatchLocation::FileName,
            MatchType::Contains,
            vec![s("test")],
            MatchAction::Relay,
            None,
            Some(vec![s("R1")]),
        )];
        for i in 1..6 {
            rules.push(make_rule(
                &format!("R{i}"),
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Contains,
                vec![s("data")],
                MatchAction::Relay,
                None,
                Some(vec![format!("R{}", i + 1)]),
            ));
        }
        rules.push(make_rule(
            "R6",
            EnumerationScope::ContentsEnumeration,
            MatchLocation::FileContentAsString,
            MatchType::Contains,
            vec![s("data")],
            MatchAction::Snaffle,
            Some(Triage::Black),
            None,
        ));
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("test_file");
        let content = b"data";
        let findings = engine.evaluate_file(&entry, Some(content));
        assert!(
            findings.is_empty(),
            "R6 should not be reached due to depth limit, got {} findings",
            findings.len()
        );
    }

    #[test]
    fn should_discard_dir_matches_exact_name() {
        let rules = vec![make_rule(
            "SkipGit",
            EnumerationScope::DirectoryEnumeration,
            MatchLocation::FileName,
            MatchType::Exact,
            vec![s(".git")],
            MatchAction::Discard,
            None,
            None,
        )];
        let engine = RuleEngine::compile(rules).unwrap();
        assert!(engine.should_discard_dir(".git", "/export/.git"));
    }

    #[test]
    fn should_discard_dir_no_match() {
        let rules = vec![make_rule(
            "SkipGit",
            EnumerationScope::DirectoryEnumeration,
            MatchLocation::FileName,
            MatchType::Exact,
            vec![s(".git")],
            MatchAction::Discard,
            None,
            None,
        )];
        let engine = RuleEngine::compile(rules).unwrap();
        assert!(!engine.should_discard_dir("src", "/export/src"));
    }

    #[test]
    fn compile_rejects_duplicate_rule_names() {
        let rules = vec![
            make_rule(
                "Duplicate",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("foo")],
                MatchAction::Snaffle,
                Some(Triage::Green),
                None,
            ),
            make_rule(
                "Duplicate",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("bar")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];

        let result = RuleEngine::compile(rules);
        let err = result
            .err()
            .expect("compile() should reject duplicate rule names");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate"),
            "error should mention 'duplicate': {msg}"
        );
    }

    #[test]
    fn eval_rule_respects_max_size_for_content_rules() {
        let rules = vec![
            make_rule(
                "RelaySmall",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s(".env")],
                MatchAction::Relay,
                None,
                Some(vec![s("SmallContent")]),
            ),
            {
                let mut r = make_rule(
                    "SmallContent",
                    EnumerationScope::ContentsEnumeration,
                    MatchLocation::FileContentAsString,
                    MatchType::Contains,
                    vec![s("SECRET")],
                    MatchAction::Snaffle,
                    Some(Triage::Red),
                    None,
                );
                r.max_size = Some(1024);
                r
            },
        ];
        let engine = RuleEngine::compile(rules).unwrap();

        let mut entry = mock_file_entry(".env");
        entry.size = 2048;
        let content = b"SECRET=value";
        let findings = engine.evaluate_file(&entry, Some(content));
        assert!(
            findings.is_empty(),
            "content rule with max_size=1024 should skip file of size 2048"
        );
    }

    #[test]
    fn eval_rule_allows_within_max_size() {
        let rules = vec![
            make_rule(
                "RelaySmall",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s(".env")],
                MatchAction::Relay,
                None,
                Some(vec![s("SmallContent")]),
            ),
            {
                let mut r = make_rule(
                    "SmallContent",
                    EnumerationScope::ContentsEnumeration,
                    MatchLocation::FileContentAsString,
                    MatchType::Contains,
                    vec![s("SECRET")],
                    MatchAction::Snaffle,
                    Some(Triage::Red),
                    None,
                );
                r.max_size = Some(1024);
                r
            },
        ];
        let engine = RuleEngine::compile(rules).unwrap();

        let mut entry = mock_file_entry(".env");
        entry.size = 512;
        let content = b"SECRET=value";
        let findings = engine.evaluate_file(&entry, Some(content));
        assert_eq!(
            findings.len(),
            1,
            "file within max_size should be evaluated"
        );
    }

    #[test]
    fn eval_snaffle_finding_contains_matched_pattern_not_rule_name() {
        let rules = vec![make_rule(
            "SshKeys",
            EnumerationScope::FileEnumeration,
            MatchLocation::FileName,
            MatchType::Exact,
            vec![s("id_rsa")],
            MatchAction::Snaffle,
            Some(Triage::Black),
            None,
        )];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("id_rsa");
        let findings = engine.evaluate_file(&entry, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].matched_pattern, "id_rsa",
            "matched_pattern should be the pattern, not the rule name"
        );
    }

    #[test]
    fn eval_snaffle_multi_pattern_reports_which_matched() {
        let rules = vec![make_rule(
            "SshKeys",
            EnumerationScope::FileEnumeration,
            MatchLocation::FileName,
            MatchType::Exact,
            vec![s("id_rsa"), s("id_ecdsa"), s("id_ed25519")],
            MatchAction::Snaffle,
            Some(Triage::Black),
            None,
        )];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("id_ecdsa");
        let findings = engine.evaluate_file(&entry, None);
        assert_eq!(findings[0].matched_pattern, "id_ecdsa");
    }

    #[test]
    fn eval_snaffle_relay_to_content_reports_content_pattern() {
        let rules = vec![
            make_rule(
                "EnvFiles",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s(".env")],
                MatchAction::Relay,
                None,
                Some(vec![s("CredentialPatterns")]),
            ),
            make_rule(
                "CredentialPatterns",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Regex,
                vec![s(r"(?i)password\s*=")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry(".env");
        let content = b"PASSWORD = secret123";
        let findings = engine.evaluate_file(&entry, Some(content));
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].matched_pattern, r"(?i)password\s*=",
            "matched_pattern should be the regex pattern source"
        );
    }

    #[test]
    fn eval_snaffle_without_triage_defaults_to_yellow() {
        let rules = vec![make_rule(
            "NoTriage",
            EnumerationScope::FileEnumeration,
            MatchLocation::FileName,
            MatchType::Exact,
            vec![s("suspicious_file")],
            MatchAction::Snaffle,
            None,
            None,
        )];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("suspicious_file");
        let findings = engine.evaluate_file(&entry, None);
        assert_eq!(
            findings[0].triage,
            Triage::Yellow,
            "missing triage should default to Yellow, not Green"
        );
    }

    #[test]
    fn eval_snaffle_contains_reports_matched_pattern() {
        let rules = vec![make_rule(
            "ConfigFiles",
            EnumerationScope::FileEnumeration,
            MatchLocation::FileName,
            MatchType::Contains,
            vec![s("password"), s("secret")],
            MatchAction::Snaffle,
            Some(Triage::Yellow),
            None,
        )];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("my_secret_file");
        let findings = engine.evaluate_file(&entry, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].matched_pattern, "secret");
    }

    #[test]
    fn eval_bytes_rule_matches_binary_content_with_null_bytes() {
        let rules = vec![
            make_rule(
                "BinRelay",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("data.bin")],
                MatchAction::Relay,
                None,
                Some(vec![s("MagicBytes")]),
            ),
            make_rule(
                "MagicBytes",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsBytes,
                MatchType::Contains,
                vec![s("%PDF")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("data.bin");
        let content: &[u8] = &[0x00, 0x00, b'%', b'P', b'D', b'F', 0x00];
        let findings = engine.evaluate_file(&entry, Some(content));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "MagicBytes");
        assert_eq!(findings[0].triage, Triage::Red);
    }

    #[test]
    fn eval_bytes_regex_matches_der_header() {
        let rules = vec![
            make_rule(
                "DerRelay",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("cert.der")],
                MatchAction::Relay,
                None,
                Some(vec![s("DerHeader")]),
            ),
            make_rule(
                "DerHeader",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsBytes,
                MatchType::Regex,
                vec![s(r"\x30\x82")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("cert.der");
        let content: &[u8] = &[0x30, 0x82, 0x03, 0x45, 0x30, 0x82, 0x03];
        let findings = engine.evaluate_file(&entry, Some(content));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, "DerHeader");
    }

    #[test]
    fn eval_bytes_rule_no_content_returns_no_match() {
        let rules = vec![
            make_rule(
                "BinRelay",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("data.bin")],
                MatchAction::Relay,
                None,
                Some(vec![s("MagicBytes")]),
            ),
            make_rule(
                "MagicBytes",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsBytes,
                MatchType::Contains,
                vec![s("%PDF")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("data.bin");
        let findings = engine.evaluate_file(&entry, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn eval_binary_content_skips_string_rules() {
        let rules = vec![
            make_rule(
                "BinFile",
                EnumerationScope::FileEnumeration,
                MatchLocation::FileName,
                MatchType::Exact,
                vec![s("data.bin")],
                MatchAction::Relay,
                None,
                Some(vec![s("ContentCheck")]),
            ),
            make_rule(
                "ContentCheck",
                EnumerationScope::ContentsEnumeration,
                MatchLocation::FileContentAsString,
                MatchType::Contains,
                vec![s("password")],
                MatchAction::Snaffle,
                Some(Triage::Red),
                None,
            ),
        ];
        let engine = RuleEngine::compile(rules).unwrap();
        let entry = mock_file_entry("data.bin");
        let content = b"password\x00binary_data";
        let findings = engine.evaluate_file(&entry, Some(content));
        assert!(
            findings.is_empty(),
            "binary content should skip FileContentAsString rules"
        );
    }
}
