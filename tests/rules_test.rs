#[path = "integration/helpers.rs"]
mod helpers;

use niffler::classifier::{
    ClassifierRule, EnumerationScope, FileEntry, MatchAction, MatchLocation, MatchType, RuleEngine,
    RuleFile, Triage, load_embedded_defaults,
};

/// Helper: load rules from a single TOML fixture file.
fn load_fixture_rules(fixture_name: &str) -> Vec<ClassifierRule> {
    let path = helpers::fixture_path(&format!("sample_rules/{fixture_name}"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()));
    let rule_file: RuleFile =
        toml::from_str(&text).unwrap_or_else(|e| panic!("failed to parse {fixture_name}: {e}"));
    rule_file.rules
}

/// Helper: build a compiled and validated engine from embedded defaults.
fn default_engine() -> RuleEngine {
    let rules = load_embedded_defaults().expect("embedded defaults should load");
    let engine = RuleEngine::compile(rules).expect("embedded defaults should compile");
    engine
        .validate_relay_targets()
        .expect("embedded defaults should have no dangling relays");
    engine
        .detect_relay_cycles()
        .expect("embedded defaults should have no cycles");
    engine
        .validate_scope_location()
        .expect("embedded defaults should have valid scope/location combos");
    engine
}

/// Helper: make a FileEntry for evaluation.
fn file_entry(name: &str, path: &str, size: u64, uid: u32, gid: u32, mode: u32) -> FileEntry {
    let extension = name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_string())
        .unwrap_or_default();
    FileEntry {
        name: name.into(),
        path: path.into(),
        extension,
        size,
        uid,
        gid,
        mode,
    }
}

// ===== Embedded defaults tests (1-6) =====

#[test]
fn embedded_defaults_all_parse() {
    let rules = load_embedded_defaults().expect("all 14 embedded TOML files should parse");
    let engine = RuleEngine::compile(rules).expect("all rules should compile");
    assert!(
        engine.rule_count() > 0,
        "engine should contain at least one rule"
    );
}

#[test]
fn embedded_defaults_no_dangling_relays() {
    let rules = load_embedded_defaults().unwrap();
    let engine = RuleEngine::compile(rules).unwrap();
    engine
        .validate_relay_targets()
        .expect("no relay target should reference a non-existent rule");
}

#[test]
fn embedded_defaults_no_cycles() {
    let rules = load_embedded_defaults().unwrap();
    let engine = RuleEngine::compile(rules).unwrap();
    engine
        .detect_relay_cycles()
        .expect("no circular relay chains should exist");
}

#[test]
fn embedded_defaults_scope_location_valid() {
    let rules = load_embedded_defaults().unwrap();
    let engine = RuleEngine::compile(rules).unwrap();
    engine
        .validate_scope_location()
        .expect("all scope/location combinations should be valid");
}

#[test]
fn embedded_defaults_cover_all_scopes() {
    let engine = default_engine();
    assert!(
        !engine.share_rules().is_empty(),
        "should have ShareEnumeration rules"
    );
    assert!(
        !engine.dir_rules().is_empty(),
        "should have DirectoryEnumeration rules"
    );
    assert!(
        !engine.file_rules().is_empty(),
        "should have FileEnumeration rules"
    );
    assert!(
        !engine.content_rules().is_empty(),
        "should have ContentsEnumeration rules"
    );
}

#[test]
fn embedded_defaults_cover_all_triage_levels() {
    let rules = load_embedded_defaults().unwrap();

    let has_triage = |level: Triage| -> bool {
        rules
            .iter()
            .any(|r| r.action == MatchAction::Snaffle && r.triage == Some(level))
    };

    assert!(
        has_triage(Triage::Green),
        "should have Green severity rules"
    );
    assert!(
        has_triage(Triage::Yellow),
        "should have Yellow severity rules"
    );
    assert!(has_triage(Triage::Red), "should have Red severity rules");
    assert!(
        has_triage(Triage::Black),
        "should have Black severity rules"
    );
}

// ===== Custom rules from fixtures (7-10) =====

#[test]
fn custom_rules_load_from_directory() {
    let rules = load_fixture_rules("valid_rules.toml");
    assert!(!rules.is_empty(), "valid_rules.toml should contain rules");
    let engine = RuleEngine::compile(rules).expect("valid_rules.toml should compile");
    engine
        .validate_relay_targets()
        .expect("valid_rules.toml should have no dangling relays");
    engine
        .detect_relay_cycles()
        .expect("valid_rules.toml should have no cycles");
    engine
        .validate_scope_location()
        .expect("valid_rules.toml should have valid scope/location combos");
    assert!(engine.rule_count() >= 5, "should have at least 5 rules");
}

#[test]
fn custom_rules_relay_chain_evaluates() {
    let rules = load_fixture_rules("relay_chain.toml");
    let engine = RuleEngine::compile(rules).expect("relay_chain.toml should compile");

    // File named "test.env" matches ChainEntry (FileName regex \.env$)
    let entry = file_entry("test.env", "/exports/home/test.env", 256, 1000, 1000, 0o644);

    // Content matches both ChainMiddle (password|secret) and ChainTerminal (password=...)
    let content = b"password=secret123";
    let findings = engine.evaluate_file(&entry, Some(content));

    assert!(
        !findings.is_empty(),
        "relay chain should produce at least one finding"
    );
    let terminal_finding = findings
        .iter()
        .find(|f| f.rule_name == "ChainTerminal")
        .expect("should have a finding from ChainTerminal");
    assert_eq!(
        terminal_finding.triage,
        Triage::Red,
        "ChainTerminal finding should be Red severity"
    );
}

#[test]
fn custom_rules_dangling_relay_rejected() {
    let rules = load_fixture_rules("invalid_relay.toml");
    let engine = RuleEngine::compile(rules).expect("invalid_relay.toml should compile (syntax ok)");
    let result = engine.validate_relay_targets();
    assert!(
        result.is_err(),
        "dangling relay target 'NonExistentRule' should be detected"
    );
}

#[test]
fn custom_rules_cycle_detected() {
    let rules = load_fixture_rules("cycle_rules.toml");
    let engine = RuleEngine::compile(rules).expect("cycle_rules.toml should compile (syntax ok)");
    let result = engine.detect_relay_cycles();
    assert!(
        result.is_err(),
        "circular relay RuleA -> RuleB -> RuleA should be detected"
    );
}

// ===== Behavior tests (11-13) =====

#[test]
fn discard_stops_processing() {
    let rules = vec![
        ClassifierRule {
            name: "DiscardJpg".into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileExtension,
            match_type: MatchType::Exact,
            patterns: vec!["jpg".into()],
            action: MatchAction::Discard,
            triage: None,
            relay_targets: None,
            max_size: None,
            context_bytes: None,
            description: None,
        },
        ClassifierRule {
            name: "SnaffleAll".into(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileExtension,
            match_type: MatchType::Exact,
            patterns: vec!["jpg".into()],
            action: MatchAction::Snaffle,
            triage: Some(Triage::Green),
            relay_targets: None,
            max_size: None,
            context_bytes: None,
            description: None,
        },
    ];
    let engine = RuleEngine::compile(rules).unwrap();
    let entry = file_entry("photo.jpg", "/data/photo.jpg", 1024, 1000, 1000, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.is_empty(),
        "Discard should stop processing before Snaffle can match"
    );
}

#[test]
fn relay_chain_depth_limit() {
    // Build a chain of 7 relay rules + terminal Snaffle (8 rules total).
    // MAX_RELAY_DEPTH = 5, so the chain should stop before reaching Snaffle.
    let mut rules = Vec::new();

    for i in 0..7 {
        let next = format!("Relay{}", i + 1);
        rules.push(ClassifierRule {
            name: format!("Relay{i}"),
            scope: if i == 0 {
                EnumerationScope::FileEnumeration
            } else {
                EnumerationScope::ContentsEnumeration
            },
            match_location: if i == 0 {
                MatchLocation::FileName
            } else {
                MatchLocation::FileContentAsString
            },
            match_type: MatchType::Contains,
            patterns: vec!["deep".into()],
            action: MatchAction::Relay,
            triage: None,
            relay_targets: Some(vec![next]),
            max_size: None,
            context_bytes: None,
            description: None,
        });
    }

    // Terminal Snaffle at hop 7
    rules.push(ClassifierRule {
        name: "Relay7".into(),
        scope: EnumerationScope::ContentsEnumeration,
        match_location: MatchLocation::FileContentAsString,
        match_type: MatchType::Contains,
        patterns: vec!["deep".into()],
        action: MatchAction::Snaffle,
        triage: Some(Triage::Black),
        relay_targets: None,
        max_size: None,
        context_bytes: None,
        description: None,
    });

    let engine = RuleEngine::compile(rules).unwrap();
    let entry = file_entry("deep.txt", "/data/deep.txt", 100, 1000, 1000, 0o644);
    let content = b"deep chain content";

    // Should not panic or stack overflow
    let findings = engine.evaluate_file(&entry, Some(content));

    // Depth limit (5) stops chain before hop 7. Zero findings expected.
    assert!(
        findings.is_empty(),
        "chain exceeding MAX_RELAY_DEPTH should not reach terminal Snaffle (got {} findings)",
        findings.len()
    );
}

#[test]
fn fixture_file_matches_expected_rule() {
    let engine = default_engine();

    // id_rsa matches SshPrivateKeys rule (FileName exact match, Snaffle Black)
    let entry = file_entry("id_rsa", "/home/user/.ssh/id_rsa", 1700, 1000, 1000, 0o600);
    let findings = engine.evaluate_file(&entry, None);

    assert!(
        !findings.is_empty(),
        "id_rsa should match at least one file enumeration rule"
    );
    let black_finding = findings
        .iter()
        .find(|f| f.triage == Triage::Black)
        .expect("id_rsa should produce a Black severity finding");
    assert_eq!(
        black_finding.rule_name, "SshPrivateKeys",
        "finding should come from SshPrivateKeys rule"
    );
}
