use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use walkdir::WalkDir;

use super::rule::{ClassifierRule, RuleFile};

const DEFAULT_RULES: &[(&str, &str)] = &[
    (
        "share/discard.toml",
        include_str!("../../rules/share/discard.toml"),
    ),
    (
        "share/flag.toml",
        include_str!("../../rules/share/flag.toml"),
    ),
    (
        "dir/discard.toml",
        include_str!("../../rules/dir/discard.toml"),
    ),
    ("dir/flag.toml", include_str!("../../rules/dir/flag.toml")),
    (
        "file/discard.toml",
        include_str!("../../rules/file/discard.toml"),
    ),
    (
        "file/black.toml",
        include_str!("../../rules/file/black.toml"),
    ),
    ("file/red.toml", include_str!("../../rules/file/red.toml")),
    (
        "file/yellow.toml",
        include_str!("../../rules/file/yellow.toml"),
    ),
    (
        "file/green.toml",
        include_str!("../../rules/file/green.toml"),
    ),
    (
        "content/credentials.toml",
        include_str!("../../rules/content/credentials.toml"),
    ),
    (
        "content/connection_strings.toml",
        include_str!("../../rules/content/connection_strings.toml"),
    ),
    (
        "content/cloud.toml",
        include_str!("../../rules/content/cloud.toml"),
    ),
    (
        "content/crypto.toml",
        include_str!("../../rules/content/crypto.toml"),
    ),
    (
        "content/linux.toml",
        include_str!("../../rules/content/linux.toml"),
    ),
    (
        "content/tokens.toml",
        include_str!("../../rules/content/tokens.toml"),
    ),
    (
        "content/network.toml",
        include_str!("../../rules/content/network.toml"),
    ),
];

/// Load all embedded default rules compiled into the binary.
pub fn load_embedded_defaults() -> Result<Vec<ClassifierRule>> {
    let mut rules = Vec::new();
    for (filename, content) in DEFAULT_RULES {
        let parsed: RuleFile = toml::from_str(content)
            .with_context(|| format!("failed to parse embedded rule: {filename}"))?;
        rules.extend(parsed.rules);
    }
    Ok(rules)
}

/// Load all `.toml` rule files from a directory (recursive).
pub fn load_rules_from_dir(dir: &Path) -> Result<Vec<ClassifierRule>> {
    let mut rules = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read rule file: {}", path.display()))?;
            let parsed: RuleFile = toml::from_str(&content)
                .with_context(|| format!("failed to parse rule file: {}", path.display()))?;
            rules.extend(parsed.rules);
        }
    }
    Ok(rules)
}

/// Merge extra rules into base rules. Same-name rules in extra replace base rules;
/// new names are appended.
pub fn merge_rules(base: Vec<ClassifierRule>, extra: Vec<ClassifierRule>) -> Vec<ClassifierRule> {
    let mut name_to_index: HashMap<String, usize> = HashMap::new();
    let mut merged: Vec<ClassifierRule> = Vec::with_capacity(base.len() + extra.len());

    for rule in base {
        name_to_index.insert(rule.name.clone(), merged.len());
        merged.push(rule);
    }

    for rule in extra {
        if let Some(&idx) = name_to_index.get(&rule.name) {
            merged[idx] = rule;
        } else {
            name_to_index.insert(rule.name.clone(), merged.len());
            merged.push(rule);
        }
    }

    merged
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::classifier::action::MatchAction;
    use crate::classifier::engine::RuleEngine;
    use crate::classifier::rule::{EnumerationScope, MatchLocation, MatchType};
    use crate::classifier::triage::Triage;

    fn make_rule(name: &str, triage: Option<Triage>) -> ClassifierRule {
        ClassifierRule {
            name: name.to_string(),
            scope: EnumerationScope::FileEnumeration,
            match_location: MatchLocation::FileName,
            match_type: MatchType::Exact,
            patterns: vec!["test".to_string()],
            action: MatchAction::Snaffle,
            triage,
            relay_targets: None,
            max_size: None,
            context_bytes: None,
            description: None,
        }
    }

    #[test]
    fn embedded_defaults_parse() {
        let rules = load_embedded_defaults().unwrap();
        assert!(!rules.is_empty(), "embedded defaults should not be empty");
    }

    #[test]
    fn embedded_defaults_no_duplicate_names() {
        let rules = load_embedded_defaults().unwrap();
        let mut names = HashSet::new();
        for rule in &rules {
            assert!(
                names.insert(&rule.name),
                "duplicate rule name: '{}'",
                rule.name
            );
        }
    }

    #[test]
    fn embedded_defaults_no_dangling_relays() {
        let rules = load_embedded_defaults().unwrap();
        let engine = RuleEngine::compile(rules).unwrap();
        engine
            .validate_relay_targets()
            .expect("no dangling relay targets in embedded defaults");
    }

    #[test]
    fn embedded_defaults_no_relay_cycles() {
        let rules = load_embedded_defaults().unwrap();
        let engine = RuleEngine::compile(rules).unwrap();
        engine
            .detect_relay_cycles()
            .expect("no relay cycles in embedded defaults");
    }

    #[test]
    fn embedded_defaults_valid_scope_location() {
        let rules = load_embedded_defaults().unwrap();
        let engine = RuleEngine::compile(rules).unwrap();
        engine
            .validate_scope_location()
            .expect("all scope/location combos valid in embedded defaults");
    }

    #[test]
    fn merge_rules_same_name_replaces() {
        let base = vec![make_rule("Foo", Some(Triage::Green))];
        let extra = vec![make_rule("Foo", Some(Triage::Red))];
        let merged = merge_rules(base, extra);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].name, "Foo");
        assert_eq!(merged[0].triage, Some(Triage::Red));
    }

    #[test]
    fn merge_rules_new_rules_added() {
        let base = vec![make_rule("Foo", Some(Triage::Green))];
        let extra = vec![make_rule("Bar", Some(Triage::Yellow))];
        let merged = merge_rules(base, extra);

        assert_eq!(merged.len(), 2);
        let names: Vec<&str> = merged.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"Foo"));
        assert!(names.contains(&"Bar"));
    }
}
