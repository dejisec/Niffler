use serde::Deserialize;

use super::action::MatchAction;
use super::triage::Triage;

/// Scope at which a rule is evaluated in the pipeline.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum EnumerationScope {
    ShareEnumeration,
    DirectoryEnumeration,
    FileEnumeration,
    ContentsEnumeration,
}

/// What part of the item to match against.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum MatchLocation {
    ExportPath,
    FilePath,
    FileName,
    FileExtension,
    FileContentAsString,
    FileContentAsBytes,
    FileLength,
    FileOwnerUid,
    FileOwnerGid,
    FileMode,
}

/// How the pattern string is interpreted.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum MatchType {
    Exact,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    Glob,
}

/// A single classifier rule loaded from TOML.
#[derive(Debug, Deserialize, Clone)]
pub struct ClassifierRule {
    pub name: String,
    pub scope: EnumerationScope,
    pub match_location: MatchLocation,
    pub match_type: MatchType,
    pub patterns: Vec<String>,
    pub action: MatchAction,
    pub triage: Option<Triage>,
    pub relay_targets: Option<Vec<String>>,
    pub max_size: Option<u64>,
    pub context_bytes: Option<usize>,
    pub description: Option<String>,
}

/// Wrapper for TOML `[[rules]]` array-of-tables deserialization.
#[derive(Debug, Deserialize)]
pub struct RuleFile {
    pub rules: Vec<ClassifierRule>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_roundtrip_snaffle_rule() {
        let toml_str = r#"
[[rules]]
name = "SshPrivateKeys"
scope = "FileEnumeration"
match_location = "FileName"
match_type = "Exact"
patterns = ["id_rsa", "id_ecdsa", "id_ed25519"]
action = "Snaffle"
triage = "Black"
max_size = 65536
context_bytes = 200
description = "SSH private key files"
"#;
        let rule_file: RuleFile = toml::from_str(toml_str).unwrap();
        assert_eq!(rule_file.rules.len(), 1);

        let rule = &rule_file.rules[0];
        assert_eq!(rule.name, "SshPrivateKeys");
        assert_eq!(rule.scope, EnumerationScope::FileEnumeration);
        assert_eq!(rule.match_location, MatchLocation::FileName);
        assert_eq!(rule.match_type, MatchType::Exact);
        assert_eq!(rule.patterns, vec!["id_rsa", "id_ecdsa", "id_ed25519"]);
        assert_eq!(rule.action, MatchAction::Snaffle);
        assert_eq!(rule.triage, Some(Triage::Black));
        assert!(rule.relay_targets.is_none());
        assert_eq!(rule.max_size, Some(65536));
        assert_eq!(rule.context_bytes, Some(200));
        assert_eq!(rule.description.as_deref(), Some("SSH private key files"));
    }

    #[test]
    fn toml_roundtrip_relay_rule() {
        let toml_str = r#"
[[rules]]
name = "EnvFiles"
scope = "FileEnumeration"
match_location = "FileName"
match_type = "Regex"
patterns = ['\.env(\.(local|dev|staging|prod|backup))?$']
action = "Relay"
relay_targets = ["CredentialPatterns", "CloudKeyPatterns"]
description = "Environment variable files"
"#;
        let rule_file: RuleFile = toml::from_str(toml_str).unwrap();
        let rule = &rule_file.rules[0];

        assert_eq!(rule.name, "EnvFiles");
        assert_eq!(rule.action, MatchAction::Relay);
        assert_eq!(
            rule.relay_targets.as_deref(),
            Some(
                &[
                    "CredentialPatterns".to_string(),
                    "CloudKeyPatterns".to_string()
                ][..]
            )
        );
        assert_eq!(rule.triage, None);
    }

    #[test]
    fn toml_roundtrip_discard_rule() {
        let toml_str = r#"
[[rules]]
name = "SkipImages"
scope = "FileEnumeration"
match_location = "FileExtension"
match_type = "Exact"
patterns = ["jpg", "png", "gif"]
action = "Discard"
"#;
        let rule_file: RuleFile = toml::from_str(toml_str).unwrap();
        let rule = &rule_file.rules[0];

        assert_eq!(rule.name, "SkipImages");
        assert_eq!(rule.action, MatchAction::Discard);
        assert_eq!(rule.triage, None);
        assert!(rule.relay_targets.is_none());
    }

    #[test]
    fn optional_fields_default_to_none() {
        let toml_str = r#"
[[rules]]
name = "Minimal"
scope = "FileEnumeration"
match_location = "FileName"
match_type = "Contains"
patterns = ["secret"]
action = "Snaffle"
triage = "Yellow"
"#;
        let rule_file: RuleFile = toml::from_str(toml_str).unwrap();
        let rule = &rule_file.rules[0];

        assert!(rule.max_size.is_none());
        assert!(rule.context_bytes.is_none());
        assert!(rule.description.is_none());
    }

    #[test]
    fn multiple_rules_in_one_file() {
        let toml_str = r#"
[[rules]]
name = "RuleOne"
scope = "FileEnumeration"
match_location = "FileName"
match_type = "Exact"
patterns = ["foo"]
action = "Snaffle"
triage = "Green"

[[rules]]
name = "RuleTwo"
scope = "DirectoryEnumeration"
match_location = "FileName"
match_type = "Exact"
patterns = [".git"]
action = "Discard"
"#;
        let rule_file: RuleFile = toml::from_str(toml_str).unwrap();
        assert_eq!(rule_file.rules.len(), 2);
        assert_eq!(rule_file.rules[0].name, "RuleOne");
        assert_eq!(rule_file.rules[1].name, "RuleTwo");
    }
}
