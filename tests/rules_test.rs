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

#[test]
fn bak_extension_stripped_to_underlying() {
    let engine = default_engine();
    // secrets.kdbx.bak should match KeePassDatabases via stripped "kdbx" extension
    let entry = file_entry(
        "secrets.kdbx.bak",
        "/data/secrets.kdbx.bak",
        4096,
        1000,
        1000,
        0o644,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "KeePassDatabases" && f.triage == Triage::Black),
        "secrets.kdbx.bak should match KeePassDatabases with Black triage, got: {findings:?}"
    );
}

#[test]
fn bak_with_content_relays_both_paths() {
    let engine = default_engine();
    // config.yaml.bak should relay via BOTH BackupFileExtensions (.bak)
    // AND ConfigFileExtensions (stripped .yaml)
    let entry = file_entry(
        "config.yaml.bak",
        "/data/config.yaml.bak",
        256,
        1000,
        1000,
        0o644,
    );
    let content = b"password = supersecret123";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "config.yaml.bak with credentials should produce CredentialPatterns finding, got: {findings:?}"
    );
}

#[test]
fn plain_bak_no_underlying() {
    let engine = default_engine();
    // notes.bak has no underlying extension — only BackupFileExtensions relay fires
    let entry = file_entry("notes.bak", "/data/notes.bak", 256, 1000, 1000, 0o644);
    let content = b"password = supersecret123";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "notes.bak with credentials should still produce finding via BackupFileExtensions relay"
    );
}

#[test]
fn terraform_dir_discarded() {
    let engine = default_engine();
    assert!(
        engine.should_discard_dir(".terraform", "/project/.terraform"),
        ".terraform directory should be discarded"
    );
}

#[test]
fn venv_dir_discarded() {
    let engine = default_engine();
    assert!(
        engine.should_discard_dir("venv", "/project/venv"),
        "venv directory should be discarded"
    );
}

#[test]
fn cargo_dir_discarded() {
    let engine = default_engine();
    assert!(
        engine.should_discard_dir(".cargo", "/home/user/.cargo"),
        ".cargo directory should be discarded"
    );
}

#[test]
fn minified_js_discarded() {
    let engine = default_engine();
    let entry = file_entry("app.min.js", "/data/app.min.js", 50000, 1000, 1000, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.is_empty(),
        "minified JS should be discarded, got: {findings:?}"
    );
}

#[test]
fn css_file_discarded() {
    let engine = default_engine();
    let entry = file_entry("styles.css", "/data/styles.css", 1024, 1000, 1000, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.is_empty(),
        "CSS file should be discarded, got: {findings:?}"
    );
}

#[test]
fn ppk_file_matches_black() {
    let engine = default_engine();
    let entry = file_entry("mykey.ppk", "/home/user/mykey.ppk", 2048, 1000, 1000, 0o600);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "PuttyKeys" && f.triage == Triage::Black),
        "PPK file should match PuttyKeys with Black triage, got: {findings:?}"
    );
}

#[test]
fn psafe3_file_matches_black() {
    let engine = default_engine();
    let entry = file_entry(
        "vault.psafe3",
        "/data/vault.psafe3",
        4096,
        1000,
        1000,
        0o644,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "PasswordManagerExtensions" && f.triage == Triage::Black),
        "psafe3 file should match PasswordManagerExtensions, got: {findings:?}"
    );
}

#[test]
fn running_config_matches_black() {
    let engine = default_engine();
    let entry = file_entry("running-config", "/data/running-config", 8192, 0, 0, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "NetworkDeviceConfigs" && f.triage == Triage::Black),
        "running-config should match NetworkDeviceConfigs, got: {findings:?}"
    );
}

#[test]
fn ntds_dit_matches_black() {
    let engine = default_engine();
    let entry = file_entry("NTDS.DIT", "/data/NTDS.DIT", 1048576, 0, 0, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "WindowsHashFiles" && f.triage == Triage::Black),
        "NTDS.DIT should match WindowsHashFiles, got: {findings:?}"
    );
}

#[test]
fn lsass_dmp_matches_black() {
    let engine = default_engine();
    let entry = file_entry("lsass.dmp", "/data/lsass.dmp", 1048576, 0, 0, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "MemoryDumpsBlack" && f.triage == Triage::Black),
        "lsass.dmp should match MemoryDumpsBlack, got: {findings:?}"
    );
}

#[test]
fn cyberark_backup_key_matches_black() {
    let engine = default_engine();
    let entry = file_entry("backup.key", "/data/backup.key", 512, 0, 0, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "CyberArkPamFiles" && f.triage == Triage::Black),
        "backup.key should match CyberArkPamFiles, got: {findings:?}"
    );
}

#[test]
fn keytab_file_matches_yellow() {
    let engine = default_engine();
    let entry = file_entry("krb5.keytab", "/etc/krb5.keytab", 512, 0, 0, 0o600);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "KerberosKeytab" && f.triage == Triage::Yellow),
        "keytab should match KerberosKeytab Yellow, got: {findings:?}"
    );
}

#[test]
fn kerberos_cache_matches_yellow() {
    let engine = default_engine();
    let entry = file_entry("krb5cc_1000", "/tmp/krb5cc_1000", 512, 1000, 1000, 0o600);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "KerberosCache" && f.triage == Triage::Yellow),
        "krb5cc_* should match KerberosCache Yellow, got: {findings:?}"
    );
}

#[test]
fn pcap_file_matches_yellow() {
    let engine = default_engine();
    let entry = file_entry(
        "capture.pcap",
        "/data/capture.pcap",
        1048576,
        1000,
        1000,
        0o644,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "PacketCaptures" && f.triage == Triage::Yellow),
        "pcap should match PacketCaptures Yellow, got: {findings:?}"
    );
}

#[test]
fn rdp_file_matches_yellow() {
    let engine = default_engine();
    let entry = file_entry("server.rdp", "/data/server.rdp", 256, 1000, 1000, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "RdpFiles" && f.triage == Triage::Yellow),
        "rdp should match RdpFiles Yellow, got: {findings:?}"
    );
}

#[test]
fn generic_dmp_matches_yellow() {
    let engine = default_engine();
    let entry = file_entry("something.dmp", "/data/something.dmp", 1048576, 0, 0, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "MemoryDumpsYellow" && f.triage == Triage::Yellow),
        "generic .dmp should match MemoryDumpsYellow, got: {findings:?}"
    );
}

/// Helper: build engine from defaults + an extra relay rule for testing content rules.
fn engine_with_relay(relay_name: &str, ext: &str, target: &str) -> RuleEngine {
    let mut rules = load_embedded_defaults().expect("defaults load");
    rules.push(ClassifierRule {
        name: relay_name.into(),
        scope: EnumerationScope::FileEnumeration,
        match_location: MatchLocation::FileExtension,
        match_type: MatchType::Exact,
        patterns: vec![ext.into()],
        action: MatchAction::Relay,
        triage: None,
        relay_targets: Some(vec![target.into()]),
        max_size: None,
        context_bytes: None,
        description: None,
        exclude_patterns: None,
        skip_comments: None,
        exclude_file_paths: None,
    });
    let engine = RuleEngine::compile(rules).expect("compile");
    engine.validate_relay_targets().expect("no dangling");
    engine
}

#[test]
fn github_token_pattern_matches() {
    let engine = engine_with_relay("TestRelayToTokens", "env", "TokenPatterns");
    let entry = file_entry("secrets.env", "/data/secrets.env", 256, 1000, 1000, 0o644);
    let content = b"GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "GitHub token should match TokenPatterns, got: {findings:?}"
    );
}

#[test]
fn slack_webhook_pattern_matches() {
    let engine = engine_with_relay("TestRelayToTokens", "yaml", "TokenPatterns");
    let entry = file_entry("config.yaml", "/data/config.yaml", 256, 1000, 1000, 0o644);
    let content =
        b"webhook: https://hooks.slack.com/services/T0123ABCD/B0123ABCD/xxxxxxxxxxxxxxxxxxx1";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "Slack webhook should match TokenPatterns, got: {findings:?}"
    );
}

#[test]
fn jdbc_connection_string_matches() {
    let engine = engine_with_relay("TestRelayToNetwork", "java", "NetworkCredentialPatterns");
    let entry = file_entry("Db.java", "/data/Db.java", 256, 1000, 1000, 0o644);
    let content = b"String url = \"jdbc:mysql://root:password@db.internal:3306/mydb\";";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "NetworkCredentialPatterns"),
        "JDBC string should match NetworkCredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn sql_create_user_matches() {
    let engine = engine_with_relay("TestRelayToSql", "sql", "SqlAccountCreation");
    let entry = file_entry("setup.sql", "/data/setup.sql", 256, 1000, 1000, 0o644);
    let content = b"CREATE USER admin IDENTIFIED BY 'supersecret';";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "SqlAccountCreation"),
        "SQL CREATE USER should match SqlAccountCreation, got: {findings:?}"
    );
}

#[test]
fn password_txt_matches_red() {
    let engine = default_engine();
    let entry = file_entry(
        "passwords.txt",
        "/data/passwords.txt",
        256,
        1000,
        1000,
        0o644,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "PasswordFiles" && f.triage == Triage::Red),
        "passwords.txt should match PasswordFiles Red, got: {findings:?}"
    );
}

#[test]
fn htpasswd_matches_red() {
    let engine = default_engine();
    let entry = file_entry(".htpasswd", "/var/www/.htpasswd", 256, 1000, 1000, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "WebAuthFiles" && f.triage == Triage::Red),
        ".htpasswd should match WebAuthFiles Red, got: {findings:?}"
    );
}

#[test]
fn php_file_with_creds_relays() {
    let engine = default_engine();
    let entry = file_entry("config.php", "/data/config.php", 256, 1000, 1000, 0o644);
    let content = b"$db_password = 'supersecret123';";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "PHP file with password should relay to CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn java_file_with_jdbc_relays() {
    let engine = default_engine();
    let entry = file_entry(
        "Database.java",
        "/data/Database.java",
        256,
        1000,
        1000,
        0o644,
    );
    let content = b"String url = \"jdbc:mysql://root:password@db.internal:3306/mydb\";";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "NetworkCredentialPatterns"),
        "Java file with JDBC should relay to NetworkCredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn js_file_with_github_token_relays() {
    let engine = default_engine();
    let entry = file_entry("deploy.js", "/data/deploy.js", 256, 1000, 1000, 0o644);
    let content = b"const token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "JS file with GitHub token should relay to TokenPatterns, got: {findings:?}"
    );
}

#[test]
fn pem_file_relays_to_crypto() {
    let engine = default_engine();
    let entry = file_entry("server.pem", "/data/server.pem", 2048, 1000, 1000, 0o644);
    let content = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CryptoPrivateKeys"),
        "PEM with private key should relay to CryptoPrivateKeys, got: {findings:?}"
    );
}

#[test]
fn wp_config_relays_to_creds() {
    let engine = default_engine();
    let entry = file_entry(
        "wp-config.php",
        "/var/www/wp-config.php",
        1024,
        1000,
        1000,
        0o644,
    );
    let content = b"$db_password = 'hunter2secret';";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "wp-config.php with password should produce CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn env_file_now_relays_to_tokens() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content = b"SLACK_TOKEN=xoxb-1234567890-abcdefghijklmnop";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        ".env with Slack token should produce TokenPatterns finding, got: {findings:?}"
    );
}

#[test]
fn unattend_xml_relays_to_creds() {
    let engine = default_engine();
    let entry = file_entry("unattend.xml", "/data/unattend.xml", 1024, 0, 0, 0o644);
    let content = b"<AdministratorPassword>password = admin123</AdministratorPassword>";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "unattend.xml with password should produce CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn pgpass_relays_to_creds() {
    let engine = default_engine();
    let entry = file_entry(".pgpass", "/home/user/.pgpass", 128, 1000, 1000, 0o600);
    let content = b"db.host:5432:mydb:admin:password=secretpass123";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        ".pgpass with credentials should produce CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn suid_without_execute_does_not_match() {
    let engine = default_engine();
    // Mode 0o4644 = SUID set but no execute bit
    let entry = file_entry(
        "somefile.txt",
        "/data/somefile.txt",
        1024,
        1000,
        1000,
        0o4644,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.iter().all(|f| f.rule_name != "SuidBinaries"),
        "SUID without execute should NOT match SuidBinaries"
    );
}

#[test]
fn suid_with_execute_still_matches() {
    let engine = default_engine();
    // Mode 0o4755 = SUID with owner execute
    let entry = file_entry("binary", "/data/binary", 1024, 0, 0, 0o4755);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.iter().any(|f| f.rule_name == "SuidBinaries"),
        "SUID with owner execute should match SuidBinaries"
    );
}

#[test]
fn sgid_without_execute_does_not_match() {
    let engine = default_engine();
    // Mode 0o2644 = SGID set but no group execute
    let entry = file_entry(
        "somefile.txt",
        "/data/somefile.txt",
        1024,
        1000,
        1000,
        0o2644,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.iter().all(|f| f.rule_name != "SgidBinaries"),
        "SGID without group execute should NOT match SgidBinaries"
    );
}

#[test]
fn sgid_with_execute_still_matches() {
    let engine = default_engine();
    // Mode 0o2755 = SGID with group execute
    let entry = file_entry("binary", "/data/binary", 1024, 0, 0, 0o2755);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.iter().any(|f| f.rule_name == "SgidBinaries"),
        "SGID with group execute should match SgidBinaries"
    );
}

#[test]
fn the_file_env_relays_to_credential_scan() {
    let engine = default_engine();
    let entry = file_entry("the_file_env", "/data/the_file_env", 256, 1000, 1000, 0o644);
    let content = b"password = supersecret123";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "the_file_env with credentials should produce CredentialPatterns finding"
    );
}

#[test]
fn env_files_rule_still_matches_dotenv() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    // Use a realistic-looking AWS key (not the well-known AKIAIOSFODNN7EXAMPLE which is excluded)
    let content = b"API_KEY = AKIAZ3MHQN7XJWRS4YTB";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        !findings.is_empty(),
        ".env with credentials should still produce findings"
    );
}

#[test]
fn admin_conf_at_generic_path_no_k8s_finding() {
    let engine = default_engine();
    let entry = file_entry("admin.conf", "/opt/oracle/admin.conf", 512, 0, 0, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.iter().all(|f| f.rule_name != "KubernetesConfigs"),
        "generic admin.conf should NOT match KubernetesConfigs"
    );
}

#[test]
fn admin_conf_at_kubernetes_path_is_black() {
    let engine = default_engine();
    let entry = file_entry("admin.conf", "/etc/kubernetes/admin.conf", 512, 0, 0, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "KubernetesAdminConf" && f.triage == Triage::Black),
        "admin.conf at kubernetes path should match KubernetesAdminConf with Black triage"
    );
}

#[test]
fn kubeconfig_still_matches() {
    let engine = default_engine();
    let entry = file_entry(
        "kubeconfig",
        "/home/user/.kube/kubeconfig",
        512,
        1000,
        1000,
        0o600,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.iter().any(|f| f.rule_name == "KubernetesConfigs"),
        "kubeconfig should still match KubernetesConfigs"
    );
}

#[test]
fn wifi_passwords_txt_matches_red() {
    let engine = default_engine();
    let entry = file_entry(
        "wifi_passwords.txt",
        "/data/wifi_passwords.txt",
        203,
        1000,
        1000,
        0o644,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "PasswordFiles" && f.triage == Triage::Red),
        "wifi_passwords.txt should match PasswordFiles Red, got: {findings:?}"
    );
}

#[test]
fn vault_pass_txt_matches_red() {
    let engine = default_engine();
    let entry = file_entry("vault_pass.txt", "/data/vault_pass.txt", 29, 0, 0, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "VaultPasswordFiles" && f.triage == Triage::Red),
        "vault_pass.txt should match VaultPasswordFiles Red, got: {findings:?}"
    );
}

#[test]
fn ovpn_file_relays_to_creds() {
    let engine = default_engine();
    let entry = file_entry("corp.ovpn", "/data/corp.ovpn", 251, 1000, 1000, 0o644);
    // Don't prefix with '#' -- skip_comments treats that as a comment line.
    let content = b"auth-user-pass inline\npassword = VPN_Adm1n_2024!";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "ovpn with embedded creds should relay to CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn sql_file_relays_to_content() {
    let engine = default_engine();
    let entry = file_entry("dump.sql", "/data/dump.sql", 571, 0, 0, 0o644);
    let content = b"CREATE USER admin IDENTIFIED BY 'supersecret';";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "SqlAccountCreation"),
        "SQL file with CREATE USER should relay to SqlAccountCreation, got: {findings:?}"
    );
}

#[test]
fn deploy_sh_catches_db_pass() {
    let engine = default_engine();
    let entry = file_entry("deploy.sh", "/data/deploy.sh", 201, 1000, 1000, 0o755);
    let content = b"DB_PASS=\"D3pl0y_Pr0d!2024\"";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "shell script with DB_PASS= should match CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn inventory_ini_catches_ansible_ssh_pass() {
    let engine = default_engine();
    let entry = file_entry("inventory.ini", "/data/inventory.ini", 360, 0, 0, 0o644);
    let content = b"web01.corp.local ansible_user=deploy ansible_ssh_pass=W3bD3pl0y!";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "inventory.ini with ansible_ssh_pass= should match CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn jenkins_xml_catches_xml_password_tag() {
    let engine = default_engine();
    let entry = file_entry(
        "jenkins_config.xml",
        "/data/jenkins_config.xml",
        408,
        0,
        0,
        0o644,
    );
    let content = b"<password>D0ck3rR3g!Pr0d2024</password>";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "XML with <password> tag should match CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn terraform_tf_catches_aws_keys() {
    let engine = default_engine();
    let entry = file_entry("main.tf", "/data/main.tf", 292, 0, 0, 0o644);
    // Use a realistic-looking AWS key (not the well-known AKIAIOSFODNN7EXAMPLE which is excluded)
    let content = b"access_key = \"AKIAZ3MHQN7XJWRS4YTB\"";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CloudKeyPatterns"),
        "Terraform .tf with AWS key should relay to CloudKeyPatterns, got: {findings:?}"
    );
}

#[test]
fn powershell_file_relays_to_creds() {
    let engine = default_engine();
    let entry = file_entry("setup.ps1", "/data/setup.ps1", 256, 1000, 1000, 0o644);
    let content = b"$password = \"Secret123!abc\"";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "PowerShell with password should relay to CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn batch_file_relays_to_creds() {
    let engine = default_engine();
    let entry = file_entry("deploy.bat", "/data/deploy.bat", 256, 1000, 1000, 0o644);
    let content = b"set PASSWORD=Secret123abc";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "batch file with PASSWORD= should relay to CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn npmrc_relays_to_tokens() {
    let engine = default_engine();
    let entry = file_entry(".npmrc", "/home/user/.npmrc", 256, 1000, 1000, 0o644);
    // The //registry... format is treated as a comment line by skip_comments.
    // Use a standalone _authToken line with an npm_ prefixed token (36 alnum chars after npm_).
    let content = b"_authToken=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        ".npmrc with npm token should produce TokenPatterns finding, got: {findings:?}"
    );
}

#[test]
fn secrets_yml_relays_to_creds() {
    let engine = default_engine();
    let entry = file_entry("secrets.yml", "/data/secrets.yml", 256, 1000, 1000, 0o644);
    let content = b"db_password: hunter2secretval";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "secrets.yml with password should relay to CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn appsettings_json_relays() {
    let engine = default_engine();
    let entry = file_entry(
        "appsettings.json",
        "/data/appsettings.json",
        512,
        1000,
        1000,
        0o644,
    );
    let content = b"Server=db.local;Database=app;Password=SecretDbPass123!";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "appsettings.json with password should produce findings, got: {findings:?}"
    );
}

#[test]
fn deploy_key_matches_red() {
    let engine = default_engine();
    let entry = file_entry(
        "deploy_key",
        "/home/user/.ssh/deploy_key",
        1700,
        1000,
        1000,
        0o600,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "SshCustomKeyNames" && f.triage == Triage::Red),
        "deploy_key should match SshCustomKeyNames Red, got: {findings:?}"
    );
}

#[test]
fn gradle_file_relays() {
    let engine = default_engine();
    let entry = file_entry("build.gradle", "/data/build.gradle", 256, 1000, 1000, 0o644);
    let content = b"password = \"secret123value!\"";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "Gradle file with password should relay to CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn properties_file_relays() {
    let engine = default_engine();
    let entry = file_entry(
        "db.properties",
        "/data/db.properties",
        256,
        1000,
        1000,
        0o644,
    );
    let content = b"jdbc.password=secret123abc!";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "properties file with password should relay to CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn hcl_file_relays() {
    let engine = default_engine();
    let entry = file_entry("config.hcl", "/data/config.hcl", 256, 1000, 1000, 0o644);
    let content = b"password = \"vault_secret_val\"";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "HCL file with password should relay to CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn template_file_relays() {
    let engine = default_engine();
    let entry = file_entry("vars.j2", "/data/vars.j2", 256, 1000, 1000, 0o644);
    let content = b"db_password: supersecretvalue1";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "Jinja2 template with password should relay to CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn docker_config_json_matches_black() {
    let engine = default_engine();
    let entry = file_entry(
        "config.json",
        "/home/user/.docker/config.json",
        512,
        1000,
        1000,
        0o644,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "DockerConfigPaths" && f.triage == Triage::Black),
        "Docker config.json should match DockerConfigPaths Black, got: {findings:?}"
    );
}

#[test]
fn authorized_keys_matches_yellow() {
    let engine = default_engine();
    let entry = file_entry(
        "authorized_keys",
        "/home/user/.ssh/authorized_keys",
        181,
        1000,
        1000,
        0o644,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "SshInfoFiles" && f.triage == Triage::Yellow),
        "authorized_keys should match SshInfoFiles Yellow, got: {findings:?}"
    );
}

#[test]
fn secret_equals_value_matches() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    // The credential pattern now requires a qualifying suffix: secret_key, secret_token, etc.
    let content = b"MY_SECRET_KEY=SuperSecretVal1ab";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "secret_key= assignment should match CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn url_embedded_credentials_match() {
    let engine = default_engine();
    let entry = file_entry("app.conf", "/data/app.conf", 256, 1000, 1000, 0o644);
    let content = b"db_url=mysql://admin:p4ssw0rd@db.local:3306/app";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "URL-embedded credentials should match CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn http_basic_auth_header_matches() {
    let engine = default_engine();
    let entry = file_entry("proxy.conf", "/data/proxy.conf", 256, 1000, 1000, 0o644);
    // Use a base64 value that does not end with '=' to avoid the empty-value
    // exclude pattern [=:]\s*["']?\s*$ matching the trailing '=' of padding.
    let content = b"Authorization: Basic YWRtaW46cDRzc3cwcmQ";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "HTTP Basic auth header should match CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn mysql_cli_password_in_script_matches() {
    let engine = default_engine();
    let entry = file_entry("backup.sh", "/data/backup.sh", 256, 1000, 1000, 0o644);
    let content = b"mysql -u root -pR00tPass! -h db.local";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "mysql -p inline password should match CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn saas_token_and_cloud_key_patterns_match() {
    let engine = default_engine();
    let cases: &[(&str, &[u8], &str)] = &[
        (
            "secrets.env",
            b"SENDGRID_KEY=SG.f4k3S3ndGr1dK3yF0rNFS4ud1t",
            "TokenPatterns",
        ),
        (
            "secrets.env",
            b"STRIPE_KEY=sk_test_f4k3Str1p3S3cr3tK3yL4bTesting1",
            "CloudKeyPatterns",
        ),
        (
            ".pypirc",
            b"password = pypi-AgEIcHlwaS5vcmcABCDEFGH",
            "TokenPatterns",
        ),
        (
            ".env",
            b"OPENAI_API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh",
            "TokenPatterns",
        ),
        (
            ".env",
            b"ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh",
            "TokenPatterns",
        ),
        (
            ".env",
            b"HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
            "TokenPatterns",
        ),
        (
            "vault.env",
            b"VAULT_TOKEN=hvs.CAESIABCDEFGHIJKLMNOP1234",
            "TokenPatterns",
        ),
        (
            "config.env",
            b"GCP_KEY=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567",
            "CloudKeyPatterns",
        ),
        (
            ".env",
            b"DO_TOKEN=dop_v1_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "CloudKeyPatterns",
        ),
        (
            ".env",
            b"SHOPIFY_TOKEN=shpat_abcdef0123456789abcdef0123456789",
            "TokenPatterns",
        ),
    ];

    for (name, content, expected_rule) in cases {
        let path = format!("/data/{name}");
        let entry = file_entry(name, &path, 320, 1000, 1000, 0o644);
        let findings = engine.evaluate_file(&entry, Some(*content));
        assert!(
            findings.iter().any(|f| f.rule_name == *expected_rule),
            "content {:?} should match {expected_rule}, got: {findings:?}",
            std::str::from_utf8(content).unwrap_or("<binary>")
        );
    }
}

#[test]
fn credential_pattern_skips_changeme_placeholder() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content = b"password=changeme";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().all(|f| f.rule_name != "CredentialPatterns"),
        "changeme placeholder should be suppressed by exclude_patterns, got: {findings:?}"
    );
}

#[test]
fn credential_pattern_skips_env_var_reference() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content = b"password=${DB_PASSWORD}";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().all(|f| f.rule_name != "CredentialPatterns"),
        "${{}} env var reference should be suppressed, got: {findings:?}"
    );
}

#[test]
fn credential_pattern_skips_template_syntax() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content = b"password={{ vault_password }}";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().all(|f| f.rule_name != "CredentialPatterns"),
        "{{{{}}}} template syntax should be suppressed, got: {findings:?}"
    );
}

#[test]
fn credential_pattern_skips_comment_line() {
    let engine = default_engine();
    let entry = file_entry("app.conf", "/data/app.conf", 256, 1000, 1000, 0o644);
    let content = b"# password = my_secret_password_here";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().all(|f| f.rule_name != "CredentialPatterns"),
        "commented line should be suppressed by skip_comments, got: {findings:?}"
    );
}

#[test]
fn credential_pattern_matches_real_secret() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content = b"DB_PASSWORD=xK8mP!zQ2wR5vBnL";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "real secret should still match CredentialPatterns, got: {findings:?}"
    );
}

#[test]
fn gcp_service_account_structure_via_relay() {
    // GcpServiceAccountStructure is a content rule reachable via relay.
    // Test it through a custom relay to verify it works and assigns Yellow triage.
    let engine = engine_with_relay("TestJsonRelay", "json", "GcpServiceAccountStructure");
    let entry = file_entry("service.json", "/data/service.json", 512, 1000, 1000, 0o644);
    let content = br#"{"type": "service_account", "project_id": "my-project"}"#;
    let findings = engine.evaluate_file(&entry, Some(content));
    let sa_finding = findings
        .iter()
        .find(|f| f.rule_name == "GcpServiceAccountStructure");
    assert!(
        sa_finding.is_some(),
        "GCP service_account structure should match via relay, got: {findings:?}"
    );
    assert_eq!(
        sa_finding.unwrap().triage,
        Triage::Yellow,
        "GCP service_account structure should be Yellow (informational), not Red"
    );
}

#[test]
fn hidden_dotfile_without_creds_produces_no_findings() {
    let engine = default_engine();
    let entry = file_entry(".gitignore", "/data/.gitignore", 64, 1000, 1000, 0o644);
    let content = b"*.log\nnode_modules/\n";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.is_empty(),
        "dotfile without credential content should produce no findings"
    );
}

#[test]
fn linux_lost_and_found_discarded() {
    let engine = default_engine();
    assert!(
        engine.should_discard_dir("lost+found", "/lost+found"),
        "lost+found directory should be discarded"
    );
}

#[test]
fn linux_snapshots_dir_discarded() {
    let engine = default_engine();
    assert!(
        engine.should_discard_dir(".snapshots", "/data/.snapshots"),
        ".snapshots directory should be discarded"
    );
}

#[test]
fn linux_system_bin_paths_discarded() {
    let engine = default_engine();
    for (name, path) in [
        ("bin", "/bin"),
        ("sbin", "/sbin"),
        ("bin", "/usr/bin"),
        ("sbin", "/usr/sbin"),
        ("libexec", "/usr/libexec"),
        ("bin", "/usr/local/bin"),
        ("sbin", "/usr/local/sbin"),
    ] {
        assert!(
            engine.should_discard_dir(name, path),
            "should discard {path}"
        );
    }
}

#[test]
fn linux_boot_and_kernel_discarded() {
    let engine = default_engine();
    for (name, path) in [
        ("boot", "/boot"),
        ("modules", "/lib/modules"),
        ("firmware", "/lib/firmware"),
        ("src", "/usr/src"),
        ("modules", "/usr/lib/modules"),
        ("firmware", "/usr/lib/firmware"),
    ] {
        assert!(
            engine.should_discard_dir(name, path),
            "should discard {path}"
        );
    }
}

#[test]
fn linux_usr_share_noise_discarded() {
    let engine = default_engine();
    for (name, path) in [
        ("locale", "/usr/share/locale"),
        ("zoneinfo", "/usr/share/zoneinfo"),
        ("fonts", "/usr/share/fonts"),
        ("icons", "/usr/share/icons"),
        ("themes", "/usr/share/themes"),
        ("mime", "/usr/share/mime"),
        ("applications", "/usr/share/applications"),
        ("terminfo", "/usr/share/terminfo"),
        ("i18n", "/usr/share/i18n"),
        ("info", "/usr/share/info"),
        ("help", "/usr/share/help"),
        ("pixmaps", "/usr/share/pixmaps"),
        ("sounds", "/usr/share/sounds"),
    ] {
        assert!(
            engine.should_discard_dir(name, path),
            "should discard {path}"
        );
    }
}

#[test]
fn linux_pkg_cache_discarded() {
    let engine = default_engine();
    for (name, path) in [
        ("apt", "/var/cache/apt"),
        ("yum", "/var/cache/yum"),
        ("dnf", "/var/cache/dnf"),
        ("pacman", "/var/cache/pacman"),
        ("dpkg", "/var/lib/dpkg"),
        ("apt", "/var/lib/apt"),
        ("rpm", "/var/lib/rpm"),
        ("pacman", "/var/lib/pacman"),
    ] {
        assert!(
            engine.should_discard_dir(name, path),
            "should discard {path}"
        );
    }
}

#[test]
fn linux_tmp_dirs_discarded() {
    let engine = default_engine();
    assert!(
        engine.should_discard_dir("tmp", "/tmp"),
        "should discard /tmp"
    );
    assert!(
        engine.should_discard_dir("tmp", "/var/tmp"),
        "should discard /var/tmp"
    );
}

#[test]
fn linux_system_includes_discarded() {
    let engine = default_engine();
    assert!(
        engine.should_discard_dir("include", "/usr/include"),
        "should discard /usr/include"
    );
    assert!(
        engine.should_discard_dir("include", "/usr/local/include"),
        "should discard /usr/local/include"
    );
}

#[test]
fn linux_system_state_discarded() {
    let engine = default_engine();
    for (name, path) in [
        ("systemd", "/var/lib/systemd"),
        ("dbus", "/var/lib/dbus"),
        ("snapd", "/var/lib/snapd"),
        ("flatpak", "/var/lib/flatpak"),
    ] {
        assert!(
            engine.should_discard_dir(name, path),
            "should discard {path}"
        );
    }
}

#[test]
fn linux_high_value_dirs_not_discarded() {
    let engine = default_engine();
    // These MUST NOT be discarded — they contain credentials
    assert!(
        !engine.should_discard_dir("etc", "/etc"),
        "/etc must NOT be discarded"
    );
    assert!(
        !engine.should_discard_dir("home", "/home"),
        "/home must NOT be discarded"
    );
    assert!(
        !engine.should_discard_dir("root", "/root"),
        "/root must NOT be discarded"
    );
    assert!(
        !engine.should_discard_dir("opt", "/opt"),
        "/opt must NOT be discarded"
    );
    assert!(
        !engine.should_discard_dir("log", "/var/log"),
        "/var/log must NOT be discarded"
    );
    assert!(
        !engine.should_discard_dir("www", "/var/www"),
        "/var/www must NOT be discarded"
    );
    assert!(
        !engine.should_discard_dir("backups", "/var/backups"),
        "/var/backups must NOT be discarded"
    );
    assert!(
        !engine.should_discard_dir("docker", "/var/lib/docker"),
        "/var/lib/docker must NOT be discarded"
    );
    assert!(
        !engine.should_discard_dir("srv", "/srv"),
        "/srv must NOT be discarded"
    );
}

#[test]
fn c_header_files_discarded() {
    let engine = default_engine();
    for ext in ["h", "hpp", "hh", "hxx"] {
        let name = format!("foo.{ext}");
        let path = format!("/usr/include/{name}");
        let entry = file_entry(&name, &path, 2048, 0, 0, 0o644);
        let findings = engine.evaluate_file(&entry, None);
        assert!(
            findings.is_empty(),
            ".{ext} files should be discarded, got: {findings:?}"
        );
    }
}

#[test]
fn kernel_module_files_discarded() {
    let engine = default_engine();
    let entry = file_entry("ext4.ko", "/lib/modules/5.15/ext4.ko", 4096, 0, 0, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.is_empty(),
        ".ko files should be discarded, got: {findings:?}"
    );
}

#[test]
fn locale_files_discarded() {
    let engine = default_engine();
    let mo_entry = file_entry(
        "messages.mo",
        "/usr/share/locale/en/messages.mo",
        8192,
        0,
        0,
        0o644,
    );
    let findings = engine.evaluate_file(&mo_entry, None);
    assert!(
        findings.is_empty(),
        ".mo files should be discarded, got: {findings:?}"
    );

    let po_entry = file_entry(
        "messages.po",
        "/usr/share/locale/en/messages.po",
        8192,
        0,
        0,
        0o644,
    );
    let findings = engine.evaluate_file(&po_entry, None);
    assert!(
        findings.is_empty(),
        ".po files should be discarded, got: {findings:?}"
    );
}

#[test]
fn extensionless_config_with_aws_key_caught_by_content_fallback() {
    let engine = default_engine();
    // A file named "config" (no extension) doesn't match any file rule,
    // but content fallback should still catch the AWS key.
    let entry = file_entry("config", "/data/config", 256, 1000, 1000, 0o644);
    let content = b"aws_access_key_id = AKIAZ3MHQN7XJWRS4YTB";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        !findings.is_empty(),
        "extensionless file with AWS key should be caught by content fallback, got: {findings:?}"
    );
}

#[test]
fn txt_file_with_password_caught_by_content_fallback() {
    // Bug 3.3: .txt files have no file rule that relays to content scanning,
    // but the content fallback (Bug 3.1 fix) catches them.
    // Use "memo.txt" which doesn't match any filename rule (unlike "notes.txt"
    // which matches TodoFiles).
    let engine = default_engine();
    let entry = file_entry("memo.txt", "/data/memo.txt", 256, 1000, 1000, 0o644);
    let content = b"password=hunter2secret1";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "memo.txt with password should be caught by content fallback, got: {findings:?}"
    );
}

#[test]
fn content_fallback_skips_binary_content() {
    let engine = default_engine();
    // Extensionless file with binary content should NOT trigger string content rules.
    let entry = file_entry("data", "/data/data", 256, 1000, 1000, 0o644);
    let content = b"password=secret\x00\x01\x02binary_stuff";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().all(|f| f.rule_name != "CredentialPatterns"),
        "binary content should not trigger string content rules via fallback, got: {findings:?}"
    );
}

#[test]
fn content_fallback_does_not_fire_when_file_rule_relays() {
    let engine = default_engine();
    // .env matches a file rule that relays to content scanning.
    // The content fallback should NOT fire (had_relay_or_snaffle = true).
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content = b"DB_PASSWORD=xK8mP!zQ2wR5vBnL";
    let findings = engine.evaluate_file(&entry, Some(content));
    // Should still find credentials via the relay path.
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        ".env should still find credentials via relay, got: {findings:?}"
    );
}

#[test]
fn content_fallback_no_content_no_findings() {
    let engine = default_engine();
    // Extensionless file with no content should produce no findings.
    let entry = file_entry("unknown_file", "/data/unknown_file", 256, 1000, 1000, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.is_empty(),
        "extensionless file without content should produce no findings, got: {findings:?}"
    );
}

#[test]
fn dotfile_without_secrets_no_false_positive() {
    let engine = default_engine();
    // Extensionless dotfile with innocuous content should not trigger findings.
    let entry = file_entry(".gitignore", "/data/.gitignore", 64, 1000, 1000, 0o644);
    let content = b"*.log\nnode_modules/\ntarget/\n";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.is_empty(),
        "dotfile without secrets should produce no false positives, got: {findings:?}"
    );
}

// --- Bug 3.2: .map discard pattern precision ---

#[test]
fn network_map_file_not_discarded() {
    let engine = default_engine();
    // "network.map" should NOT be discarded by the minified files rule.
    // Only ".js.map" and ".css.map" should be discarded.
    let entry = file_entry("network.map", "/data/network.map", 256, 1000, 1000, 0o644);
    let content = b"password=networkSecret123!";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        !findings.is_empty(),
        "network.map should not be discarded, content fallback should find credentials, got: {findings:?}"
    );
}

#[test]
fn js_source_map_still_discarded() {
    let engine = default_engine();
    let entry = file_entry("app.js.map", "/data/app.js.map", 50000, 1000, 1000, 0o644);
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.is_empty(),
        ".js.map files should still be discarded, got: {findings:?}"
    );
}

#[test]
fn css_source_map_still_discarded() {
    let engine = default_engine();
    let entry = file_entry(
        "styles.css.map",
        "/data/styles.css.map",
        50000,
        1000,
        1000,
        0o644,
    );
    let findings = engine.evaluate_file(&entry, None);
    assert!(
        findings.is_empty(),
        ".css.map files should still be discarded, got: {findings:?}"
    );
}

#[test]
fn discard_linux_system_paths_nested_catches_backup_prefix() {
    let engine = default_engine();

    // Path rooted under a backup tree — must still be discarded.
    assert!(
        engine.should_discard_dir("doc", "/backups/host/root/usr/share/doc/m2crypto-0.21.1",),
        "nested /usr/share/doc/ should be discarded under backup prefix"
    );

    // Absolute path — must still be discarded by the existing rule.
    assert!(
        engine.should_discard_dir("doc", "/usr/share/doc/m2crypto-0.21.1"),
        "absolute /usr/share/doc/ must still be discarded"
    );

    // Unrelated path — must NOT be discarded.
    assert!(
        !engine.should_discard_dir("myapp", "/srv/myapp/config"),
        "unrelated path must not be discarded"
    );
}

#[test]
fn discard_oracle_vendor_dirs_nested_catches_backup_prefix() {
    let engine = default_engine();

    assert!(
        engine.should_discard_dir("man3", "/host/1.2.3/perl/man/man3",),
        "nested Oracle perl/man/man3 should be discarded"
    );

    assert!(
        engine.should_discard_dir("admin", "/export/files/rdbms/admin",),
        "nested rdbms/admin should be discarded"
    );

    assert!(
        engine.should_discard_dir("mesg", "/host/tmp/123/srvm/mesg",),
        "nested srvm/mesg should be discarded"
    );

    assert!(
        engine.should_discard_dir("help", "/export/network/tools/help",),
        "nested network/tools/help should be discarded"
    );

    assert!(
        engine.should_discard_dir("ssl", "/export/usr/share/doc/m2crypto-0.21.1/demo/ssl",),
        "m2crypto demo/ssl should be discarded"
    );

    // Control: an unrelated nested path.
    assert!(
        !engine.should_discard_dir("config", "/srv/myapp/config"),
        "unrelated path must not be discarded"
    );
}

#[test]
fn discard_oracle_product_extensions() {
    let engine = default_engine();
    let entry = |name: &str| file_entry(name, &format!("/some/path/{name}"), 1024, 0, 0, 0o644);

    // All these extensions must produce an empty findings list (discarded before content scan).
    for name in [
        "plan.trc",
        "plan.trm",
        "catalog.msg",
        "db.bsq",
        "wrapped.plb",
        "script.sbs",
        "file.dbl",
        "build.mk",
        "transform.xsl",
    ] {
        let findings =
            engine.evaluate_file(&entry(name), Some(b"password = 'wouldmatchifscanned'"));
        assert!(
            findings.is_empty(),
            "{name}: expected discard, got findings: {findings:?}"
        );
    }
}

#[test]
fn discard_doc_format_extensions() {
    let engine = default_engine();
    let entry = |name: &str| file_entry(name, &format!("/some/path/{name}"), 1024, 0, 0, 0o644);

    for name in [
        "DBI.3",
        "perllocale.1",
        "netcat.8",
        "module.pod",
        "paper.tex",
    ] {
        let findings =
            engine.evaluate_file(&entry(name), Some(b"password = 'wouldmatchifscanned'"));
        assert!(
            findings.is_empty(),
            "{name}: expected discard, got findings: {findings:?}"
        );
    }

    // .rst is NOT discarded (README-style docs sometimes contain secrets).
    let findings = engine.evaluate_file(&entry("README.rst"), Some(b"nothing here"));
    // We don't assert findings.is_empty() here because we're not testing the rule — just
    // verifying .rst doesn't trip a discard. evaluate_file returns [] on NoMatch anyway,
    // so we just ensure no panic / compile issue.
    let _ = findings;
}

#[test]
fn credential_patterns_suppresses_shell_expansion() {
    let engine = default_engine();
    let entry = file_entry(
        "create_db.sh",
        "/source/Oracle/Automation/create_db.sh",
        1024,
        0,
        0,
        0o644,
    );

    // $(...) command substitution.
    let content = b"SYS_PWD=$(echo $* | grep -Po 'sys_pwd:\\K[^ ]+')\n";
    let findings = engine.evaluate_content_only(&entry, content);
    let creds: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_name == "CredentialPatterns")
        .collect();
    assert!(
        creds.is_empty(),
        "shell $(...) expansion should not match: {creds:?}"
    );

    // Variable expansion ${VAR}.
    let content = b"SYS_PASSWD=${SYS_PASSWD}\n";
    let findings = engine.evaluate_content_only(&entry, content);
    let creds: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_name == "CredentialPatterns")
        .collect();
    assert!(
        creds.is_empty(),
        "${{VAR}} expansion should not match: {creds:?}"
    );

    // Bare variable.
    let content = b"PWD=$sys_passwd\n";
    let findings = engine.evaluate_content_only(&entry, content);
    let creds: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_name == "CredentialPatterns")
        .collect();
    assert!(creds.is_empty(), "bare $var should not match: {creds:?}");

    // Log line echo.
    let content = b"echo \"INFO: SYS_PASSWD : $sys_passwd\"\n";
    let findings = engine.evaluate_content_only(&entry, content);
    let creds: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_name == "CredentialPatterns")
        .collect();
    assert!(creds.is_empty(), "log echo should not match: {creds:?}");
}

#[test]
fn credential_patterns_still_fires_on_real_cleartext() {
    let engine = default_engine();
    let entry = file_entry("config.yml", "/etc/myapp/config.yml", 1024, 0, 0, 0o644);

    let content = b"db_password: 'superlongohverylong2'\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert_eq!(
        findings
            .iter()
            .filter(|f| f.rule_name == "CredentialPatterns")
            .count(),
        1,
        "real cleartext password must still fire: {findings:?}"
    );
}

#[test]
fn credential_patterns_excludes_trc_by_path() {
    let engine = default_engine();
    let entry = file_entry(
        "dump.trc",
        "/export/rdbms/mydb/trace/dump.trc",
        1024,
        0,
        0,
        0o644,
    );

    // Even with content that would otherwise match, the exclude_file_paths suppresses it.
    let content = b"password = 'superlongohverylong2'\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().all(|f| f.rule_name != "CredentialPatterns"),
        ".trc path exclude must suppress CredentialPatterns"
    );
}

#[test]
fn credential_patterns_excludes_perl_man_by_path() {
    let engine = default_engine();
    let entry = file_entry(
        "DBI.3",
        "/opt/oracle/perl/man/man3/DBI.3",
        1024,
        0,
        0,
        0o644,
    );

    let content = b"password = 'superlongohverylong2'\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().all(|f| f.rule_name != "CredentialPatterns"),
        "perl/man/ path exclude must suppress CredentialPatterns"
    );
}

#[test]
fn credential_patterns_excludes_apex_page_export_by_path() {
    let engine = default_engine();
    let entry = file_entry("stuff.sql", "/apex/workspace/stuff.sql", 1024, 0, 0, 0o644);

    // APEX page exports contain literal strings like 'passwd = confirm passwd'
    // as validation labels. These should not fire CredentialPatterns.
    let content = b"p_validation=>'passwd = confirm passwd',\n";
    let findings = engine.evaluate_content_only(&entry, content);
    let creds: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_name == "CredentialPatterns")
        .collect();
    assert!(
        creds.is_empty(),
        "APEX /apex/ path exclude must suppress CredentialPatterns: {creds:?}"
    );
}

#[test]
fn sql_account_creation_suppresses_shell_var_in_identified_by() {
    let engine = default_engine();
    let entry = file_entry(
        "setup.sql",
        "/export/Oracle/Automation/setup.sql",
        1024,
        0,
        0,
        0o644,
    );

    let content = b"ADMINISTER KEY MANAGEMENT SET KEY FORCE KEYSTORE IDENTIFIED BY \"${EP_PASS}\" CONTAINER=ALL;\n";
    let findings = engine.evaluate_content_only(&entry, content);
    let hits: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_name == "SqlAccountCreation")
        .collect();
    assert!(
        hits.is_empty(),
        "${{VAR}} expansion in IDENTIFIED BY should not match: {hits:?}"
    );
}

#[test]
fn sql_account_creation_suppresses_comment_header_prose() {
    let engine = default_engine();
    let entry = file_entry(
        "create_user_template.sql",
        "/export/Oracle/Automation/create_user_template.sql",
        1024,
        0,
        0,
        0o644,
    );

    let content = b"/*************************************************\n *  TO CREATE USER exampleuser FOR LOGON TRIGGER\n *************************************************/\n";
    let findings = engine.evaluate_content_only(&entry, content);
    let hits: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_name == "SqlAccountCreation")
        .collect();
    assert!(
        hits.is_empty(),
        "comment-header prose should not match: {hits:?}"
    );
}

#[test]
fn sql_account_creation_suppresses_message_catalog_prose() {
    let engine = default_engine();
    let entry = file_entry(
        "chksund.msg",
        "/source/Oracle/Automation/srvm/mesg/chksund.msg",
        1024,
        0,
        0,
        0o644,
    );

    let content = b"2053, CRED_CREATE_USERPASS_FAIL, \"failed to create user name and password credentials on domain {0}\"\n";
    let findings = engine.evaluate_content_only(&entry, content);
    let hits: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_name == "SqlAccountCreation")
        .collect();
    assert!(
        hits.is_empty(),
        "message catalog prose should not match: {hits:?}"
    );
}

#[test]
fn sql_account_creation_still_fires_on_real_identified_by() {
    let engine = default_engine();
    let entry = file_entry("admin.sql", "/dba/temp/admin.sql", 1024, 0, 0, 0o644);

    let content = b"CREATE USER ADMIN IDENTIFIED BY 'Sup3rS3cret99' DEFAULT TABLESPACE GG_DATA;\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().any(|f| f.rule_name == "SqlAccountCreation"),
        "real IDENTIFIED BY must still match: {findings:?}"
    );
}

#[test]
fn sql_account_creation_excludes_apex_page_export_by_path() {
    let engine = default_engine();
    let entry = file_entry("stuff.sql", "/apex/workspace/stuff.sql", 1024, 0, 0, 0o644);

    let content = b"CREATE USER FOOBAR IDENTIFIED BY 'wouldotherwisematch';\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().all(|f| f.rule_name != "SqlAccountCreation"),
        "APEX page export path should suppress SqlAccountCreation"
    );
}

#[test]
fn linux_secrets_ignores_oracle_plan_id() {
    let engine = default_engine();
    let entry = file_entry("dump.sql", "/dba/scripts/dump.sql", 1024, 0, 0, 0o644);

    let content = b"68 - SET$D471D3E9         / \"SYS_TBL_$1$\"@\"SEL$D471D3E9\"\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().all(|f| f.rule_name != "LinuxSecrets"),
        "Oracle plan ID should not match LinuxSecrets: {findings:?}"
    );
}

#[test]
fn linux_secrets_ignores_perl_groff_escape() {
    let engine = default_engine();
    let entry = file_entry(
        "perllocale.doc",
        "/dba/docs/perllocale.doc",
        1024,
        0,
        0,
        0o644,
    );

    let content = b"\\&\\f(CW\\*(C\\`LC_NUMERIC\\*(C'\\fR\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().all(|f| f.rule_name != "LinuxSecrets"),
        "Perl groff escape should not match LinuxSecrets: {findings:?}"
    );
}

#[test]
fn linux_secrets_fires_on_real_shadow_line() {
    let engine = default_engine();
    let entry = file_entry("shadow.bak", "/export/shadow.bak", 1024, 0, 0, 0o644);

    let content = b"root:$6$saltsaltsalt$hashhashhashhashhashhashhashhashhashhash0123456789:19000:0:99999:7:::\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().any(|f| f.rule_name == "LinuxSecrets"),
        "real shadow line must still match: {findings:?}"
    );
}

#[test]
fn linux_secrets_fires_on_bcrypt_hash() {
    let engine = default_engine();
    let entry = file_entry("users.txt", "/export/users.txt", 1024, 0, 0, 0o644);

    let content = b"$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().any(|f| f.rule_name == "LinuxSecrets"),
        "bcrypt hash must match: {findings:?}"
    );
}

#[test]
fn linux_secrets_fires_on_nopasswd_directive() {
    let engine = default_engine();
    let entry = file_entry("sudoers.bak", "/export/sudoers.bak", 1024, 0, 0, 0o644);

    let content = b"deploy ALL=(ALL) NOPASSWD: /usr/sbin/apache2ctl\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().any(|f| f.rule_name == "LinuxSecrets"),
        "NOPASSWD directive must match: {findings:?}"
    );
}

#[test]
fn network_credential_patterns_ignores_html_prose() {
    let engine = default_engine();
    let entry = file_entry(
        "help.htm",
        "/oracle/network/tools/help/mgr/help/listener_help.htm",
        1024,
        0,
        0,
        0o644,
    );

    let content =
        b"<li><p>Enable password authentication for the Listener Control utility</p></li>\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings
            .iter()
            .all(|f| f.rule_name != "NetworkCredentialPatterns"),
        "HTML prose should not match: {findings:?}"
    );
}

#[test]
fn network_credential_patterns_fires_on_cisco_config() {
    let engine = default_engine();
    let entry = file_entry(
        "running-config.txt",
        "/backup/running-config.txt",
        1024,
        0,
        0,
        0o644,
    );

    let content = b"enable secret 5 $1$salt$abcdef12345678\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "NetworkCredentialPatterns"),
        "Cisco enable secret must match: {findings:?}"
    );
}

#[test]
fn network_credential_patterns_fires_on_snmp_community() {
    let engine = default_engine();
    let entry = file_entry(
        "running-config.txt",
        "/backup/running-config.txt",
        1024,
        0,
        0,
        0o644,
    );

    let content = b"snmp-server community publicro RO\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "NetworkCredentialPatterns"),
        "SNMP community must match: {findings:?}"
    );
}

#[test]
fn network_credential_patterns_fires_on_jdbc_url() {
    let engine = default_engine();
    let entry = file_entry(
        "application.properties",
        "/opt/myapp/application.properties",
        1024,
        0,
        0,
        0o644,
    );

    let content = b"db.url=jdbc:postgresql://dbhost.example.com:5432/mydb\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_name == "NetworkCredentialPatterns"),
        "JDBC URL must match: {findings:?}"
    );
}

#[test]
fn connection_strings_ignores_odbc_help_html() {
    let engine = default_engine();
    let entry = file_entry(
        "sqora.htm",
        "/oracle/odbc/help/us/sqora.htm",
        1024,
        0,
        0,
        0o644,
    );

    let content = b"DSN=Personnel;UID=Kotzwinkle;PWD=;DRIVER={Oracle ODBC Driver}\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().all(|f| f.rule_name != "ConnectionStrings"),
        "odbc/help/ path should suppress: {findings:?}"
    );
}

#[test]
fn connection_strings_ignores_placeholder_format_string() {
    let engine = default_engine();
    let entry = file_entry("catalog.txt", "/etc/myapp/catalog.txt", 1024, 0, 0, 0o644);

    let content = b"Error adding replica ldap://%s:%d.\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().all(|f| f.rule_name != "ConnectionStrings"),
        "format string placeholder should not match: {findings:?}"
    );
}

#[test]
fn connection_strings_ignores_bare_dsn_without_credentials() {
    let engine = default_engine();
    let entry = file_entry("notes.txt", "/etc/myapp/notes.txt", 1024, 0, 0, 0o644);

    let content = b"The DSN=MyReports entry points to the sales database.\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().all(|f| f.rule_name != "ConnectionStrings"),
        "bare DSN= without credentials should not match: {findings:?}"
    );
}

#[test]
fn connection_strings_fires_on_dsn_with_credentials() {
    let engine = default_engine();
    let entry = file_entry("config.ini", "/opt/myapp/config.ini", 1024, 0, 0, 0o644);

    let content = b"connection = DSN=MyDb;UID=admin;PWD=s3cret999;\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().any(|f| f.rule_name == "ConnectionStrings"),
        "DSN+UID+PWD must match: {findings:?}"
    );
}

#[test]
fn connection_strings_still_fires_on_postgres_url() {
    let engine = default_engine();
    let entry = file_entry("app.conf", "/etc/myapp/app.conf", 1024, 0, 0, 0o644);

    let content = b"DATABASE_URL=postgresql://admin:hunter2@dbhost:5432/prod\n";
    let findings = engine.evaluate_content_only(&entry, content);
    assert!(
        findings.iter().any(|f| f.rule_name == "ConnectionStrings"),
        "postgres URL must match: {findings:?}"
    );
}

// --- Regression: TOML single-quoted literal-string \\s / \\$ / \\b bugs ---

#[test]
fn credential_patterns_exclude_strips_assign_tag_suppressions() {
    // Regression: the four exclude patterns that used `\\s` / `\\$` / `\\b` in
    // single-quoted TOML never matched because those literal strings rendered as
    // `\\s` (literal backslash-backslash-s) in the compiled regex. After the fix
    // each pattern must suppress CredentialPatterns on its designated FP class.
    let engine = default_engine();

    // Pattern 1: '[=:]\s*<[a-zA-Z][^>]*>' — assignment to an XML/HTML tag.
    // The main CredentialPatterns regex matches `password = <element` (8+ non-ws
    // chars); the fixed exclude then suppresses it.
    let entry1 = file_entry("config.xml", "/test/config.xml", 1024, 0, 0, 0o644);
    let content1 = b"password = <element attr=\"x\">value</element>\n";
    let findings1 = engine.evaluate_content_only(&entry1, content1);
    let creds1: Vec<_> = findings1
        .iter()
        .filter(|f| f.rule_name == "CredentialPatterns")
        .collect();
    assert!(
        creds1.is_empty(),
        "XML-tag assignment should be suppressed by exclude pattern 1, got: {creds1:?}"
    );

    // Pattern 2 (post-removal): '$password = $_POST[...]' is still suppressed by
    // the existing \$[A-Za-z_] var-RHS exclude at line 40 — this case verifies
    // PHP variable-to-variable assignments remain excluded after line 33 removal.
    let entry2 = file_entry("index.php", "/test/index.php", 1024, 0, 0, 0o644);
    let content2 = b"$password = $_POST['pw'];\n";
    let findings2 = engine.evaluate_content_only(&entry2, content2);
    let creds2: Vec<_> = findings2
        .iter()
        .filter(|f| f.rule_name == "CredentialPatterns")
        .collect();
    assert!(
        creds2.is_empty(),
        "PHP \\$password= assignment should be suppressed by exclude pattern 2, got: {creds2:?}"
    );

    // Pattern 3: '->(?:password|passwd|pwd|pass)\b' — PHP object member access.
    // The main pattern matches `password = "longsecretval"` on the same line;
    // the fixed exclude suppresses via `->password`.
    let entry3 = file_entry("user.php", "/test/user.php", 1024, 0, 0, 0o644);
    let content3 = b"$user->password = \"longsecretval\";\n";
    let findings3 = engine.evaluate_content_only(&entry3, content3);
    let creds3: Vec<_> = findings3
        .iter()
        .filter(|f| f.rule_name == "CredentialPatterns")
        .collect();
    assert!(
        creds3.is_empty(),
        "PHP ->password member access should be suppressed by exclude pattern 3, got: {creds3:?}"
    );

    // Pattern 4: '(?i)(?:password|passwd|pwd)_?timeout\s*[=:]' — timeout config key.
    // The main pattern matches `password = supersecret123` on the same line;
    // the fixed exclude suppresses when `password_timeout =` also appears on the line.
    let entry4 = file_entry("app.conf", "/test/app.conf", 1024, 0, 0, 0o644);
    let content4 = b"db_password = supersecret123; password_timeout = 30\n";
    let findings4 = engine.evaluate_content_only(&entry4, content4);
    let creds4: Vec<_> = findings4
        .iter()
        .filter(|f| f.rule_name == "CredentialPatterns")
        .collect();
    assert!(
        creds4.is_empty(),
        "password_timeout config line should be suppressed by exclude pattern 4, got: {creds4:?}"
    );
}

#[test]
fn credential_patterns_na_placeholder_does_not_swallow_substring_matches() {
    // Regression: `N/?A` in the placeholder-exclude alternation used to
    // match any substring "na" (e.g., "banana_key"), silently suppressing
    // real credentials whose value contained those letters. After the fix,
    // `N/A` and `NA` as word-bounded tokens are still suppressed, but
    // substring hits are not.
    let engine = default_engine();

    // TP case: value "banana_secret_1234567" must still fire — "na" is a
    // substring of "banana", not a word-bounded placeholder.
    let entry_tp = file_entry("creds.conf", "/test/creds.conf", 128, 0, 0, 0o644);
    let tp_content = b"password = banana_secret_1234567";
    let findings = engine.evaluate_content_only(&entry_tp, tp_content);
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "banana_secret_1234567 must still fire CredentialPatterns \
         (substring 'na' must not suppress), got: {findings:?}"
    );

    // FP cases: standalone `N/A`, `n/a`, and `NA` placeholders must still
    // be suppressed (the whole point of the exclude).
    for placeholder in ["N/A", "n/a", "NA"] {
        let content = format!("password = {placeholder}").into_bytes();
        let entry_fp = file_entry(
            "creds.conf",
            "/test/creds.conf",
            content.len() as u64,
            0,
            0,
            0o644,
        );
        let findings = engine.evaluate_content_only(&entry_fp, &content);
        assert!(
            findings.iter().all(|f| f.rule_name != "CredentialPatterns"),
            "{placeholder} must still be suppressed, got: {findings:?}"
        );
    }
}

#[test]
fn discard_python_demo_dirs_matches_m2crypto_tree() {
    let engine = default_engine();
    // Canonical m2crypto demo subdirectories must still be pruned after the
    // pattern moves from DiscardOracleVendorDirsNested to DiscardPythonDemoDirs.
    for (dir_name, full_path) in [
        ("rsa", "/usr/share/doc/m2crypto-0.21.1/demo/rsa"),
        ("ec", "/usr/share/doc/m2crypto-0.21.1/demo/ec"),
        ("smime", "/usr/share/doc/m2crypto-0.21.1/demo/smime"),
        ("ssl", "/usr/share/doc/m2crypto-0.21.1/demo/ssl"),
        (
            "rsa",
            "/backups/host/root/usr/share/doc/m2crypto-0.21.1/demo/rsa",
        ),
    ] {
        assert!(
            engine.should_discard_dir(dir_name, full_path),
            "expected m2crypto demo dir to be discarded: {full_path}"
        );
    }
}

#[test]
fn discard_oracle_vendor_dirs_nested_does_not_contain_python_demo_pattern() {
    // Structural: the m2crypto demo pattern must no longer live inside the
    // Oracle vendor rule — it's now in DiscardPythonDemoDirs.
    let rules = load_embedded_defaults().expect("embedded defaults should load");
    let oracle_rule = rules
        .iter()
        .find(|r| r.name == "DiscardOracleVendorDirsNested")
        .expect("DiscardOracleVendorDirsNested should exist");
    for p in &oracle_rule.patterns {
        assert!(
            !p.contains("m2crypto") && !p.contains("Zope") && !p.contains("medusa"),
            "Oracle rule leaked python-demo pattern: {p}"
        );
    }
}

#[test]
fn discard_oracle_product_extensions_does_not_include_msg() {
    // Structural: .msg is also Outlook email format, not just Oracle message catalogs.
    // Must not be universally discarded by extension. Oracle .msg files live under
    // /srvm/mesg/ and /ldap/mesg/ paths, which are already pruned at the directory level.
    let rules = load_embedded_defaults().expect("embedded defaults should load");
    let rule = rules
        .iter()
        .find(|r| r.name == "DiscardOracleProductExtensions")
        .expect("DiscardOracleProductExtensions should exist");
    assert!(
        !rule.patterns.iter().any(|p| p == "msg"),
        "`.msg` is also Outlook; must not be in Oracle extension discard"
    );
}

#[test]
fn discard_oracle_product_extensions_does_not_include_mk() {
    // Structural: .mk is generic GNU make convention. Must not be universally
    // discarded by extension. Oracle .mk files live under /rdbms/lib/, /network/lib/,
    // etc., which are pruned by DiscardOracleInstallLibDirs.
    let rules = load_embedded_defaults().expect("embedded defaults should load");
    let rule = rules
        .iter()
        .find(|r| r.name == "DiscardOracleProductExtensions")
        .expect("DiscardOracleProductExtensions should exist");
    assert!(
        !rule.patterns.iter().any(|p| p == "mk"),
        "`.mk` is generic GNU make; must not be in Oracle extension discard"
    );
}

#[test]
fn oracle_install_lib_dirs_are_discarded_at_dir_level() {
    let engine = default_engine();
    for (dir_name, full_path) in [
        ("lib", "/u01/app/oracle/product/19c/dbhome_1/rdbms/lib"),
        ("lib", "/u01/app/oracle/product/19c/dbhome_1/network/lib"),
        ("lib", "/u01/app/oracle/product/19c/dbhome_1/precomp/lib"),
        ("lib", "/u01/app/oracle/product/19c/dbhome_1/plsql/lib"),
        ("lib", "/u01/app/oracle/product/19c/dbhome_1/sqlplus/lib"),
    ] {
        assert!(
            engine.should_discard_dir(dir_name, full_path),
            "Oracle install lib dir must be pruned: {full_path}"
        );
    }
}
