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
        findings.iter().any(|f| f.rule_name == "CryptoPatterns"),
        "PEM with private key should relay to CryptoPatterns, got: {findings:?}"
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
    let content = b"API_KEY = AKIAIOSFODNN7EXAMPLE1";
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
fn msa_userinfo_dotfile_relays_to_credential_scan() {
    let engine = default_engine();
    let entry = file_entry(
        ".msa_userinfo",
        "/home/user/.msa_userinfo",
        256,
        1000,
        1000,
        0o644,
    );
    let content = b"password=secret123value";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        ".msa_userinfo with credentials should produce CredentialPatterns finding"
    );
}

#[test]
fn userinfo_dotfile_relays_to_credential_scan() {
    let engine = default_engine();
    let entry = file_entry(".userinfo", "/data/.userinfo", 256, 1000, 1000, 0o644);
    let content = b"api_key=AKIAIOSFODNN7EXAMPLE1";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        !findings.is_empty(),
        ".userinfo with credentials should produce findings"
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
    let content = b"# password = VPN_Adm1n_2024!";
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
    let content = b"access_key = \"AKIAIOSFODNN7EXAMPLE\"";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CloudKeyPatterns"),
        "Terraform .tf with AWS key should relay to CloudKeyPatterns, got: {findings:?}"
    );
}

#[test]
fn sendgrid_token_matches() {
    let engine = default_engine();
    let entry = file_entry("config.json", "/data/config.json", 320, 1000, 1000, 0o644);
    let content = b"\"key\": \"SG.f4k3S3ndGr1dK3yF0rNFS4ud1t\"";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "SendGrid key SG. should match TokenPatterns, got: {findings:?}"
    );
}

#[test]
fn stripe_test_key_matches() {
    let engine = default_engine();
    let entry = file_entry("config.json", "/data/config.json", 320, 1000, 1000, 0o644);
    let content = b"\"key\": \"sk_test_f4k3Str1p3S3cr3tK3yL4bTesting1\"";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CloudKeyPatterns"),
        "Stripe test key sk_test_ should match CloudKeyPatterns, got: {findings:?}"
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
    let content = b"//registry.npmjs.org/:_authToken=secret_token_value_here_1234";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        !findings.is_empty(),
        ".npmrc with auth token should produce findings, got: {findings:?}"
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
    let content = b"MY_SECRET=SuperSecretVal1ab";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CredentialPatterns"),
        "secret= assignment should match CredentialPatterns, got: {findings:?}"
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
    let content = b"Authorization: Basic dXNlcjpwYXNzd29yZA==";
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
fn npm_token_pattern_matches() {
    let engine = default_engine();
    let entry = file_entry(".npmrc", "/home/user/.npmrc", 256, 1000, 1000, 0o644);
    let content = b"_authToken=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "npm token should match TokenPatterns, got: {findings:?}"
    );
}

#[test]
fn pypi_token_matches() {
    let engine = default_engine();
    let entry = file_entry(".pypirc", "/home/user/.pypirc", 256, 1000, 1000, 0o644);
    let content = b"password = pypi-AgEIcHlwaS5vcmcABCDEFGH";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "PyPI token should match TokenPatterns, got: {findings:?}"
    );
}

#[test]
fn openai_key_pattern_matches() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content = b"OPENAI_API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "OpenAI key should match TokenPatterns, got: {findings:?}"
    );
}

#[test]
fn anthropic_key_pattern_matches() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content = b"ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefgh";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "Anthropic key should match TokenPatterns, got: {findings:?}"
    );
}

#[test]
fn huggingface_token_matches() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content = b"HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "HuggingFace token should match TokenPatterns, got: {findings:?}"
    );
}

#[test]
fn vault_service_token_matches() {
    let engine = default_engine();
    let entry = file_entry("vault.conf", "/data/vault.conf", 256, 1000, 1000, 0o644);
    let content = b"token = \"hvs.CAESIABCDEFGHIJKLMNOP1234\"";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "Vault service token should match TokenPatterns, got: {findings:?}"
    );
}

#[test]
fn gcp_api_key_matches() {
    let engine = default_engine();
    let entry = file_entry("config.json", "/data/config.json", 256, 1000, 1000, 0o644);
    let content = b"\"api_key\": \"AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567\"";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CloudKeyPatterns"),
        "GCP API key should match CloudKeyPatterns, got: {findings:?}"
    );
}

#[test]
fn digitalocean_token_matches() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content =
        b"DO_TOKEN=dop_v1_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "CloudKeyPatterns"),
        "DigitalOcean token should match CloudKeyPatterns, got: {findings:?}"
    );
}

#[test]
fn shopify_token_matches() {
    let engine = default_engine();
    let entry = file_entry(".env", "/data/.env", 256, 1000, 1000, 0o644);
    let content = b"SHOPIFY_TOKEN=shpat_abcdef0123456789abcdef0123456789";
    let findings = engine.evaluate_file(&entry, Some(content));
    assert!(
        findings.iter().any(|f| f.rule_name == "TokenPatterns"),
        "Shopify token should match TokenPatterns, got: {findings:?}"
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
