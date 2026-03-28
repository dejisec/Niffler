use ssh_key::PrivateKey;
use ssh_key::private::KeypairData;

#[derive(Debug)]
pub struct KeyFinding {
    pub key_type: String,
    pub is_encrypted: bool,
    pub bits: Option<usize>,
}

/// Check if data contains an OpenSSH private key.
/// Returns key metadata if found, None otherwise.
pub fn check_ssh_key(data: &[u8]) -> Option<KeyFinding> {
    let text = std::str::from_utf8(data).ok()?;
    let key = PrivateKey::from_openssh(text).ok()?;

    let bits = match key.key_data() {
        KeypairData::Ed25519(_) => Some(256),
        _ => None,
    };

    Some(KeyFinding {
        key_type: key.algorithm().to_string(),
        is_encrypted: key.is_encrypted(),
        bits,
    })
}

/// Check if data contains an X.509 private key (PEM format) or DER certificate.
pub fn check_x509_for_private_key(data: &[u8]) -> Option<KeyFinding> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.contains("-----BEGIN")
        && text.contains("PRIVATE KEY")
    {
        let is_encrypted = text.contains("ENCRYPTED");
        return Some(KeyFinding {
            key_type: "X.509 Private Key".into(),
            is_encrypted,
            bits: None,
        });
    }

    use x509_parser::prelude::FromDer;
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(data) {
        return Some(KeyFinding {
            key_type: format!("X.509 Certificate ({})", cert.subject),
            is_encrypted: false,
            bits: None,
        });
    }

    None
}

/// Check if data contains a PGP private key block (pure string matching, no pgp crate).
pub fn check_pgp_key(data: &[u8]) -> Option<KeyFinding> {
    let text = std::str::from_utf8(data).ok()?;
    if text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        return Some(KeyFinding {
            key_type: "PGP Private Key".into(),
            is_encrypted: text.contains("ENCRYPTED"),
            bits: None,
        });
    }
    None
}

/// Try all key material inspectors in priority order: SSH → X.509 → PGP.
pub fn inspect_key_material(data: &[u8]) -> Option<KeyFinding> {
    check_ssh_key(data)
        .or_else(|| check_x509_for_private_key(data))
        .or_else(|| check_pgp_key(data))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const UNENCRYPTED_ED25519_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
";

    pub(crate) const ENCRYPTED_ED25519_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBKH96ujW
umB6/WnTNPjTeaAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN
796jTiQfZfG1KaT0PtFDJ/XFSqtiAAAAoFzvbvyFMhAiwBOXF0mhUUacPUCMZXivG2up2c
hEnAw1b6BLRPyWbY5cC2n9ggD4ivJ1zSts6sBgjyiXQAReyrP35myYvT/OIB/NpwZM/xIJ
N7MHSUzlkX4adBrga3f7GS4uv4ChOoxC4XsE5HsxtGsq1X8jzqLlZTmOcxkcEneYQexrUc
bQP0o+gL5aKK8cQgiIlXeDbRjqhc4+h4EF6lY=
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn ssh_key_unencrypted_detected() {
        let result = check_ssh_key(UNENCRYPTED_ED25519_KEY.as_bytes());
        let finding = result.expect("should detect unencrypted key");
        assert!(!finding.is_encrypted);
        assert!(!finding.key_type.is_empty());
        assert!(finding.key_type.contains("ed25519"));
        assert_eq!(finding.bits, Some(256));
    }

    #[test]
    fn ssh_key_encrypted_detected() {
        let result = check_ssh_key(ENCRYPTED_ED25519_KEY.as_bytes());
        let finding = result.expect("should detect encrypted key");
        assert!(finding.is_encrypted);
        assert!(finding.key_type.contains("ed25519"));
    }

    #[test]
    fn ssh_key_invalid_data_returns_none() {
        assert!(check_ssh_key(b"This is not an SSH key").is_none());
    }

    #[test]
    fn ssh_key_empty_data_returns_none() {
        assert!(check_ssh_key(b"").is_none());
    }

    #[test]
    fn ssh_key_public_key_returns_none() {
        let pubkey = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILtMSEnZH0GU89zP user@host";
        assert!(check_ssh_key(pubkey).is_none());
    }

    #[test]
    fn x509_pem_private_key_detected() {
        let data = b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n-----END PRIVATE KEY-----\n";
        let finding = check_x509_for_private_key(data).expect("should detect private key");
        assert!(!finding.is_encrypted);
        assert!(finding.key_type.contains("Private Key"));
    }

    #[test]
    fn x509_pem_encrypted_private_key_detected() {
        let data =
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFH...\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let finding =
            check_x509_for_private_key(data).expect("should detect encrypted private key");
        assert!(finding.is_encrypted);
    }

    #[test]
    fn x509_pem_rsa_private_key_detected() {
        let data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n";
        let finding = check_x509_for_private_key(data).expect("should detect RSA private key");
        assert!(!finding.is_encrypted);
        assert!(finding.key_type.contains("Private Key"));
    }

    #[test]
    fn x509_pem_ec_private_key_detected() {
        let data = b"-----BEGIN EC PRIVATE KEY-----\nMHQCAQ...\n-----END EC PRIVATE KEY-----\n";
        let finding = check_x509_for_private_key(data).expect("should detect EC private key");
        assert!(finding.key_type.contains("Private Key"));
    }

    #[test]
    fn x509_plain_text_returns_none() {
        assert!(check_x509_for_private_key(b"Just some random text").is_none());
    }

    #[test]
    fn x509_pem_certificate_only() {
        let data = b"-----BEGIN CERTIFICATE-----\nMIIDXTCCA...\n-----END CERTIFICATE-----\n";
        assert!(
            check_x509_for_private_key(data).is_none(),
            "cert-only should return None — classifier handles via rules"
        );
    }

    #[test]
    fn pgp_private_key_detected() {
        let data = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----\n";
        let finding = check_pgp_key(data).expect("should detect PGP private key");
        assert!(finding.key_type.contains("PGP"));
    }

    #[test]
    fn pgp_public_key_not_detected() {
        let data = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v2\n\nmQENBF...\n-----END PGP PUBLIC KEY BLOCK-----\n";
        assert!(check_pgp_key(data).is_none());
    }

    #[test]
    fn pgp_no_match_on_plain_text() {
        assert!(check_pgp_key(b"Not a PGP key").is_none());
    }

    #[test]
    fn pgp_encrypted_detection() {
        let data = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\nENCRYPTED\n\nlQOYBF...\n-----END PGP PRIVATE KEY BLOCK-----\n";
        let finding = check_pgp_key(data).expect("should detect encrypted PGP key");
        assert!(finding.is_encrypted);
    }
}
