#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct NfsFh(Vec<u8>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsFileType {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone)]
pub struct NfsAttrs {
    pub file_type: NfsFileType,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
}

fn file_type_from_metadata(meta: &std::fs::Metadata) -> NfsFileType {
    if meta.file_type().is_file() {
        NfsFileType::Regular
    } else if meta.file_type().is_dir() {
        NfsFileType::Directory
    } else if meta.file_type().is_symlink() {
        NfsFileType::Symlink
    } else {
        NfsFileType::Other
    }
}

fn clamp_mtime(raw: i64) -> u64 {
    raw.max(0) as u64
}

impl NfsAttrs {
    pub fn is_file(&self) -> bool {
        self.file_type == NfsFileType::Regular
    }

    pub fn is_directory(&self) -> bool {
        self.file_type == NfsFileType::Directory
    }

    pub fn is_symlink(&self) -> bool {
        self.file_type == NfsFileType::Symlink
    }

    pub fn from_metadata(meta: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            file_type: file_type_from_metadata(meta),
            size: meta.len(),
            mode: meta.mode(),
            uid: meta.uid(),
            gid: meta.gid(),
            mtime: clamp_mtime(meta.mtime()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsVersion {
    V3,
    V4,
}

#[derive(Debug, Clone)]
pub struct NfsExport {
    pub path: String,
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub fh: NfsFh,
    pub attrs: NfsAttrs,
}

#[derive(Debug)]
pub struct ReadResult {
    pub data: Vec<u8>,
    pub eof: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportAccessOptions {
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Misconfiguration {
    NoRootSquash,
    InsecureExport,
    SubtreeBypass,
}

impl std::fmt::Display for Misconfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRootSquash => write!(f, "no_root_squash"),
            Self::InsecureExport => write!(f, "insecure"),
            Self::SubtreeBypass => write!(f, "subtree"),
        }
    }
}

impl NfsFh {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfs_fh_default_has_empty_bytes() {
        let fh = NfsFh::default();
        assert!(fh.as_bytes().is_empty());
    }

    #[test]
    fn nfs_fh_new_stores_data() {
        let fh = NfsFh::new(vec![1, 2, 3]);
        assert_eq!(fh.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn nfs_fh_clone_holds_same_bytes() {
        let fh = NfsFh::new(vec![10, 20, 30]);
        let cloned = fh.clone();
        assert_eq!(fh.as_bytes(), cloned.as_bytes());
    }

    #[test]
    fn nfs_attrs_file_type_regular() {
        let attrs = NfsAttrs {
            file_type: NfsFileType::Regular,
            size: 1024,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            mtime: 0,
        };
        assert!(attrs.is_file());
        assert!(!attrs.is_directory());
        assert!(!attrs.is_symlink());
    }

    #[test]
    fn nfs_attrs_file_type_directory() {
        let attrs = NfsAttrs {
            file_type: NfsFileType::Directory,
            size: 4096,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
        };
        assert!(attrs.is_directory());
        assert!(!attrs.is_file());
        assert!(!attrs.is_symlink());
    }

    #[test]
    fn nfs_attrs_file_type_symlink() {
        let attrs = NfsAttrs {
            file_type: NfsFileType::Symlink,
            size: 0,
            mode: 0o777,
            uid: 0,
            gid: 0,
            mtime: 0,
        };
        assert!(attrs.is_symlink());
        assert!(!attrs.is_file());
        assert!(!attrs.is_directory());
    }

    #[test]
    fn nfs_attrs_from_metadata() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello world").unwrap();
        tmp.flush().unwrap();

        let meta = std::fs::metadata(tmp.path()).unwrap();
        let attrs = NfsAttrs::from_metadata(&meta);

        assert!(attrs.is_file());
        assert_eq!(attrs.size, 11);
    }

    #[test]
    fn export_access_options_default() {
        let opts = ExportAccessOptions::default();
        assert!(opts.allowed_hosts.is_empty());
    }

    #[test]
    fn export_access_options_with_hosts() {
        let opts = ExportAccessOptions {
            allowed_hosts: vec!["*".into(), "10.0.0.0/24".into()],
        };
        assert_eq!(opts.allowed_hosts.len(), 2);
        assert_eq!(opts.allowed_hosts[0], "*");
        assert_eq!(opts.allowed_hosts[1], "10.0.0.0/24");
    }

    #[test]
    fn misconfiguration_display_no_root_squash() {
        let m = Misconfiguration::NoRootSquash;
        assert!(m.to_string().contains("no_root_squash"));
    }

    #[test]
    fn misconfiguration_display_insecure() {
        let m = Misconfiguration::InsecureExport;
        assert!(m.to_string().contains("insecure"));
    }

    #[test]
    fn misconfiguration_display_subtree() {
        let m = Misconfiguration::SubtreeBypass;
        assert!(m.to_string().contains("subtree"));
    }

    #[test]
    fn misconfiguration_clone_eq() {
        let m = Misconfiguration::NoRootSquash;
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn clamp_mtime_negative_becomes_zero() {
        assert_eq!(clamp_mtime(-1), 0u64);
        assert_eq!(clamp_mtime(i64::MIN), 0u64);
    }

    #[test]
    fn clamp_mtime_positive_preserved() {
        assert_eq!(clamp_mtime(0), 0u64);
        assert_eq!(clamp_mtime(1700000000), 1700000000u64);
    }
}
