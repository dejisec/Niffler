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
