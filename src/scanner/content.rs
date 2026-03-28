use std::io::Read;
use std::path::Path;

use crate::nfs::{NfsFh, NfsOps};

use super::error::ScannerError;

pub const DEFAULT_CHUNK_SIZE: u32 = 65536;

/// Check if data is likely binary by looking for null bytes anywhere in the scan buffer.
pub fn is_likely_binary(data: &[u8]) -> bool {
    data.contains(&0)
}

/// Read file content via chunked NFS READ calls, capped at `max_scan_size`.
pub async fn read_for_scan(
    client: &mut dyn NfsOps,
    fh: &NfsFh,
    max_scan_size: u64,
    file_size: u64,
) -> Result<Vec<u8>, ScannerError> {
    let to_read = file_size.min(max_scan_size);
    let mut buf = Vec::with_capacity(to_read as usize);
    let mut offset = 0u64;

    while offset < to_read {
        let chunk_size = (to_read - offset).min(DEFAULT_CHUNK_SIZE as u64) as u32;
        let result = client.read(fh, offset, chunk_size).await?;
        if result.data.is_empty() {
            break;
        }
        buf.extend_from_slice(&result.data);
        offset += result.data.len() as u64;
        if result.eof {
            break;
        }
    }

    Ok(buf)
}

/// Read file content from the local filesystem, capped at `max_scan_size`.
pub fn read_local_for_scan(path: &Path, max_scan_size: u64) -> Result<Vec<u8>, ScannerError> {
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(max_scan_size).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::{NfsError, ReadResult};

    #[test]
    fn binary_detection_null_byte_at_start() {
        assert!(is_likely_binary(&[0, 65, 66, 67]));
    }

    #[test]
    fn binary_detection_null_byte_in_middle() {
        assert!(is_likely_binary(b"hello\0world"));
    }

    #[test]
    fn binary_detection_null_byte_at_8191() {
        let mut data = vec![0x41u8; 8192];
        data[8191] = 0x00;
        assert!(is_likely_binary(&data));
    }

    #[test]
    fn binary_detection_null_byte_beyond_8192() {
        let mut data = vec![0x41u8; 16384];
        data[8192] = 0x00;
        assert!(is_likely_binary(&data));
    }

    #[test]
    fn binary_detection_pure_text() {
        assert!(!is_likely_binary(b"This is plain text\nwith newlines\n"));
    }

    #[test]
    fn binary_detection_empty_data() {
        assert!(!is_likely_binary(b""));
    }

    #[test]
    fn binary_detection_short_data() {
        assert!(!is_likely_binary(b"hi"));
    }

    #[test]
    fn binary_detection_checks_full_scan_buffer() {
        let mut data = vec![0x41u8; 16384];
        data[10000] = 0x00;
        assert!(
            is_likely_binary(&data),
            "null bytes anywhere in the scan buffer should trigger binary detection"
        );
    }

    #[tokio::test]
    async fn read_for_scan_single_chunk() {
        let mut mock = MockNfsOps::new();
        let fh = NfsFh::default();

        mock.expect_read().times(1).returning(|_, _, _| {
            Ok(ReadResult {
                data: vec![0x42; 1000],
                eof: true,
            })
        });

        let result = read_for_scan(&mut mock, &fh, 1_048_576, 1000)
            .await
            .unwrap();
        assert_eq!(result.len(), 1000);
    }

    #[tokio::test]
    async fn read_for_scan_multi_chunk_assembly() {
        let mut mock = MockNfsOps::new();
        let fh = NfsFh::default();

        let mut call_count = 0u32;
        mock.expect_read().times(2).returning(move |_, _, _| {
            call_count += 1;
            if call_count == 1 {
                Ok(ReadResult {
                    data: vec![0xAA; 65536],
                    eof: false,
                })
            } else {
                Ok(ReadResult {
                    data: vec![0xBB; 30000],
                    eof: true,
                })
            }
        });

        let result = read_for_scan(&mut mock, &fh, 1_048_576, 95536)
            .await
            .unwrap();
        assert_eq!(result.len(), 95536);
        assert!(result[..65536].iter().all(|&b| b == 0xAA));
        assert!(result[65536..].iter().all(|&b| b == 0xBB));
    }

    #[tokio::test]
    async fn read_for_scan_early_eof() {
        let mut mock = MockNfsOps::new();
        let fh = NfsFh::default();

        mock.expect_read().times(1).returning(|_, _, _| {
            Ok(ReadResult {
                data: vec![0x42; 100],
                eof: true,
            })
        });

        let result = read_for_scan(&mut mock, &fh, 1_048_576, 5000)
            .await
            .unwrap();
        assert_eq!(result.len(), 100);
    }

    #[tokio::test]
    async fn read_for_scan_max_scan_size_caps_read() {
        let mut mock = MockNfsOps::new();
        let fh = NfsFh::default();

        mock.expect_read().times(1..=2).returning(|_, _, count| {
            let size = count as usize;
            Ok(ReadResult {
                data: vec![0x42; size],
                eof: false,
            })
        });

        let result = read_for_scan(&mut mock, &fh, 100_000, 2_000_000)
            .await
            .unwrap();
        assert!(result.len() <= 100_000);
    }

    #[tokio::test]
    async fn read_for_scan_empty_data_stops() {
        let mut mock = MockNfsOps::new();
        let fh = NfsFh::default();

        mock.expect_read().times(1).returning(|_, _, _| {
            Ok(ReadResult {
                data: vec![],
                eof: false,
            })
        });

        let result = read_for_scan(&mut mock, &fh, 1_048_576, 5000)
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn read_for_scan_nfs_error_propagates() {
        let mut mock = MockNfsOps::new();
        let fh = NfsFh::default();

        mock.expect_read().times(1).returning(|_, _, _| {
            Err(Box::new(NfsError::PermissionDenied) as Box<dyn std::error::Error + Send + Sync>)
        });

        let err = read_for_scan(&mut mock, &fh, 1_048_576, 5000)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ScannerError::Nfs(NfsError::PermissionDenied)),
            "expected Nfs(PermissionDenied), got: {err:?}"
        );
    }

    #[test]
    fn local_read_full_file() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let content = vec![0x42u8; 500];
        tmp.write_all(&content).unwrap();
        tmp.flush().unwrap();

        let result = read_local_for_scan(tmp.path(), 1_048_576).unwrap();
        assert_eq!(result.len(), 500);
        assert_eq!(result, content);
    }

    #[test]
    fn local_read_capped_by_max_scan_size() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&vec![0x42u8; 10000]).unwrap();
        tmp.flush().unwrap();

        let result = read_local_for_scan(tmp.path(), 5000).unwrap();
        assert_eq!(result.len(), 5000);
    }

    #[test]
    fn local_read_file_not_found() {
        let result = read_local_for_scan(Path::new("/nonexistent/file.txt"), 1_048_576);
        assert!(result.is_err());
    }
}
