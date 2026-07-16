//! Sample downloading — fetch raw malware from capable sources to disk.
//!
//! Unlike enrichment/collection (which produce data), this writes files. Each
//! hash is offered to every [`Operation::Download`]-capable source in turn; the
//! first that has it wins. Samples land as password-protected ZIPs so live
//! malware never sits unpacked on disk; `--extract` unpacks on demand with the
//! well-known abuse.ch password.

use crate::sources::{Operation, ThreatSource};
use crate::util::RateLimiter;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// The password abuse.ch protects sample ZIPs with.
pub const ZIP_PASSWORD: &[u8] = b"infected";

/// What became of one requested hash.
pub struct DownloadReport {
    pub sha256: String,
    pub outcome: Outcome,
}

pub enum Outcome {
    /// Saved to `archive`; `extracted` is set when `--extract` unpacked it.
    Saved {
        source: String,
        archive: PathBuf,
        extracted: Option<PathBuf>,
    },
    /// No capable source had the sample.
    NotFound,
    /// A source or the filesystem errored (message kept for the user).
    Failed(String),
}

/// Download each hash into `dir`, optionally extracting the binary.
pub async fn download(
    sources: &[Box<dyn ThreatSource>],
    hashes: &[String],
    dir: &Path,
    extract: bool,
    limiter: &RateLimiter,
) -> Vec<DownloadReport> {
    let mut reports = Vec::with_capacity(hashes.len());
    for hash in hashes {
        reports.push(DownloadReport {
            sha256: hash.clone(),
            outcome: fetch_one(sources, hash, dir, extract, limiter).await,
        });
    }
    reports
}

async fn fetch_one(
    sources: &[Box<dyn ThreatSource>],
    hash: &str,
    dir: &Path,
    extract: bool,
    limiter: &RateLimiter,
) -> Outcome {
    for source in sources
        .iter()
        .filter(|s| s.capabilities().supports(Operation::Download))
    {
        limiter.acquire(source.name()).await;
        let sample = match source.fetch_sample(hash).await {
            Ok(Some(s)) => s,
            Ok(None) => continue, // this source doesn't have it — try the next
            Err(e) => return Outcome::Failed(format!("{}: {e:#}", source.name())),
        };

        let ext = if sample.archived { "zip" } else { "bin" };
        let archive = dir.join(format!("{hash}.{ext}"));
        if let Err(e) =
            std::fs::create_dir_all(dir).and_then(|_| write_new(&archive, &sample.bytes))
        {
            return Outcome::Failed(format!("writing {}: {e}", archive.display()));
        }

        let extracted = if extract && sample.archived {
            match extract_zip(&archive, dir) {
                Ok(path) => Some(path),
                Err(e) => return Outcome::Failed(format!("extracting {hash}: {e}")),
            }
        } else {
            None
        };
        return Outcome::Saved {
            source: sample.source.to_string(),
            archive,
            extracted,
        };
    }
    Outcome::NotFound
}

/// Write bytes to a path, refusing to clobber an existing file.
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .or_else(|e| match e.kind() {
            // Re-downloading the same sample is a no-op, not an error.
            std::io::ErrorKind::AlreadyExists => std::fs::File::create(path),
            _ => Err(e),
        })?;
    f.write_all(bytes)
}

/// Unpack the (single) entry of a password-protected ZIP into `dir`, returning
/// the extracted file's path. The inner filename is taken from the archive but
/// stripped to its base name so a malicious entry can't escape `dir`.
fn extract_zip(archive: &Path, dir: &Path) -> anyhow::Result<PathBuf> {
    let file = std::fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(file)?;
    if zip.is_empty() {
        anyhow::bail!("archive is empty");
    }
    let mut entry = zip.by_index_decrypt(0, ZIP_PASSWORD)?;

    let inner = entry
        .enclosed_name()
        .and_then(|p| p.file_name().map(|n| n.to_os_string()))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| {
            // Fall back to the archive stem when the entry has no usable name.
            archive
                .file_stem()
                .unwrap_or_else(|| std::ffi::OsStr::new("sample"))
                .to_os_string()
        });
    let out_path = dir.join(inner);

    let mut out = std::fs::File::create(&out_path)?;
    let mut buf = [0u8; 8192];
    loop {
        let n = entry.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
    }
    Ok(out_path)
}
