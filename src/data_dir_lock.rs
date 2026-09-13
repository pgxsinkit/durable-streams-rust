//! Process-lifetime ownership of a Durable Streams data directory.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// A non-blocking advisory lock held for as long as the server owns `data_dir`.
/// Keeping the file open is intentional: closing it releases the OS lock.
pub struct DataDirLock {
    _file: File,
}

impl DataDirLock {
    pub fn acquire(data_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join(".durable-streams.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        #[cfg(unix)]
        {
            // SAFETY: `file` remains open in this value until process shutdown.
            let rc = unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&file),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            };
            if rc != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!("data directory is already locked: {}", path.display()),
                ));
            }
        }

        #[cfg(not(unix))]
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "exclusive data-directory locking requires Unix",
            ));
        }

        Ok(Self { _file: file })
    }
}
