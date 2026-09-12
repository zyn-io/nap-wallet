//! Recoverable multi-file installation. A durable journal means an interrupted
//! install rolls back on startup, before either signing identity is opened.
//! Backup directories intentionally remain: they contain recovery secrets.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use serde_json::{json, Value};

const JOURNAL: &str = "nap-restore-pending.json";

fn sync_dir(path: &Path) -> Result<(), String> {
    File::open(path).and_then(|f| f.sync_all()).map_err(|e| format!("sync restore directory: {e}"))
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| format!("create restore file: {e}"))?;
    file.write_all(bytes).and_then(|_| file.sync_all()).map_err(|e| format!("sync restore file: {e}"))
}

pub(crate) fn export_file(dir: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    let path = dir.join(format!("nap-wallet-backup-{:016x}.json", rand::random::<u64>()));
    private_file(&path, bytes)?;
    sync_dir(dir)?;
    Ok(path)
}

fn install(path: &Path, bytes: Option<&[u8]>) -> Result<(), String> {
    let parent = path.parent().ok_or("restore target has no parent")?;
    if let Some(bytes) = bytes {
        let temp = parent.join(format!(".nap-install-{:016x}", rand::random::<u64>()));
        private_file(&temp, bytes)?;
        fs::rename(&temp, path).map_err(|e| format!("install restore file: {e}"))?;
    } else {
        match fs::remove_file(path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(format!("clear restore file: {e}")),
        }
    }
    sync_dir(parent)
}

pub(crate) fn pending(dir: &Path) -> bool { dir.join(JOURNAL).exists() }

pub(crate) fn recover(dir: &Path) -> Result<(), String> {
    let journal = dir.join(JOURNAL);
    let bytes = match fs::read(&journal) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("read restore journal: {e}")),
    };
    let entries: Vec<Value> = serde_json::from_slice(&bytes).map_err(|e| format!("invalid restore journal: {e}"))?;
    for entry in entries {
        let target = Path::new(entry["target"].as_str().ok_or("invalid restore target")?);
        let old = match entry["backup"].as_str() {
            Some(path) => Some(fs::read(path).map_err(|e| format!("read restore recovery copy: {e}"))?),
            None => None,
        };
        install(target, old.as_deref())?;
    }
    fs::remove_file(journal).map_err(|e| format!("clear restore journal: {e}"))?;
    sync_dir(dir)
}

pub(crate) fn replace(dir: &Path, files: &[(PathBuf, Option<Vec<u8>>)]) -> Result<PathBuf, String> {
    if pending(dir) { return Err("unfinished restore; restart Nap to recover before continuing".into()); }
    let backup = dir.join(format!("restore-backup-{:016x}", rand::random::<u64>()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)] {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&backup).map_err(|e| format!("create recovery directory: {e}"))?;
    let mut entries = Vec::new();
    for (i, (target, _)) in files.iter().enumerate() {
        if target.is_symlink() { return Err("refusing to replace a symlink during restore".into()); }
        let old = match fs::read(target) {
            Ok(bytes) => {
                let path = backup.join(i.to_string());
                private_file(&path, &bytes)?;
                Some(path)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("read current recovery material: {e}")),
        };
        entries.push(json!({ "target": target, "backup": old }));
    }
    let journal_bytes = serde_json::to_vec(&entries).map_err(|e| e.to_string())?;
    private_file(&backup.join("index.json"), &journal_bytes)?;
    sync_dir(&backup)?;
    private_file(&dir.join(JOURNAL), &journal_bytes)?;
    sync_dir(dir)?;
    let result = (|| {
        for (target, bytes) in files { install(target, bytes.as_deref())?; }
        fs::remove_file(dir.join(JOURNAL)).map_err(|e| format!("commit restore: {e}"))?;
        sync_dir(dir)
    })();
    if let Err(error) = result {
        if !pending(dir) { private_file(&dir.join(JOURNAL), &journal_bytes)?; sync_dir(dir)?; }
        recover(dir).map_err(|rollback| format!("{error}; rollback failed: {rollback}; restart required"))?;
        return Err(error);
    }
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!("nap-restore-test-{:016x}", rand::random::<u64>()));
        fs::create_dir(&path).unwrap(); path
    }
    #[test]
    fn replace_retains_both_original_keys() {
        let dir = directory(); let a = dir.join("wallet"); let b = dir.join("zyn.key");
        private_file(&a, b"old-wallet").unwrap(); private_file(&b, b"old-zyn").unwrap();
        let backup = replace(&dir, &[(a.clone(), Some(b"new-wallet".to_vec())), (b.clone(), Some(b"new-zyn".to_vec()))]).unwrap();
        assert_eq!(fs::read(a).unwrap(), b"new-wallet"); assert_eq!(fs::read(b).unwrap(), b"new-zyn");
        assert_eq!(fs::read(backup.join("0")).unwrap(), b"old-wallet");
        assert_eq!(fs::read(backup.join("1")).unwrap(), b"old-zyn"); assert!(!pending(&dir));
    }
    #[test]
    fn failed_install_rolls_back_already_replaced_key() {
        let dir = directory(); let a = dir.join("wallet"); let b = dir.join("absent/zyn.key");
        private_file(&a, b"old-wallet").unwrap();
        assert!(replace(&dir, &[(a.clone(), Some(b"new-wallet".to_vec())), (b, Some(b"new-zyn".to_vec()))]).is_err());
        // Recovery may require repairing the missing parent; the journal must
        // remain until every target can be restored, never silently committed.
        assert_eq!(fs::read(&a).unwrap(), b"old-wallet");
        fs::create_dir(dir.join("absent")).unwrap(); recover(&dir).unwrap(); assert!(!pending(&dir));
    }
    #[test]
    fn interrupted_install_is_recovered_idempotently() {
        let dir = directory(); let a = dir.join("wallet"); let saved = dir.join("saved");
        private_file(&a, b"partial-new").unwrap(); private_file(&saved, b"old-wallet").unwrap();
        private_file(&dir.join(JOURNAL), &serde_json::to_vec(&json!([{ "target": a, "backup": saved }])).unwrap()).unwrap();
        recover(&dir).unwrap(); recover(&dir).unwrap(); assert_eq!(fs::read(a).unwrap(), b"old-wallet");
    }

    #[test]
    fn explicit_export_is_private_and_never_overwrites() {
        let dir = directory();
        let first = export_file(&dir, b"recovery-secret").unwrap();
        let second = export_file(&dir, b"second-backup").unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read(&first).unwrap(), b"recovery-secret");
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(first).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
