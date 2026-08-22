use std::{
    fs::{DirBuilder, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use crypto_box::{PublicKey, SecretKey, aead::OsRng};

use super::address::DerpPublicKey;

#[derive(Clone)]
pub struct DerpIdentity {
    secret: SecretKey,
}

impl std::fmt::Debug for DerpIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerpIdentity")
            .field("public_key", &self.public_key())
            .finish()
    }
}

impl DerpIdentity {
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: SecretKey::from(bytes),
        }
    }

    pub fn public_key(&self) -> DerpPublicKey {
        DerpPublicKey::from_bytes(*self.secret.public_key().as_bytes())
    }

    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }

    pub(crate) fn crypto_public(key: DerpPublicKey) -> PublicKey {
        PublicKey::from(*key.as_bytes())
    }
}

pub fn load_or_create(path: &Path) -> Result<DerpIdentity> {
    if path.exists() {
        return load(path);
    }
    create_private_parent(path)?;
    let identity = DerpIdentity::generate();
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            writeln!(file, "{}", hex::encode(identity.secret.to_bytes()))?;
            file.sync_all()?;
            Ok(identity)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => load(path),
        Err(error) => Err(error).with_context(|| format!("failed creating {}", path.display())),
    }
}

pub fn load(path: &Path) -> Result<DerpIdentity> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed inspecting {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "DERP identity must be a regular file"
    );
    let mode = metadata.permissions().mode() & 0o777;
    ensure!(
        mode & 0o077 == 0,
        "DERP identity has insecure mode {mode:o}"
    );
    let encoded = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading {}", path.display()))?;
    let bytes = hex::decode(encoded.trim()).context("DERP identity must be hexadecimal")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("DERP identity must contain exactly 32 bytes"))?;
    Ok(DerpIdentity::from_bytes(bytes))
}

pub fn backup(source: &Path, destination: &Path) -> Result<()> {
    let identity = load(source)?;
    write_new(destination, identity.secret.to_bytes(), "backup")
}

pub fn restore(source: &Path, destination: &Path) -> Result<DerpIdentity> {
    if destination.exists() {
        bail!("DERP identity already exists at {}", destination.display());
    }
    let identity = load(source)?;
    write_new(destination, identity.secret.to_bytes(), "restore")?;
    Ok(identity)
}

fn write_new(path: &Path, bytes: [u8; 32], operation: &str) -> Result<()> {
    create_private_parent(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to {operation} DERP identity {}", path.display()))?;
    writeln!(file, "{}", hex::encode(bytes))?;
    file.sync_all()?;
    Ok(())
}

fn create_private_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        // DirBuilder applies this mode only to directories it creates. Never
        // mutate an existing shared parent merely because it contains a key.
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_persistent_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("derp.key");
        let first = load_or_create(&path).unwrap();
        let second = load_or_create(&path).unwrap();
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn backup_and_restore_preserve_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("identity.derp");
        let backup_path = dir.path().join("backup.derp");
        let restored_path = dir.path().join("restored/identity.derp");
        let original = load_or_create(&source).unwrap();
        backup(&source, &backup_path).unwrap();
        let restored = restore(&backup_path, &restored_path).unwrap();
        assert_eq!(original.public_key(), restored.public_key());
    }

    #[test]
    fn identity_creation_preserves_existing_parent_mode() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.path().join("derp.key");

        load_or_create(&path).unwrap();

        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
