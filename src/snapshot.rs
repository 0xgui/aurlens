use crate::model::{Change, Limits, PackageFile, Snapshot};
use rustix::fs::{Mode, OFlags, open, openat};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub struct CaptureError {
    pub code: &'static str,
    pub path: Option<String>,
    pub message: &'static str,
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{}: {} ({path})", self.code, self.message),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for CaptureError {}

fn error(code: &'static str, path: Option<&str>, message: &'static str) -> CaptureError {
    CaptureError {
        code,
        path: path.map(str::to_owned),
        message,
    }
}

fn io_error(path: Option<&str>) -> CaptureError {
    error(
        "filesystem_error",
        path,
        "Cannot inspect package filesystem entry",
    )
}

fn changed(path: Option<&str>) -> CaptureError {
    error(
        "snapshot_changed",
        path,
        "Package filesystem changed during review",
    )
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.chars().any(char::is_control)
}

fn pin_at(parent: &File, name: &str, relative: Option<&str>) -> Result<File, CaptureError> {
    openat(
        parent,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| io_error(relative))
}

fn metadata(file: &File, path: Option<&str>) -> Result<Metadata, CaptureError> {
    file.metadata().map_err(|_| io_error(path))
}

fn identity(meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

fn stable(before: &Metadata, after: &Metadata) -> bool {
    identity(before) == identity(after)
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.size() == after.size()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

struct Root {
    file: File,
    ancestry: Vec<(u64, u64)>,
}

fn open_root(path: &Path) -> Result<Root, CaptureError> {
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(error(
            "unsafe_path",
            None,
            "Parent path components are unsupported",
        ));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| io_error(None))?
            .join(path)
    };
    let mut file = File::from(
        open(
            "/",
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| io_error(None))?,
    );
    let mut ancestry = vec![identity(&metadata(&file, None)?)];
    for component in absolute.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name
                .to_str()
                .filter(|name| safe_name(name))
                .ok_or_else(|| error("unsafe_path", None, "Unsupported package path name"))?,
            _ => {
                return Err(error(
                    "unsafe_path",
                    None,
                    "Unsupported package path component",
                ));
            }
        };
        file = pin_at(&file, name, None)?;
        let stat = metadata(&file, None)?;
        if stat.file_type().is_symlink() {
            return Err(error(
                "symlink",
                None,
                "Package root and ancestors must not be symlinks",
            ));
        }
        if !stat.is_dir() {
            return Err(error(
                "root_not_directory",
                None,
                "Package root and ancestors must be directories",
            ));
        }
        ancestry.push(identity(&stat));
    }
    Ok(Root { file, ancestry })
}

fn proc_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

struct Collector<'a> {
    limits: &'a Limits,
    files: Vec<PackageFile>,
    directories: Vec<(String, u32)>,
    identities: Vec<(String, u64, u64)>,
    excluded: Vec<String>,
    entries: usize,
    bytes: usize,
}

impl Collector<'_> {
    fn walk(&mut self, directory: &File, relative: &str, depth: usize) -> Result<(), CaptureError> {
        let before = metadata(directory, Some(relative))?;
        self.directories
            .push((relative.to_owned(), before.mode() & 0o7777));
        let entries = fs::read_dir(proc_path(directory)).map_err(|_| io_error(Some(relative)))?;
        for entry in entries {
            let entry = entry.map_err(|_| io_error(Some(relative)))?;
            self.entries = self.entries.checked_add(1).ok_or_else(|| {
                error(
                    "entry_limit",
                    Some(relative),
                    "Package entry limit exceeded",
                )
            })?;
            if self.entries > self.limits.max_entries {
                return Err(error(
                    "entry_limit",
                    Some(relative),
                    "Package entry limit exceeded",
                ));
            }
            let name = entry.file_name();
            let name = name
                .to_str()
                .filter(|name| safe_name(name))
                .ok_or_else(|| {
                    error(
                        "unsafe_name",
                        Some(relative),
                        "Unsupported filesystem entry name",
                    )
                })?;
            let child_path = if relative == "." {
                name.to_owned()
            } else {
                format!("{relative}/{name}")
            };
            if depth >= self.limits.max_depth {
                return Err(error(
                    "depth_limit",
                    Some(&child_path),
                    "Package depth limit exceeded",
                ));
            }
            // O_PATH cannot read a device or block on a FIFO, even if the name races.
            let child = pin_at(directory, name, Some(&child_path))?;
            let stat = metadata(&child, Some(&child_path))?;
            if stat.file_type().is_symlink() {
                return Err(error(
                    "symlink",
                    Some(&child_path),
                    "Symbolic links are unsupported",
                ));
            }
            if !stat.is_dir() && !stat.is_file() {
                return Err(error(
                    "special_file",
                    Some(&child_path),
                    "Special filesystem entries are unsupported",
                ));
            }
            self.identities
                .push((child_path.clone(), stat.dev(), stat.ino()));
            if relative == "." && name == ".git" && stat.is_dir() {
                self.excluded.push(child_path.clone());
            } else if stat.is_dir() {
                self.walk(&child, &child_path, depth + 1)?;
            } else {
                self.read_file(&child, &stat, &child_path)?;
            }
            let current = pin_at(directory, name, Some(&child_path))?;
            let after = metadata(&current, Some(&child_path))?;
            let unchanged = if relative == "." && name == ".git" && stat.is_dir() {
                identity(&stat) == identity(&after) && after.is_dir()
            } else {
                stable(&stat, &after)
            };
            if !unchanged {
                return Err(changed(Some(&child_path)));
            }
        }
        if !stable(&before, &metadata(directory, Some(relative))?) {
            return Err(changed(Some(relative)));
        }
        Ok(())
    }

    fn read_file(
        &mut self,
        pinned: &File,
        before: &Metadata,
        path: &str,
    ) -> Result<(), CaptureError> {
        if before.nlink() != 1 {
            return Err(error(
                "hardlink",
                Some(path),
                "Multiply linked regular files are unsupported",
            ));
        }
        if self.files.len() >= self.limits.max_files {
            return Err(error(
                "file_limit",
                Some(path),
                "Package file limit exceeded",
            ));
        }
        let remaining = self.limits.max_total_bytes.saturating_sub(self.bytes);
        let cap = self.limits.max_file_bytes.min(remaining);
        if before.size() > self.limits.max_file_bytes as u64 {
            return Err(error(
                "file_byte_limit",
                Some(path),
                "Package file byte limit exceeded",
            ));
        }
        if before.size() > remaining as u64 {
            return Err(error(
                "total_byte_limit",
                Some(path),
                "Package total byte limit exceeded",
            ));
        }
        // Open the already pinned, verified regular inode through procfs, never
        // the mutable checkout name. No unverified special inode gets IO-opened.
        let file = File::from(
            open(
                proc_path(pinned),
                OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| io_error(Some(path)))?,
        );
        if !stable(before, &metadata(&file, Some(path))?) {
            return Err(changed(Some(path)));
        }
        let mut bytes = Vec::new();
        (&file)
            .take((cap as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| io_error(Some(path)))?;
        if bytes.len() > cap {
            let code = if cap == self.limits.max_file_bytes {
                "file_byte_limit"
            } else {
                "total_byte_limit"
            };
            return Err(error(code, Some(path), "Package byte limit exceeded"));
        }
        if !stable(before, &metadata(&file, Some(path))?) || bytes.len() as u64 != before.size() {
            return Err(changed(Some(path)));
        }
        let text = String::from_utf8(bytes).map_err(|_| {
            error(
                "unsupported_text",
                Some(path),
                "File must contain UTF-8 text",
            )
        })?;
        if text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
        {
            return Err(error(
                "unsupported_text",
                Some(path),
                "Binary or control-character content is unsupported",
            ));
        }
        self.bytes += text.len();
        let sha256 = format!("{:x}", Sha256::digest(text.as_bytes()));
        self.files.push(PackageFile {
            path: path.to_owned(),
            mode: before.mode() & 0o7777,
            text,
            sha256,
        });
        Ok(())
    }
}

fn field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn digest(files: &[PackageFile], directories: &[(String, u32)]) -> String {
    let mut records: Vec<(&str, u8, u32, &[u8])> = files
        .iter()
        .map(|file| (file.path.as_str(), b'f', file.mode, file.text.as_bytes()))
        .collect();
    records.extend(
        directories
            .iter()
            .map(|(path, mode)| (path.as_str(), b'd', *mode, &[][..])),
    );
    records.sort_by(|a, b| a.0.cmp(b.0));
    let mut hash = Sha256::new();
    field(&mut hash, b"AURLens snapshot v1");
    for (path, kind, mode, bytes) in records {
        field(&mut hash, &[kind]);
        field(&mut hash, path.as_bytes());
        field(&mut hash, &mode.to_be_bytes());
        field(&mut hash, bytes);
    }
    format!("{:x}", hash.finalize())
}

pub fn capture(path: &Path, limits: &Limits) -> Result<Snapshot, CaptureError> {
    let root = open_root(path)?;
    let stat = metadata(&root.file, None)?;
    let mut collector = Collector {
        limits,
        files: Vec::new(),
        directories: Vec::new(),
        identities: vec![(".".to_owned(), stat.dev(), stat.ino())],
        excluded: Vec::new(),
        entries: 0,
        bytes: 0,
    };
    collector.walk(&root.file, ".", 0)?;
    if !collector.files.iter().any(|file| file.path == "PKGBUILD") {
        return Err(error(
            "missing_pkgbuild",
            Some("PKGBUILD"),
            "Root PKGBUILD must be a regular text file",
        ));
    }
    if open_root(path)?.ancestry != root.ancestry {
        return Err(changed(None));
    }
    collector.files.sort_by(|a, b| a.path.cmp(&b.path));
    collector.directories.sort();
    collector.identities.sort();
    collector.excluded.sort();
    let digest = digest(&collector.files, &collector.directories);
    Ok(Snapshot {
        files: collector.files,
        directories: collector.directories,
        digest,
        excluded: collector.excluded,
        identities: collector.identities,
        ancestry: root.ancestry,
    })
}

pub fn verify(path: &Path, expected: &Snapshot, limits: &Limits) -> Result<(), CaptureError> {
    let current = capture(path, limits)?;
    if current.digest != expected.digest
        || current.identities != expected.identities
        || current.ancestry != expected.ancestry
        || current.excluded != expected.excluded
    {
        return Err(changed(None));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Entry<'a> {
    File(&'a PackageFile),
    Directory(u32),
}

impl Entry<'_> {
    fn summary(self) -> String {
        match self {
            Self::File(file) => file.sha256.clone(),
            Self::Directory(mode) => format!("directory:{mode:04o}"),
        }
    }
}

fn entries(snapshot: &Snapshot) -> BTreeMap<&str, Entry<'_>> {
    let mut entries: BTreeMap<_, _> = snapshot
        .files
        .iter()
        .map(|file| (file.path.as_str(), Entry::File(file)))
        .collect();
    entries.extend(
        snapshot
            .directories
            .iter()
            .map(|(path, mode)| (path.as_str(), Entry::Directory(*mode))),
    );
    entries
}

pub fn compare(old: &Snapshot, new: &Snapshot) -> Vec<Change> {
    let old = entries(old);
    let new = entries(new);
    let mut paths: Vec<_> = old.keys().chain(new.keys()).copied().collect();
    paths.sort_unstable();
    paths.dedup();
    let mut changes = Vec::new();
    for path in paths {
        let before = old.get(path).copied();
        let after = new.get(path).copied();
        let mut push = |kind: &str, before: Option<String>, after: Option<String>| {
            changes.push(Change {
                path: path.to_owned(),
                kind: kind.to_owned(),
                before,
                after,
            });
        };
        match (before, after) {
            (None, Some(after)) => push("added", None, Some(after.summary())),
            (Some(before), None) => push("deleted", Some(before.summary()), None),
            (Some(Entry::File(before)), Some(Entry::File(after))) => {
                if before.sha256 != after.sha256 {
                    push(
                        "modified",
                        Some(before.sha256.clone()),
                        Some(after.sha256.clone()),
                    );
                }
                if before.mode != after.mode {
                    push(
                        "mode_changed",
                        Some(format!("{:04o}", before.mode)),
                        Some(format!("{:04o}", after.mode)),
                    );
                }
            }
            (Some(Entry::Directory(before)), Some(Entry::Directory(after))) => {
                if before != after {
                    push(
                        "mode_changed",
                        Some(format!("{before:04o}")),
                        Some(format!("{after:04o}")),
                    );
                }
            }
            (Some(before), Some(after)) => push(
                "type_changed",
                Some(before.summary()),
                Some(after.summary()),
            ),
            (None, None) => {}
        }
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::{TempDir, tempdir};

    fn package() -> TempDir {
        let root = tempdir().unwrap();
        fs::write(root.path().join("PKGBUILD"), "pkgname=example\npkgver=1\n").unwrap();
        root
    }

    fn snapshot(root: &Path) -> Snapshot {
        capture(root, &Limits::default()).unwrap()
    }

    fn failure(root: &Path) -> CaptureError {
        capture(root, &Limits::default()).unwrap_err()
    }

    #[test]
    fn hashes_are_portable_sorted_and_include_original_bytes() {
        let a = package();
        let b = package();
        for root in [a.path(), b.path()] {
            fs::create_dir(root.join("empty")).unwrap();
            fs::write(root.join("helper"), "hello\r\n").unwrap();
        }
        let first = snapshot(a.path());
        let second = snapshot(b.path());
        assert_eq!(first.digest, second.digest);
        assert_eq!(
            first
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            ["PKGBUILD", "helper"]
        );
        assert_eq!(first.files[1].text, "hello\r\n");
        assert!(first.directories.iter().any(|(path, _)| path == "empty"));
        assert!(compare(&first, &second).is_empty());
        verify(a.path(), &first, &Limits::default()).unwrap();
    }

    #[test]
    fn collection_never_executes_package_source() {
        let root = package();
        let marker = root.path().join("executed");
        fs::write(root.path().join("PKGBUILD"), "touch executed\nexit 99\n").unwrap();
        let collected = snapshot(root.path());
        assert_eq!(collected.files[0].text, "touch executed\nexit 99\n");
        assert!(!marker.exists());
    }

    #[test]
    fn includes_hidden_helpers_ignore_files_src_and_pkg() {
        let root = package();
        fs::write(root.path().join(".gitignore"), "*\n").unwrap();
        fs::write(root.path().join(".helper"), "hidden\n").unwrap();
        fs::write(root.path().join("example.install"), "helper\n").unwrap();
        for name in ["src", "pkg"] {
            fs::create_dir(root.path().join(name)).unwrap();
            fs::write(root.path().join(name).join("helper"), "included\n").unwrap();
        }
        let collected = snapshot(root.path());
        assert_eq!(collected.files.len(), 6);
        assert!(collected.files.iter().any(|file| file.path == "src/helper"));
        assert!(collected.files.iter().any(|file| file.path == "pkg/helper"));
    }

    #[test]
    fn excludes_only_real_root_git_directory() {
        let root = package();
        fs::create_dir(root.path().join(".git")).unwrap();
        fs::write(root.path().join(".git/data"), [0, 255]).unwrap();
        let before = snapshot(root.path());
        assert_eq!(before.excluded, [".git"]);
        fs::write(root.path().join(".git/data"), [255, 0, 1]).unwrap();
        assert_eq!(snapshot(root.path()).digest, before.digest);
        verify(root.path(), &before, &Limits::default()).unwrap();
        fs::create_dir(root.path().join("nested")).unwrap();
        fs::create_dir(root.path().join("nested/.git")).unwrap();
        fs::write(root.path().join("nested/.git/data"), [0]).unwrap();
        assert_eq!(failure(root.path()).code, "unsupported_text");
    }

    #[test]
    fn a_git_regular_file_is_included() {
        let root = package();
        fs::write(root.path().join(".git"), "gitdir: elsewhere\n").unwrap();
        let collected = snapshot(root.path());
        assert!(collected.excluded.is_empty());
        assert!(collected.files.iter().any(|file| file.path == ".git"));
    }

    #[test]
    fn symlinks_are_rejected_without_external_content_or_paths() {
        let root = package();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret"), "external-sensitive-marker").unwrap();
        for name in ["linked", ".git"] {
            symlink(outside.path().join("secret"), root.path().join(name)).unwrap();
            let err = failure(root.path());
            assert_eq!(err.code, "symlink");
            assert_eq!(err.path.as_deref(), Some(name));
            assert!(!err.to_string().contains("external-sensitive-marker"));
            assert!(!err.to_string().contains(outside.path().to_str().unwrap()));
            fs::remove_file(root.path().join(name)).unwrap();
        }
        symlink("absent", root.path().join("broken")).unwrap();
        assert_eq!(failure(root.path()).code, "symlink");
    }

    #[test]
    fn rejects_root_and_ancestor_symlinks_and_parent_components() {
        let root = package();
        let outer = tempdir().unwrap();
        symlink(root.path(), outer.path().join("linked")).unwrap();
        assert_eq!(failure(&outer.path().join("linked")).code, "symlink");
        fs::create_dir(root.path().join("child")).unwrap();
        fs::write(root.path().join("child/PKGBUILD"), "nested\n").unwrap();
        assert_eq!(failure(&outer.path().join("linked/child")).code, "symlink");
        assert_eq!(
            failure(&outer.path().join("linked/../linked")).code,
            "unsafe_path"
        );
    }

    #[test]
    fn rejects_hardlinks_binary_invalid_utf8_and_control_text() {
        let root = package();
        fs::hard_link(root.path().join("PKGBUILD"), root.path().join("hard")).unwrap();
        assert_eq!(failure(root.path()).code, "hardlink");
        fs::remove_file(root.path().join("hard")).unwrap();
        for bytes in [&[0][..], &[255][..], &[27][..], "\u{0085}".as_bytes()] {
            fs::write(root.path().join("binary"), bytes).unwrap();
            assert_eq!(failure(root.path()).code, "unsupported_text");
        }
    }

    #[test]
    fn rejects_fifo_and_socket_without_opening_them_for_io() {
        let root = package();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            root.path().join("fifo"),
            Mode::RUSR | Mode::WUSR,
        )
        .unwrap();
        assert_eq!(failure(root.path()).code, "special_file");
        fs::remove_file(root.path().join("fifo")).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(root.path().join("socket")).unwrap();
        assert_eq!(failure(root.path()).code, "special_file");
    }

    #[test]
    fn pinned_regular_inode_cannot_turn_into_a_fifo_before_io_open() {
        let root = package();
        let opened = open_root(root.path()).unwrap();
        let pinned = pin_at(&opened.file, "PKGBUILD", Some("PKGBUILD")).unwrap();
        fs::rename(root.path().join("PKGBUILD"), root.path().join("original")).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            root.path().join("PKGBUILD"),
            Mode::RUSR | Mode::WUSR,
        )
        .unwrap();
        let limits = Limits::default();
        let mut collector = Collector {
            limits: &limits,
            files: Vec::new(),
            directories: Vec::new(),
            identities: Vec::new(),
            excluded: Vec::new(),
            entries: 0,
            bytes: 0,
        };
        let before = metadata(&pinned, Some("PKGBUILD")).unwrap();
        collector.read_file(&pinned, &before, "PKGBUILD").unwrap();
        assert_eq!(collector.files[0].text, "pkgname=example\npkgver=1\n");
        assert_eq!(failure(root.path()).code, "special_file");
    }

    #[test]
    fn rejects_unsafe_and_non_utf8_names_without_echoing_them() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let root = package();
        for name in [OsString::from("bad\nname"), OsString::from_vec(vec![255])] {
            fs::write(root.path().join(&name), "text").unwrap();
            let err = failure(root.path());
            assert_eq!(err.code, "unsafe_name");
            assert_eq!(err.path.as_deref(), Some("."));
            fs::remove_file(root.path().join(name)).unwrap();
        }
    }

    #[test]
    fn requires_regular_root_pkgbuild() {
        let root = tempdir().unwrap();
        assert_eq!(failure(root.path()).code, "missing_pkgbuild");
        fs::create_dir(root.path().join("PKGBUILD")).unwrap();
        assert_eq!(failure(root.path()).code, "missing_pkgbuild");
    }

    #[test]
    fn exact_byte_limits_succeed_and_one_extra_byte_fails() {
        let root = package();
        fs::write(root.path().join("PKGBUILD"), "1234").unwrap();
        let limits = Limits {
            max_file_bytes: 4,
            max_total_bytes: 4,
            ..Limits::default()
        };
        capture(root.path(), &limits).unwrap();
        fs::write(root.path().join("PKGBUILD"), "12345").unwrap();
        assert_eq!(
            capture(root.path(), &limits).unwrap_err().code,
            "file_byte_limit"
        );
        fs::write(root.path().join("PKGBUILD"), "1234").unwrap();
        fs::write(root.path().join("helper"), "5").unwrap();
        assert_eq!(
            capture(root.path(), &limits).unwrap_err().code,
            "total_byte_limit"
        );
    }

    #[test]
    fn counts_files_entries_and_depth_including_empty_directories() {
        let root = package();
        let limits = Limits {
            max_files: 1,
            max_entries: 1,
            max_depth: 1,
            ..Limits::default()
        };
        capture(root.path(), &limits).unwrap();
        fs::create_dir(root.path().join("empty")).unwrap();
        assert_eq!(
            capture(root.path(), &limits).unwrap_err().code,
            "entry_limit"
        );
        let limits = Limits {
            max_files: 1,
            max_entries: 3,
            max_depth: 1,
            ..Limits::default()
        };
        capture(root.path(), &limits).unwrap();
        fs::write(root.path().join("helper"), "").unwrap();
        assert_eq!(
            capture(root.path(), &limits).unwrap_err().code,
            "file_limit"
        );
        fs::remove_file(root.path().join("helper")).unwrap();
        fs::create_dir(root.path().join("empty/deeper")).unwrap();
        assert_eq!(
            capture(root.path(), &limits).unwrap_err().code,
            "depth_limit"
        );
    }

    #[test]
    fn detects_added_deleted_modified_and_empty_directory_changes() {
        for mutation in ["added", "deleted", "modified", "directory"] {
            let root = package();
            fs::write(root.path().join("helper"), "original").unwrap();
            let before = snapshot(root.path());
            match mutation {
                "added" => fs::write(root.path().join("new"), "new").unwrap(),
                "deleted" => fs::remove_file(root.path().join("helper")).unwrap(),
                "modified" => fs::write(root.path().join("helper"), "changed").unwrap(),
                _ => fs::create_dir(root.path().join("empty")).unwrap(),
            }
            assert_eq!(
                verify(root.path(), &before, &Limits::default())
                    .unwrap_err()
                    .code,
                "snapshot_changed"
            );
        }
    }

    #[test]
    fn detects_permissions_and_same_content_inode_replacement() {
        let root = package();
        let before = snapshot(root.path());
        let original = fs::metadata(root.path().join("PKGBUILD"))
            .unwrap()
            .permissions();
        fs::set_permissions(
            root.path().join("PKGBUILD"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(verify(root.path(), &before, &Limits::default()).is_err());
        fs::set_permissions(root.path().join("PKGBUILD"), original).unwrap();
        let replacement = root.path().join("replacement");
        fs::write(&replacement, &before.files[0].text).unwrap();
        fs::rename(replacement, root.path().join("PKGBUILD")).unwrap();
        assert_eq!(snapshot(root.path()).digest, before.digest);
        assert_eq!(
            verify(root.path(), &before, &Limits::default())
                .unwrap_err()
                .code,
            "snapshot_changed"
        );
    }

    #[test]
    fn detects_replaced_root_and_ancestor_even_with_identical_bytes() {
        let outer = tempdir().unwrap();
        let ancestor = outer.path().join("ancestor");
        let root = ancestor.join("package");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("PKGBUILD"), "same").unwrap();
        let before = snapshot(&root);
        fs::rename(&ancestor, outer.path().join("old")).unwrap();
        fs::create_dir_all(&ancestor).unwrap();
        fs::rename(outer.path().join("old/package"), &root).unwrap();
        assert_eq!(snapshot(&root).digest, before.digest);
        assert_eq!(
            verify(&root, &before, &Limits::default()).unwrap_err().code,
            "snapshot_changed"
        );
        let before = snapshot(&root);
        fs::rename(&root, ancestor.join("old-package")).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("PKGBUILD"), "same").unwrap();
        assert_eq!(
            verify(&root, &before, &Limits::default()).unwrap_err().code,
            "snapshot_changed"
        );
    }

    #[test]
    fn compare_reports_content_modes_additions_deletions_and_types() {
        let old = package();
        let new = package();
        fs::write(old.path().join("deleted.install"), "old").unwrap();
        fs::write(new.path().join("added.install"), "new").unwrap();
        fs::write(new.path().join("PKGBUILD"), "changed\n").unwrap();
        fs::set_permissions(
            new.path().join("PKGBUILD"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::create_dir(old.path().join("type")).unwrap();
        fs::write(new.path().join("type"), "file").unwrap();
        let changes = compare(&snapshot(old.path()), &snapshot(new.path()));
        let actual: Vec<_> = changes
            .iter()
            .map(|change| (change.path.as_str(), change.kind.as_str()))
            .collect();
        assert_eq!(
            actual,
            [
                ("PKGBUILD", "modified"),
                ("PKGBUILD", "mode_changed"),
                ("added.install", "added"),
                ("deleted.install", "deleted"),
                ("type", "type_changed")
            ]
        );
        let mode = changes
            .iter()
            .find(|change| change.kind == "mode_changed")
            .unwrap();
        assert_eq!(mode.after.as_deref(), Some("0755"));
        assert!(
            changes.iter().all(|change| !change
                .before
                .as_deref()
                .unwrap_or("")
                .contains("changed"))
        );
    }
}
