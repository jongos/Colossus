//! Bounded Git metadata parsing. Never invokes Git, hooks, filters, or repository configuration.
use crate::{content, model::*, platform};
use sha1::{Digest, Sha1};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Component, Path, PathBuf},
};
const MAX_METADATA: u64 = 16 * 1024 * 1024;

fn read_known(path: &Path, artifacts: &BTreeMap<PathBuf, Artifact>) -> Result<Vec<u8>, String> {
    let a = artifacts
        .get(path)
        .ok_or("metadata path was not inventoried within authorized roots")?;
    if a.kind != "file" || a.logical_bytes > MAX_METADATA {
        return Err("metadata is not a regular bounded file".into());
    }
    let pinned = platform::pin(path).map_err(|e| e.to_string())?;
    if pinned.stat.identity != a.identity
        || pinned.stat.modified != a.modified_filetime
        || pinned.stat.logical != a.logical_bytes
    {
        return Err("metadata changed since inventory".into());
    }
    let file = platform::open(path, true).map_err(|e| e.to_string())?;
    let before = platform::stat(&file).map_err(|e| e.to_string())?;
    if before != pinned.stat {
        return Err("metadata changed while opening".into());
    }
    let mut data = Vec::new();
    (&file)
        .take(MAX_METADATA + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_METADATA
        || platform::stat(&file).map_err(|e| e.to_string())? != before
    {
        return Err("metadata changed during inspection or exceeds bound".into());
    }
    Ok(data)
}
fn text(path: &Path, artifacts: &BTreeMap<PathBuf, Artifact>) -> Result<String, String> {
    String::from_utf8(read_known(path, artifacts)?)
        .map(|s| s.trim().to_owned())
        .map_err(|_| "non-UTF8 Git metadata".into())
}
#[derive(Debug)]
pub struct IndexEntry {
    pub path: String,
    pub size: u32,
    pub seconds: u32,
    pub nanos: u32,
}
pub fn parse_index(data: &[u8]) -> Result<Vec<IndexEntry>, String> {
    parse_index_interruptible(data, &|| false)
}
fn parse_index_interruptible(
    data: &[u8],
    stop: &dyn Fn() -> bool,
) -> Result<Vec<IndexEntry>, String> {
    fn word(d: &[u8], o: usize) -> Result<u32, String> {
        Ok(u32::from_be_bytes(
            d.get(o..o + 4)
                .ok_or("truncated index")?
                .try_into()
                .unwrap(),
        ))
    }
    if data.get(0..4) != Some(b"DIRC") {
        return Err("invalid index signature".into());
    }
    let version = word(data, 4)?;
    if version != 2 && version != 3 {
        return Err(format!("unsupported index version {version}"));
    }
    let count = word(data, 8)? as usize;
    if count > 250_000 {
        return Err("index entry budget exceeded".into());
    }
    let mut out = Vec::new();
    let mut pos = 12;
    for _ in 0..count {
        if stop() {
            return Err("cancelled during index parsing".into());
        }
        let start = pos;
        let seconds = word(data, pos + 8)?;
        let nanos = word(data, pos + 12)?;
        let size = word(data, pos + 36)?;
        let flags = u16::from_be_bytes(
            data.get(pos + 60..pos + 62)
                .ok_or("truncated index flags")?
                .try_into()
                .unwrap(),
        );
        if flags & 0x7000 != 0 {
            return Err("unmerged or extended index flags unsupported".into());
        }
        pos += 62;
        let end = data
            .get(pos..)
            .ok_or("truncated path")?
            .iter()
            .position(|b| *b == 0)
            .ok_or("unterminated index path")?
            + pos;
        let path = std::str::from_utf8(&data[pos..end])
            .map_err(|_| "non-UTF8 index path")?
            .to_owned();
        if path.is_empty()
            || Path::new(&path)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            || path.contains('\\')
            || path.contains(':')
        {
            return Err("unsafe or unsupported index path".into());
        }
        out.push(IndexEntry {
            path,
            size,
            seconds,
            nanos,
        });
        pos = start + ((end + 1 - start + 7) & !7);
        if pos > data.len() {
            return Err("truncated index padding".into());
        }
    }
    // SHA-1 indices only. Reject split/sparse/unknown mandatory extensions.
    while data.len().saturating_sub(pos) > 20 {
        let sig = data.get(pos..pos + 4).ok_or("truncated extension")?;
        let len = word(data, pos + 4)? as usize;
        if !sig[0].is_ascii_uppercase() {
            return Err("unsupported mandatory index extension".into());
        }
        pos = pos.checked_add(8 + len).ok_or("extension overflow")?;
        if pos > data.len() {
            return Err("truncated extension body".into());
        }
    }
    if data.len().saturating_sub(pos) != 20 {
        return Err("unsupported index checksum length".into());
    }
    if Sha1::digest(&data[..pos]).as_slice() != &data[pos..] {
        return Err("Git index SHA-1 checksum mismatch".into());
    }
    Ok(out)
}

pub fn collect(report: &mut Report, stop: &dyn Fn() -> bool) {
    let artifacts: BTreeMap<_, _> = report
        .artifacts
        .iter()
        .map(|a| (PathBuf::from(&a.path), a.clone()))
        .collect();
    let markers: Vec<_> = artifacts
        .iter()
        .filter(|(p, _)| p.file_name().is_some_and(|s| s == ".git"))
        .map(|(p, a)| (p.clone(), a.clone()))
        .collect();
    for (marker, a) in markers {
        if stop() {
            report.cancelled = true;
            report.complete = false;
            return;
        }
        let root = marker.parent().unwrap();
        let mut repo=Repository {path:root.to_string_lossy().into_owned(),kind:if a.kind=="directory"{"repository"}else{"linked_worktree_or_submodule"}.into(),head:None,gitdir_claim:None,common_dir_claim:None,resolved_gitdir:None,resolved_common_dir:None,index_checksum:None,locked:None,index_entries:None,possibly_modified:vec![],untracked:vec![],limitations:vec!["Metadata comparison only; content dirtiness, staged changes, ignored rules and HEAD/index equivalence are not verified.".into(),"Index checksum consistency is not authentication; repository metadata remains untrusted.".into()]};
        let gitdir = if a.kind == "directory" {
            Some(marker.clone())
        } else {
            match text(&marker, &artifacts) {
                Ok(value) => {
                    if let Some(claim) = value.strip_prefix("gitdir: ") {
                        repo.gitdir_claim = Some(claim.into());
                        match content::resolve(root, claim, &artifacts) {
                            Ok(target) if artifacts[&target].kind == "directory" => Some(target),
                            _ => {
                                repo.limitations.push("Gitdir claim unresolved: no inventoried directory target through safe components; external state remains unknown.".into());
                                None
                            }
                        }
                    } else {
                        repo.limitations.push("Malformed gitdir file".into());
                        None
                    }
                }
                Err(e) => {
                    repo.limitations.push(e);
                    None
                }
            }
        };
        if let Some(dir) = gitdir {
            repo.resolved_gitdir = Some(dir.to_string_lossy().into_owned());
            match text(&dir.join("HEAD"), &artifacts) {
                Ok(v) => repo.head = Some(v),
                Err(e) => repo.limitations.push(format!("HEAD: {e}")),
            }
            repo.locked = if artifacts.contains_key(&dir.join("locked"))
                || artifacts.contains_key(&dir.join("index.lock"))
            {
                Some(true)
            } else {
                None
            };
            if artifacts.contains_key(&dir.join("commondir")) {
                match text(&dir.join("commondir"), &artifacts) {
                    Ok(v) => {
                        repo.resolved_common_dir = content::resolve(&dir, &v, &artifacts)
                            .ok()
                            .filter(|p| artifacts[p].kind == "directory")
                            .map(|p| p.to_string_lossy().into_owned());
                        if repo.resolved_common_dir.is_none() {
                            repo.limitations.push(
                                "Common Git directory is unresolved or outside inventory.".into(),
                            );
                        }
                        repo.common_dir_claim = Some(v);
                    }
                    Err(e) => repo.limitations.push(e),
                }
            }
            match read_known(&dir.join("index"), &artifacts)
                .and_then(|d| parse_index_interruptible(&d, stop))
            {
                Ok(entries) => {
                    repo.index_checksum = Some("sha1_consistent_not_authenticated".into());
                    repo.index_entries = Some(entries.len());
                    let indexed: BTreeMap<_, _> =
                        entries.iter().map(|e| (root.join(&e.path), e)).collect();
                    for (path, e) in &indexed {
                        if stop() {
                            report.cancelled = true;
                            report.complete = false;
                            return;
                        }
                        let ticks = 116444736000000000u64
                            + u64::from(e.seconds) * 10_000_000
                            + u64::from(e.nanos) / 100;
                        if !artifacts.get(path).is_some_and(|a| {
                            a.logical_bytes == u64::from(e.size) && a.modified_filetime == ticks
                        }) {
                            repo.possibly_modified.push(e.path.clone());
                        }
                    }
                    for (path, a) in &artifacts {
                        if stop() {
                            report.cancelled = true;
                            report.complete = false;
                            return;
                        }
                        if a.kind == "file"
                            && a.project_owner.as_deref() == Some(repo.path.as_str())
                            && !path.starts_with(&marker)
                            && !indexed.contains_key(path)
                        {
                            if let Ok(p) = path.strip_prefix(root) {
                                repo.untracked.push(p.to_string_lossy().into_owned());
                            }
                        }
                    }
                    repo.limitations.push("Untracked list includes ignored files; possibly_modified includes missing/uninspected paths and metadata-only differences.".into());
                }
                Err(e) => repo.limitations.push(format!("index: {e}")),
            }
        }
        if repo.index_entries.is_none() {
            report.complete = false;
            report.issues.push(Issue {
                path: repo.path.clone(),
                code: "git_coverage_gap".into(),
                detail: "Git index unavailable or unsupported; see repository limitations".into(),
            });
        }
        report.repositories.push(repo);
    }
}
