//! Explicit, bounded content reads against inventoried identities. No ambient discovery.
use crate::{model::Artifact, platform};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

pub struct Budget {
    pub remaining: u64,
    pub read: u64,
}
impl Budget {
    pub fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            read: 0,
        }
    }
    pub fn read(
        &mut self,
        a: &Artifact,
        limit: u64,
        stop: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        self.stream(a, limit, stop, |b| data.extend_from_slice(b))?;
        Ok(data)
    }
    pub fn hash(
        &mut self,
        a: &Artifact,
        limit: u64,
        stop: &dyn Fn() -> bool,
    ) -> Result<String, String> {
        let mut hash = Sha256::new();
        self.stream(a, limit, stop, |b| hash.update(b))?;
        Ok(format!("{:x}", hash.finalize()))
    }
    fn stream(
        &mut self,
        a: &Artifact,
        limit: u64,
        stop: &dyn Fn() -> bool,
        mut accept: impl FnMut(&[u8]),
    ) -> Result<(), String> {
        if stop() {
            return Err("cancelled before content read".into());
        }
        if a.kind != "file" {
            return Err("content requires an inventoried regular file".into());
        }
        if a.logical_bytes > limit || a.logical_bytes > self.remaining {
            return Err("content byte budget exceeded; no bytes read".into());
        }
        let path = Path::new(&a.path);
        let pinned = platform::pin(path).map_err(|e| e.to_string())?;
        if pinned.stat.identity != a.identity
            || pinned.stat.logical != a.logical_bytes
            || pinned.stat.modified != a.modified_filetime
        {
            return Err("content changed since inventory".into());
        }
        // Read-sharing only blocks writers and deletion for the duration of this read.
        let mut file = platform::open(path, true).map_err(|e| e.to_string())?;
        let before = platform::stat(&file).map_err(|e| e.to_string())?;
        if before != pinned.stat {
            return Err("content changed while opening".into());
        }
        let mut buffer = [0u8; 65536];
        let mut total = 0;
        while total < a.logical_bytes {
            if stop() {
                return Err("cancelled during content read".into());
            }
            let wanted = buffer.len().min((a.logical_bytes - total) as usize);
            let n = file
                .read(&mut buffer[..wanted])
                .map_err(|e| e.to_string())?;
            self.remaining -= n as u64;
            self.read += n as u64;
            total += n as u64;
            if n == 0 {
                return Err("content shortened during read".into());
            }
            accept(&buffer[..n]);
        }
        if stop() {
            return Err("cancelled after content read".into());
        }
        if platform::stat(&file).map_err(|e| e.to_string())? != before {
            return Err("content changed during read".into());
        }
        Ok(())
    }
}

/// Resolve only through inventoried directories, including every intermediate component.
/// Dot-dot never authorizes new paths; links, streams, devices and ambiguous names fail closed.
pub fn resolve(
    base: &Path,
    claim: &str,
    artifacts: &BTreeMap<PathBuf, Artifact>,
) -> Result<PathBuf, String> {
    use std::path::Component;
    if claim.is_empty() || claim.contains('\0') || claim.contains('*') || claim.contains('?') {
        return Err("empty, wildcard or unsupported path".into());
    }
    let raw = Path::new(claim);
    let mut current = if raw.is_absolute() {
        PathBuf::new()
    } else {
        base.to_path_buf()
    };
    for part in raw.components() {
        match part {
            Component::Prefix(p) => {
                current.push(p.as_os_str());
                continue;
            }
            Component::RootDir => {
                current.push(part.as_os_str());
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                if !artifacts
                    .get(&current)
                    .is_some_and(|a| a.kind == "directory")
                {
                    return Err("parent traversal lacks inventoried directory evidence".into());
                }
                if !current.pop() {
                    return Err("path escapes volume root".into());
                }
            }
            Component::Normal(name) => {
                let text = name.to_str().ok_or("non-Unicode path")?;
                if text.contains(':') || text.ends_with('.') || text.ends_with(' ') {
                    return Err("stream or ambiguous path component".into());
                }
                // Absolute-path ancestors outside authorized roots are not opened here.
                if let Some(a) = artifacts.get(&current) {
                    if a.kind != "directory" {
                        return Err("path traverses a link or non-directory".into());
                    }
                }
                current.push(name);
                if artifacts.get(&current).is_some_and(|a| a.kind == "reparse") {
                    return Err("path includes a skipped reparse point".into());
                }
            }
        }
    }
    if artifacts.get(&current).is_some_and(|a| a.kind != "reparse") {
        Ok(current)
    } else {
        Err("target was not inventoried in authorized scope".into())
    }
}
