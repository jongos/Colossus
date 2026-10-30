//! First cleanup executor: explicit regular files, interactive exact-plan approval.
//! Audit reports/checkpoints are never executable plans. No recursive deletion.
use crate::platform;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::fs::OpenOptions;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
const MAX_FILE: u64 = 256 * 1024 * 1024;
const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub path: String,
    pub identity: String,
    pub ancestors: Vec<String>,
    pub bytes: u64,
    pub allocated: u64,
    pub modified: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema_version: String,
    pub operation: String,
    pub root: String,
    pub root_identity: String,
    pub reason: String,
    pub recovery: String,
    pub targets: Vec<Target>,
    pub digest: String,
}
fn error(s: impl ToString) -> io::Error {
    io::Error::other(s.to_string())
}
fn digest(p: &Plan) -> io::Result<String> {
    let mut p = p.clone();
    p.digest.clear();
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&p)?)
    ))
}
fn allowed(path: &Path) -> io::Result<()> {
    platform::validate_components(path)?;
    for part in path.components() {
        let s = part.as_os_str().to_string_lossy().to_ascii_lowercase();
        if matches!(
            s.as_str(),
            ".git"
                | ".hg"
                | ".svn"
                | "node_modules"
                | ".venv"
                | "venv"
                | ".ssh"
                | ".aws"
                | ".codex"
                | ".cargo"
                | ".npm"
                | ".pnpm-store"
        ) {
            return Err(error("protected or managed path; native adapter required"));
        }
    }
    if !matches!(
        path.extension()
            .and_then(|s| s.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some(
            "bin"
                | "zip"
                | "tar"
                | "gz"
                | "7z"
                | "tmp"
                | "log"
                | "exe"
                | "dll"
                | "pdb"
                | "obj"
                | "o"
                | "rlib"
                | "rmeta"
                | "wasm"
        )
    ) {
        return Err(error("first executor supports only explicitly reviewed artifact file extensions; source/configuration and unknown types are refused"));
    }
    Ok(())
}
fn policy(parent: &Path) -> io::Result<()> {
    for dir in parent.ancestors() {
        for name in [".git", ".hg", ".svn", "colossus.artifacts.json"] {
            match std::fs::symlink_metadata(dir.join(name)) {
                Ok(_)=>return Err(error("repository/worktree or retention registry in ancestry; unsupported by first file executor")),
                Err(e) if e.kind()==io::ErrorKind::NotFound=>{},Err(e)=>return Err(e),
            }
        }
    }
    Ok(())
}
#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        ffi::c_void,
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
    };
    #[link(name = "kernel32")]
    extern "system" {
        fn SetFileInformationByHandle(
            h: *mut c_void,
            class: i32,
            info: *const c_void,
            size: u32,
        ) -> i32;
        fn GetDiskFreeSpaceExW(
            path: *const u16,
            available: *mut u64,
            total: *mut u64,
            free: *mut u64,
        ) -> i32;
        fn GetVolumeInformationByHandleW(
            h: *mut c_void,
            name: *mut u16,
            n: u32,
            serial: *mut u32,
            max: *mut u32,
            flags: *mut u32,
            fs: *mut u16,
            fs_n: u32,
        ) -> i32;
    }
    pub fn open(path: &Path, delete: bool) -> io::Result<File> {
        // Exclusive sharing refuses existing readers/writers/deleters and prevents new ones.
        let f = OpenOptions::new()
            .access_mode(0x80000000 | if delete { 0x10000 } else { 0 })
            .share_mode(0)
            .custom_flags(0x02000000 | 0x00200000)
            .open(path)?;
        if f.metadata()?.file_attributes() & (0x400 | 0x1000 | 0x40000 | 0x400000) != 0 {
            return Err(error("reparse/offline/recall file refused"));
        }
        Ok(f)
    }
    pub fn ntfs(f: &File) -> io::Result<()> {
        let mut fs = [0u16; 32];
        let mut serial = 0;
        let mut max = 0;
        let mut flags = 0;
        // SAFETY: all output buffers remain valid for the synchronous call.
        if unsafe {
            GetVolumeInformationByHandleW(
                f.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                &mut serial,
                &mut max,
                &mut flags,
                fs.as_mut_ptr(),
                32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let end = fs.iter().position(|x| *x == 0).unwrap_or(fs.len());
        if String::from_utf16_lossy(&fs[..end]) != "NTFS" {
            return Err(error("deletion currently requires local NTFS"));
        }
        Ok(())
    }
    pub fn delete(f: &File) -> io::Result<()> {
        let yes: u8 = 1;
        // SAFETY: FILE_DISPOSITION_INFO is one BOOLEAN; handle has DELETE access.
        if unsafe {
            SetFileInformationByHandle(f.as_raw_handle(), 4, &yes as *const _ as *const c_void, 1)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn free(path: &Path) -> io::Result<u64> {
        let p: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut free = 0;
        // SAFETY: NUL-terminated path is pinned by the caller; output is valid.
        if unsafe {
            GetDiskFreeSpaceExW(
                p.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut free,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(free)
    }
    pub fn journal(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)
    }
}
#[cfg(not(windows))]
mod native {
    use super::*;
    pub fn open(_: &Path, _: bool) -> io::Result<File> {
        Err(error("Windows NTFS only"))
    }
    pub fn ntfs(_: &File) -> io::Result<()> {
        Err(error("Windows NTFS only"))
    }
    pub fn delete(_: &File) -> io::Result<()> {
        Err(error("Windows NTFS only"))
    }
    pub fn free(_: &Path) -> io::Result<u64> {
        Err(error("Windows NTFS only"))
    }
    pub fn journal(_: &Path) -> io::Result<File> {
        Err(error("Windows NTFS only"))
    }
}
struct Held {
    file: File,
    _parents: platform::Pinned,
    target: Target,
}
fn hold(
    root: &platform::Pinned,
    path: &Path,
    delete: bool,
    cancel: &AtomicBool,
) -> io::Result<Held> {
    allowed(path)?;
    if !path.is_absolute() || !path.starts_with(&root.path) || path == root.path {
        return Err(error("target must be strictly inside the exact root"));
    }
    let parent = path.parent().ok_or_else(|| error("missing parent"))?;
    let parents = platform::pin(parent)?;
    if !parents.stat.directory || parents.stat.volume != root.stat.volume {
        return Err(error("directory or volume boundary mismatch"));
    }
    policy(parent)?;
    let ancestors = parents
        .handles
        .iter()
        .map(|f| platform::stat(f).map(|s| s.identity))
        .collect::<io::Result<Vec<_>>>()?;
    if !ancestors.contains(&root.stat.identity) {
        return Err(error("root identity absent from pinned ancestry"));
    }
    let mut file = native::open(path, delete)?;
    let s = platform::stat(&file)?;
    if s.directory
        || s.reparse
        || s.links != 1
        || s.volume != root.stat.volume
        || s.logical > MAX_FILE
    {
        return Err(error(
            "target must be a single-link regular file on the root volume, at most 256 MiB",
        ));
    }
    let allocated = s.allocated.ok_or_else(|| error("allocation unknown"))?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut count = 0;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(error("cancelled during preflight"));
        }
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > MAX_FILE {
            return Err(error("file exceeded limit"));
        }
        hash.update(&buf[..n]);
    }
    if count != s.logical || platform::stat(&file)? != s {
        return Err(error("target changed while hashing"));
    }
    Ok(Held {
        file,
        _parents: parents,
        target: Target {
            path: path
                .to_str()
                .ok_or_else(|| error("non-Unicode path"))?
                .into(),
            identity: s.identity,
            ancestors,
            bytes: s.logical,
            allocated,
            modified: s.modified,
            sha256: format!("{:x}", hash.finalize()),
        },
    })
}
fn root(path: &Path) -> io::Result<platform::Pinned> {
    let p = platform::pin(path)?;
    if !p.stat.directory {
        return Err(error("root is not a directory"));
    }
    native::ntfs(
        p.handles
            .last()
            .ok_or_else(|| error("missing root handle"))?,
    )?;
    Ok(p)
}
fn shape(p: &Plan) -> io::Result<()> {
    if p.schema_version != "cleanup-plan-1"
        || p.operation != "permanent-delete-files"
        || p.targets.is_empty()
        || p.targets.len() > 64
    {
        return Err(error("unsupported cleanup plan or target count"));
    }
    for text in [&p.reason, &p.recovery] {
        if text.trim().is_empty() || text.len() > 4096 {
            return Err(error("bounded reason and recovery consequences required"));
        }
    }
    let mut paths = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut total = 0u64;
    for t in &p.targets {
        if !paths.insert(&t.path) || !ids.insert(&t.identity) {
            return Err(error("duplicate path or identity"));
        }
        total = total
            .checked_add(t.bytes)
            .ok_or_else(|| error("size overflow"))?;
    }
    if total > MAX_TOTAL {
        return Err(error("plan exceeds 1 GiB content limit"));
    }
    Ok(())
}
pub fn plan(
    root_path: &Path,
    paths: &[PathBuf],
    reason: String,
    recovery: String,
    cancel: &AtomicBool,
) -> io::Result<Plan> {
    if paths.is_empty() || paths.len() > 64 {
        return Err(error("select 1..64 exact files"));
    }
    let root = root(root_path)?;
    let mut held = Vec::new();
    let mut total = 0u64;
    for path in paths {
        let h = hold(&root, path, false, cancel)?;
        total += h.target.bytes;
        if total > MAX_TOTAL {
            return Err(error("plan exceeds 1 GiB"));
        }
        held.push(h);
    }
    let mut p = Plan {
        schema_version: "cleanup-plan-1".into(),
        operation: "permanent-delete-files".into(),
        root: root.path.to_string_lossy().into(),
        root_identity: root.stat.identity.clone(),
        reason,
        recovery,
        targets: held.into_iter().map(|h| h.target).collect(),
        digest: String::new(),
    };
    shape(&p)?;
    p.digest = digest(&p)?;
    Ok(p)
}
pub fn load(path: &Path) -> io::Result<Plan> {
    let pinned = platform::pin(path)?;
    if pinned.stat.directory || pinned.stat.logical > 1024 * 1024 {
        return Err(error("invalid or oversized plan file"));
    }
    let p: Plan = serde_json::from_reader(
        pinned
            .handles
            .last()
            .ok_or_else(|| error("missing plan handle"))?,
    )?;
    shape(&p)?;
    if digest(&p)? != p.digest {
        return Err(error("plan digest mismatch; this digest is not approval"));
    }
    Ok(p)
}
fn output(path: &Path, root: &platform::Pinned) -> io::Result<(File, platform::Pinned)> {
    platform::validate_components(path)?;
    if !path.is_absolute() {
        return Err(error("absolute output required"));
    }
    let parent = platform::pin(
        path.parent()
            .ok_or_else(|| error("missing output parent"))?,
    )?;
    for h in &parent.handles {
        if platform::stat(h)?.identity == root.stat.identity {
            return Err(error("control output must be outside cleanup root"));
        }
    }
    Ok((native::journal(path)?, parent))
}
pub fn save(path: &Path, p: &Plan) -> io::Result<()> {
    let root = root(Path::new(&p.root))?;
    let (mut f, _pin) = output(path, &root)?;
    serde_json::to_writer_pretty(&mut f, p)?;
    f.sync_all()
}
fn event(f: &mut File, v: serde_json::Value) -> io::Result<()> {
    serde_json::to_writer(&mut *f, &v)?;
    f.write_all(b"\n")?;
    f.sync_all()
}
pub fn review(p: &Plan) -> String {
    let mut s=format!("PERMANENT DELETION — no undo or automatic recovery\nPlan {}\nRoot {:?}\nReason {:?}\nRecovery consequences {:?}\n",p.digest,p.root,p.reason,p.recovery);
    for t in &p.targets {
        s.push_str(&format!(
            "DELETE {:?}: {} logical bytes, {} allocated bytes, identity {}, SHA256 {}\n",
            t.path, t.bytes, t.allocated, t.identity, t.sha256
        ));
    }
    s.push_str("Only these files. No directory removal. All other paths remain outside execution scope. Allocation is not guaranteed reclaimed space.\n");
    s
}
/// Caller must obtain explicit human approval of review(plan). The CLI requires a terminal.
/// No approval flags, environment variables, audit reports or checkpoints authorize execution.
pub fn execute(
    p: &Plan,
    receipt: &Path,
    cancel: &AtomicBool,
    approve: impl FnOnce(&Plan) -> io::Result<bool>,
) -> io::Result<bool> {
    shape(p)?;
    if digest(p)? != p.digest {
        return Err(error("plan digest mismatch"));
    }
    let root = root(Path::new(&p.root))?;
    if root.stat.identity != p.root_identity {
        return Err(error("root identity changed"));
    }
    let mut held = Vec::new();
    // Acquire every exclusive file handle and pin every ancestor before approval or mutation.
    for t in &p.targets {
        let h = hold(&root, Path::new(&t.path), true, cancel)?;
        if h.target != *t {
            return Err(error("stale target; create and approve a new plan"));
        }
        held.push(h);
    }
    if !approve(p)? {
        return Err(error("approval declined; nothing deleted"));
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(error("cancelled; nothing deleted"));
    }
    // Recheck live policy immediately after the approval pause, before any deletion.
    for h in &held {
        policy(Path::new(&h.target.path).parent().unwrap())?;
        let s = platform::stat(&h.file)?;
        if s.identity != h.target.identity
            || s.links != 1
            || s.logical != h.target.bytes
            || s.modified != h.target.modified
            || s.allocated != Some(h.target.allocated)
            || s.reparse
            || s.directory
        {
            return Err(error("target changed after approval"));
        }
    }
    let (mut journal, _journal_parent) = output(receipt, &root)?;
    let before = native::free(&root.path).ok();
    event(
        &mut journal,
        serde_json::json!({"event":"approved_preflight","schema_version":"cleanup-receipt-1","plan":p,"free_bytes_before":before,"limitations":["No automatic recovery or replay; an interrupted intent requires manual reconciliation.","Free-space changes include concurrent activity and journal growth; causal reclaimed bytes remain unknown."]}),
    )?;
    let mut completed = 0usize;
    let mut selected_allocation = 0u64;
    let mut all = true;
    for h in held {
        if cancel.load(Ordering::Relaxed) {
            all = false;
            break;
        }
        policy(Path::new(&h.target.path).parent().unwrap())?;
        let s = platform::stat(&h.file)?;
        if s.identity != h.target.identity
            || s.links != 1
            || s.logical != h.target.bytes
            || s.modified != h.target.modified
            || s.allocated != Some(h.target.allocated)
            || s.reparse
            || s.directory
        {
            return Err(error(
                "target changed before deletion; remaining entries unattempted",
            ));
        }
        event(
            &mut journal,
            serde_json::json!({"event":"delete_intent","path":h.target.path,"identity":h.target.identity}),
        )?;
        if let Err(e) = native::delete(&h.file) {
            event(
                &mut journal,
                serde_json::json!({"event":"failed","path":h.target.path,"error":e.to_string()}),
            )?;
            all = false;
            break;
        }
        let path = h.target.path.clone();
        let allocation = h.target.allocated;
        drop(h.file); // Windows disposition takes effect when the exclusive handle closes.
        let absent =
            matches!(std::fs::symlink_metadata(&path),Err(e) if e.kind()==io::ErrorKind::NotFound);
        event(
            &mut journal,
            serde_json::json!({"event":if absent{"removed"}else{"outcome_unconfirmed"},"path":path,"identity":h.target.identity}),
        )?;
        if !absent {
            all = false;
            break;
        }
        completed += 1;
        selected_allocation += allocation;
    }
    let after = native::free(&root.path).ok();
    event(
        &mut journal,
        serde_json::json!({"event":"finished","complete":all,"removed_files":completed,"planned_files":p.targets.len(),"selected_removed_allocation_bytes":selected_allocation,"free_bytes_after":after,"observed_free_space_delta_bytes":before.zip(after).map(|(b,a)|i128::from(a)-i128::from(b)),"causal_reclaimed_bytes":null,"cancelled":cancel.load(Ordering::Relaxed)}),
    )?;
    Ok(all)
}
pub fn cli(args: impl Iterator<Item = String>) -> Result<i32, String> {
    use std::io::IsTerminal;
    let mut args = args;
    let action = args.next().ok_or("use cleanup plan|review|execute")?;
    let mut root_path = None;
    let mut files = vec![];
    let mut plan_path = None;
    let mut out = None;
    let mut reason = None;
    let mut recovery = None;
    while let Some(k) = args.next() {
        let v = args
            .next()
            .ok_or_else(|| format!("missing value for {k}"))?;
        match k.as_str() {
            "--root" => root_path = Some(PathBuf::from(v)),
            "--file" => files.push(PathBuf::from(v)),
            "--plan" => plan_path = Some(PathBuf::from(v)),
            "--output" | "--receipt" => out = Some(PathBuf::from(v)),
            "--reason" => reason = Some(v),
            "--recovery" => recovery = Some(v),
            _ => return Err(format!("unknown cleanup option {k}")),
        }
    }
    let cancel = std::sync::Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    ctrlc::set_handler(move || c.store(true, Ordering::Relaxed)).map_err(|e| e.to_string())?;
    let run = || -> io::Result<i32> {
        match action.as_str() {
            "plan" => {
                let p = plan(
                    root_path
                        .as_deref()
                        .ok_or_else(|| error("--root required"))?,
                    &files,
                    reason.ok_or_else(|| error("--reason required"))?,
                    recovery.ok_or_else(|| error("--recovery required"))?,
                    &cancel,
                )?;
                save(
                    out.as_deref().ok_or_else(|| error("--output required"))?,
                    &p,
                )?;
                print!("{}", review(&p));
                Ok(0)
            }
            "review" => {
                let p = load(
                    plan_path
                        .as_deref()
                        .ok_or_else(|| error("--plan required"))?,
                )?;
                print!("{}", review(&p));
                Ok(0)
            }
            "execute" => {
                if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                    return Err(error("execution requires an interactive terminal and exact-plan confirmation; piped approval is refused"));
                }
                let p = load(
                    plan_path
                        .as_deref()
                        .ok_or_else(|| error("--plan required"))?,
                )?;
                let ok = execute(
                    &p,
                    out.as_deref().ok_or_else(|| error("--receipt required"))?,
                    &cancel,
                    |p| {
                        print!(
                            "{}\nType DELETE {} to approve these exact files: ",
                            review(p),
                            p.digest
                        );
                        io::stdout().flush()?;
                        let mut answer = String::new();
                        io::stdin().read_line(&mut answer)?;
                        Ok(answer.trim() == format!("DELETE {}", p.digest))
                    },
                )?;
                Ok(if ok { 0 } else { 2 })
            }
            _ => Err(error("only cleanup plan, review and execute are supported")),
        }
    };
    run().map_err(|e| e.to_string())
}
