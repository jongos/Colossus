//! Windows opens deny delete-sharing: every ancestor remains pinned until traversal ends.
//! No path-prefix-only trust decision and no reparse traversal.
use std::{
    fs::{File, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    pub identity: String,
    pub volume: u64,
    pub logical: u64,
    pub allocated: Option<u64>,
    pub modified: u64,
    pub directory: bool,
    pub reparse: bool,
    pub links: u32,
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        ffi::c_void,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    };
    #[repr(C)]
    #[derive(Default)]
    struct Time {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct Info {
        attrs: u32,
        created: Time,
        accessed: Time,
        written: Time,
        volume: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        id_high: u32,
        id_low: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct Standard {
        allocation: i64,
        end: i64,
        links: u32,
        delete_pending: u8,
        directory: u8,
    }
    #[repr(C)]
    #[derive(Default)]
    struct FileId {
        volume: u64,
        id: [u8; 16],
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(handle: *mut c_void, info: *mut Info) -> i32;
        fn GetFileInformationByHandleEx(
            handle: *mut c_void,
            class: i32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
    }
    pub fn open(path: &Path, _content: bool) -> io::Result<File> {
        // FILE_READ_ATTRIBUTES alone does not participate in share-access checks.
        // GENERIC_READ is required for deny-delete pinning to be effective.
        OpenOptions::new()
            .access_mode(0x80000000)
            .share_mode(0x1 | 0x2)
            .custom_flags(0x02000000 | 0x00200000)
            .open(path)
    }
    pub fn stat(file: &File) -> io::Result<Stat> {
        let mut info = Info::default();
        // SAFETY: both buffers have the Win32 layouts and remain valid for the call.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut standard = Standard::default();
        let mut identity = FileId::default();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                18,
                &mut identity as *mut _ as *mut c_void,
                std::mem::size_of::<FileId>() as u32,
            )
        } == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "128-bit filesystem identity unavailable; refusing unreliable accounting",
            ));
        }
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                1,
                &mut standard as *mut _ as *mut c_void,
                std::mem::size_of::<Standard>() as u32,
            )
        };
        Ok(Stat {
            identity: format!(
                "{:016x}:{:032x}",
                identity.volume,
                u128::from_le_bytes(identity.id)
            ),
            volume: identity.volume,
            logical: (u64::from(info.size_high) << 32) | u64::from(info.size_low),
            allocated: if ok != 0 && standard.allocation >= 0 {
                Some(standard.allocation as u64)
            } else {
                None
            },
            modified: (u64::from(info.written.high) << 32) | u64::from(info.written.low),
            directory: info.attrs & 0x10 != 0,
            reparse: info.attrs & 0x400 != 0,
            links: info.links,
        })
    }
}

#[cfg(windows)]
pub use native::{open, stat};
#[cfg(not(windows))]
pub fn open(_: &Path, _: bool) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Phase 1 scanning is Windows-only",
    ))
}
#[cfg(not(windows))]
pub fn stat(_: &File) -> io::Result<Stat> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Phase 1 scanning is Windows-only",
    ))
}

pub struct Pinned {
    pub path: PathBuf,
    pub handles: Vec<File>,
    pub stat: Stat,
}
pub fn pin(path: &Path) -> io::Result<Pinned> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute paths required",
        ));
    }
    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    for part in path.components() {
        match part {
            Component::ParentDir | Component::CurDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "dot components are not allowed",
                ))
            }
            Component::Prefix(p) => {
                #[cfg(windows)]
                if !matches!(
                    p.kind(),
                    std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                ) {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "only local drive paths are supported",
                    ));
                }
                current.push(p.as_os_str());
                continue;
            }
            _ => current.push(part.as_os_str()),
        }
        let file = open(&current, false)?;
        if stat(&file)?.reparse {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "reparse point in path; traversal refused",
            ));
        }
        handles.push(file);
    }
    let last = handles
        .last()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty path"))?;
    let final_stat = stat(last)?;
    Ok(Pinned {
        path: current,
        handles,
        stat: final_stat,
    })
}
