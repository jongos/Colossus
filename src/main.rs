use colossus_audit::{audit, report, Options};
use std::{
    io::{self, Write},
    path::PathBuf,
    sync::atomic::Ordering,
};
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("colossus: {e}");
            std::process::exit(1);
        }
    }
}
fn run() -> Result<i32, String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") => {
            println!("colossus {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        Some("--help") | None => {
            println!("Colossus: read-only Windows developer-workspace auditor\nUsage: colossus audit --root ABSOLUTE_PATH [--root PATH ...] [--format json|text] [--output ABSOLUTE_NEW_FILE] [--max-entries N] [--max-depth N] [--deadline-ms N] [--quiet] [--provenance] [--hash-file ABSOLUTE_FILE ...] [--max-content-bytes N] [--statement-file ABSOLUTE_FILE ...]\nDefault: text to stdout; one worker; no links followed. Provenance is opt-in; hash files must be explicitly selected. Additional content budget defaults to 64 MiB (1 MiB/manifest, 32 MiB/hash file, 4 KiB/revision metadata, 1 MiB/statement; max 32 selected statements). Output parent must exist outside scan roots.\nExit: 0 complete within stated limits; 1 error; 2 incomplete; 130 cancelled. Ctrl-C requests a partial report.");
            return Ok(0);
        }
        Some("audit") => {}
        _ => return Err("only the read-only audit command is available; use --help".into()),
    }
    let mut options = Options::new(vec![]);
    options.progress = true;
    let mut format = "text".to_string();
    let mut output = None;
    while let Some(a) = args.next() {
        if a == "--quiet" {
            options.progress = false;
            continue;
        }
        if a == "--provenance" {
            options.provenance = true;
            continue;
        }
        let v = args
            .next()
            .ok_or_else(|| format!("missing value for {a}"))?;
        match a.as_str() {
            "--root" => options.roots.push(PathBuf::from(v)),
            "--format" => format = v,
            "--output" => output = Some(PathBuf::from(v)),
            "--hash-file" => options.hash_files.push(PathBuf::from(v)),
            "--statement-file" => options.statement_files.push(PathBuf::from(v)),
            "--max-content-bytes" => {
                options.max_content_bytes = v.parse().map_err(|_| "invalid content byte budget")?
            }
            "--max-entries" => {
                options.max_entries = v.parse().map_err(|_| "invalid entry limit")?
            }
            "--max-depth" => options.max_depth = v.parse().map_err(|_| "invalid depth")?,
            "--deadline-ms" => {
                options.deadline_ms = Some(v.parse().map_err(|_| "invalid deadline")?)
            }
            _ => return Err(format!("unknown option {a}")),
        }
    }
    if format != "text" && format != "json" {
        return Err("format must be json or text".into());
    }
    let cancel = options.cancel.clone();
    ctrlc::set_handler(move || cancel.store(true, Ordering::Relaxed)).map_err(|e| e.to_string())?;
    let r = audit(&options)?;
    let bytes = if format == "json" {
        serde_json::to_vec_pretty(&r).map_err(|e| e.to_string())?
    } else {
        report::human(&r).into_bytes()
    };
    if let Some(path) = output {
        report::write_new(&path, &bytes, &r)
            .map_err(|e| format!("report write failed (a partial new file may remain): {e}"))?;
    } else {
        io::stdout()
            .lock()
            .write_all(&bytes)
            .map_err(|e| e.to_string())?;
    }
    Ok(if r.cancelled {
        130
    } else if !r.complete {
        2
    } else {
        0
    })
}
