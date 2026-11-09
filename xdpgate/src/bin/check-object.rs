//! Build check for the XDP object (ADR 0002).
//!
//!   check-object FILE
//!
//! The maps are hand-written in Rust, so a mistake in one would not stop the
//! build, the verifier or the attach: it would only show up as a gate that
//! quietly pins nothing, or keys the CLIs cannot match. This asks libbpf, the
//! same library the loader uses, to open FILE without loading it, and fails
//! unless it defines exactly the four maps the pins and the CLIs depend on,
//! each a hash map with the frozen key size, value size and capacity, pinned by
//! name under the pin directory, plus the `xdpgate` XDP program.
#![deny(unsafe_code)]

use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::OsStringExt;
use std::process::ExitCode;

use xdpgate::libbpf::{BPF_PROG_TYPE_XDP, Object};
use xdpgate_common::{
    ALLOW_V4, ALLOW_V6, BPF_MAP_TYPE_HASH, GRANT_MAX_ENTRIES, GrantExpiry, GrantKey4, GrantKey6,
    PIN_DIR, PROTECTED_MAX_ENTRIES, PROTECTED_V4, PROTECTED_V6, ProtectedKey4, ProtectedKey6,
    ProtectedValue,
};

struct Want {
    name: &'static CStr,
    key_size: usize,
    value_size: usize,
    max_entries: usize,
}

const WANT: [Want; 4] = [
    Want {
        name: PROTECTED_V4,
        key_size: size_of::<ProtectedKey4>(),
        value_size: size_of::<ProtectedValue>(),
        max_entries: PROTECTED_MAX_ENTRIES,
    },
    Want {
        name: PROTECTED_V6,
        key_size: size_of::<ProtectedKey6>(),
        value_size: size_of::<ProtectedValue>(),
        max_entries: PROTECTED_MAX_ENTRIES,
    },
    Want {
        name: ALLOW_V4,
        key_size: size_of::<GrantKey4>(),
        value_size: size_of::<GrantExpiry>(),
        max_entries: GRANT_MAX_ENTRIES,
    },
    Want {
        name: ALLOW_V6,
        key_size: size_of::<GrantKey6>(),
        value_size: size_of::<GrantExpiry>(),
        max_entries: GRANT_MAX_ENTRIES,
    },
];

fn check(obj: &Object) -> Vec<String> {
    let mut problems = Vec::new();
    let maps: Vec<_> = obj.maps().collect();

    for map in &maps {
        if !WANT.iter().any(|w| w.name == map.name()) {
            problems.push(format!("unexpected map {}", map.name().to_string_lossy()));
        }
    }

    for want in &WANT {
        let name = want.name.to_string_lossy();
        let Some(map) = maps.iter().find(|m| m.name() == want.name) else {
            problems.push(format!("no map {name}"));
            continue;
        };
        let pin_path = map
            .pin_path()
            .map_or("unset".into(), |p| p.to_string_lossy().into_owned());
        let facts = [
            (
                "type",
                map.map_type().to_string(),
                BPF_MAP_TYPE_HASH.to_string(),
            ),
            (
                "key size",
                map.key_size().to_string(),
                want.key_size.to_string(),
            ),
            (
                "value size",
                map.value_size().to_string(),
                want.value_size.to_string(),
            ),
            (
                "max entries",
                map.max_entries().to_string(),
                want.max_entries.to_string(),
            ),
            (
                "pin path",
                pin_path,
                format!("{}/{name}", PIN_DIR.to_string_lossy()),
            ),
        ];
        for (what, got, expected) in facts {
            if got != expected {
                problems.push(format!("{name}: {what} is {got}, expected {expected}"));
            }
        }
    }

    match obj.find_program(c"xdpgate") {
        None => problems.push("no program xdpgate".into()),
        Some(prog) if prog.prog_type() != BPF_PROG_TYPE_XDP => problems.push(format!(
            "xdpgate: program type is {}, expected {BPF_PROG_TYPE_XDP} (xdp)",
            prog.prog_type()
        )),
        Some(_) => {}
    }
    problems
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let [_, file] = &args[..] else {
        eprintln!("usage: check-object FILE");
        return ExitCode::from(2);
    };
    let display = file.to_string_lossy();
    let Ok(path) = CString::new(file.clone().into_vec()) else {
        eprintln!("check-object: {display}: path contains a NUL byte");
        return ExitCode::from(2);
    };

    let obj = match Object::open(&path, PIN_DIR) {
        Ok(obj) => obj,
        Err(err) => {
            eprintln!("check-object: libbpf could not open {display}: {err}");
            return ExitCode::FAILURE;
        }
    };
    let problems = check(&obj);
    if problems.is_empty() {
        println!("check-object: {display} has the four pinned maps and the xdpgate program");
        return ExitCode::SUCCESS;
    }
    for p in &problems {
        eprintln!("check-object: {display}: {p}");
    }
    ExitCode::FAILURE
}
