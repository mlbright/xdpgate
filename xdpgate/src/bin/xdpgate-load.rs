//! xdpgate-load - load and attach the gate (generic/SKB mode), pinning its maps.
//!
//!   xdpgate-load attach <iface> [obj.o]   load, seed the protected set from
//!                                         /etc/xdpgate/protected.conf, attach,
//!                                         and pin the maps under
//!                                         /sys/fs/bpf/xdpgate
//!   xdpgate-load detach <iface>           detach and remove the pins
//!
//! Seeding happens between load and attach. libbpf creates and pins the maps
//! while loading, so they are writable before the program is wired to the
//! interface: by the time the gate goes live it already knows what it is
//! gating. Any problem with the config aborts before the attach, so the gate
//! is either armed and correct or not armed at all. It can never be attached
//! with an empty protected set, which would pass every packet while looking
//! healthy.
//!
//! The attachment outlives this process: the interface holds the program,
//! and the pinned maps are how xdpgate-ctl reaches it.
//!
//! Every byte this prints, and every exit code, matches the C version it
//! replaced; tests/goldens.sh holds it to that.
#![deny(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs::DirBuilder;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

use xdpgate::glibc::{self, EEXIST, Errno};
use xdpgate::libbpf::{
    Map, MapFd, Object, Pod, XDP_FLAGS_SKB_MODE, XDP_FLAGS_UPDATE_IF_NOEXIST, xdp_attach,
    xdp_detach,
};
use xdpgate::protected::{CONF_ENV, DeclaredSet, ProtectedSet, conf_path};
use xdpgate::text::{self, err, out};
use xdpgate::{Reported, c_string, cat, map_error_text, pin_path};
use xdpgate_common::{ALLOW_V4, ALLOW_V6, PIN_DIR, PROTECTED_V4, PROTECTED_V6};

const DEFAULT_OBJ: &str = "xdpgate.bpf.o";

fn main() {
    glibc::default_sigpipe();
    let args: Vec<OsString> = std::env::args_os().collect();
    text::exit(run(&args))
}

fn run(args: &[OsString]) -> i32 {
    // With no argv at all, C's printf("%s", NULL) prints "(null)".
    let argv0: &OsStr = args.first().map_or(OsStr::new("(null)"), |a| a);
    if args.len() < 3 {
        let (a, p) = (argv0, conf_path());
        #[rustfmt::skip]
        let usage = cat!(
            "usage: ", a, " attach <iface> [obj.o]\n",
            "       ", a, " detach <iface>\n",
            "\n",
            "the protected set is read from ", p, "\n",
            "(override with $", CONF_ENV, ")\n",
        );
        err(&usage);
        return 2;
    }

    let ifindex = glibc::if_nametoindex(&c_string(args[2].as_bytes()));
    if ifindex == 0 {
        err(&cat!("unknown interface '", args[2], "'\n"));
        return 2;
    }

    match args[1].as_bytes() {
        b"attach" => {
            let obj = args.get(3).map_or(OsStr::new(DEFAULT_OBJ), |a| a);
            attach(ifindex, obj)
        }
        b"detach" => detach(ifindex),
        _ => {
            err(&cat!("unknown command '", args[1], "'\n"));
            2
        }
    }
}

fn pin_dir() -> &'static Path {
    Path::new(OsStr::from_bytes(PIN_DIR.to_bytes()))
}

/// Best-effort: removes whichever of the four pins exist, then the directory.
fn remove_pins() {
    for name in [PROTECTED_V4, PROTECTED_V6, ALLOW_V4, ALLOW_V6] {
        let _ = std::fs::remove_file(OsStr::from_bytes(pin_path(name).to_bytes()));
    }
    let _ = std::fs::remove_dir(pin_dir());
}

fn detach(ifindex: u32) -> i32 {
    if let Err(errno) = xdp_detach(ifindex, XDP_FLAGS_SKB_MODE) {
        err(&cat!("detach failed: ", errno.message(), "\n"));
        return 1;
    }
    remove_pins();
    out(&cat!(
        "detached from ifindex ",
        ifindex as i32,
        " and removed pins\n"
    ));
    0
}

fn attach(ifindex: u32, obj_path: &OsStr) -> i32 {
    // Remember whether the pin directory is ours, so a failed attach only
    // cleans up pins it created and never tears down a live gate's maps.
    let created_pin_dir = match DirBuilder::new().mode(0o700).create(pin_dir()) {
        Ok(()) => true,
        Err(e) if e.raw_os_error() == Some(EEXIST) => false,
        Err(e) => {
            let errno = Errno(e.raw_os_error().unwrap_or(0));
            err(&cat!("mkdir ", PIN_DIR, ": ", errno.message(), "\n"));
            err(b"is the bpf filesystem mounted at /sys/fs/bpf?\n");
            return 1;
        }
    };

    if load_seed_attach(ifindex, obj_path).is_ok() {
        return 0;
    }
    if created_pin_dir {
        remove_pins();
    }
    1
}

/// Everything between creating the pin directory and the attach. The object
/// is closed before this returns, whether or not it attached: the interface
/// holds the program, and the maps are pinned.
fn load_seed_attach(ifindex: u32, obj_path: &OsStr) -> Result<(), Reported> {
    let mut obj = Object::open(&c_string(obj_path.as_bytes()), PIN_DIR).map_err(|errno| {
        err(&cat!("open ", obj_path, " failed: ", errno.message(), "\n"));
        Reported
    })?;
    if let Err(errno) = obj.load() {
        err(&cat!("load failed: ", errno.message(), "\n"));
        return Err(Reported);
    }
    let Some(prog) = obj.find_program(c"xdpgate") else {
        err(b"program 'xdpgate' not found in object\n");
        return Err(Reported);
    };

    // Arm the maps before arming the datapath.
    if seed_protected(&obj).is_err() {
        err(b"refusing to attach: the protected set is unusable\n");
        return Err(Reported);
    }

    let attached = prog.fd().and_then(|fd| {
        xdp_attach(
            ifindex,
            fd,
            XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
        )
    });
    if let Err(errno) = attached {
        err(&cat!(
            "xdp attach (generic) failed: ",
            errno.message(),
            "\n"
        ));
        return Err(Reported);
    }

    drop(obj);
    out(&cat!(
        "attached xdpgate (generic mode) to ifindex ",
        ifindex as i32,
        "; maps pinned at ",
        PIN_DIR,
        "\n"
    ));
    Ok(())
}

/// Makes the freshly loaded protected maps match protected.conf.
fn seed_protected(obj: &Object) -> Result<(), Reported> {
    let (Some(m4), Some(m6)) = (obj.find_map(PROTECTED_V4), obj.find_map(PROTECTED_V6)) else {
        err(b"protected maps not found in object\n");
        return Err(Reported);
    };

    let path = conf_path();
    let declared = DeclaredSet::parse(&path)?;
    // Check before touching a map: a reconcile that has started cannot be
    // undone, and this check exists to stop exactly that.
    declared.check_default_routes()?;
    declared.warn_unassigned();

    let set = ProtectedSet {
        v4: from_object(&m4)?,
        v6: from_object(&m6)?,
    };
    let done = set.reconcile(&declared)?;

    let n = declared.len();
    out(&cat!(
        "protected set seeded from ",
        path,
        ": ",
        n,
        " address",
        if n == 1 { "" } else { "es" },
        " (+",
        done.added,
        ", -",
        done.removed,
        ")\n"
    ));
    Ok(())
}

/// A handle on one of the loaded object's maps, which outlives the object.
fn from_object<K: Pod, V: Pod>(map: &Map<'_>) -> Result<MapFd<K, V>, Reported> {
    MapFd::from_object(map).map_err(|e| {
        err(&cat!(
            "map ",
            map.name(),
            " in the object is unusable: ",
            map_error_text(&e),
            "\n"
        ));
        Reported
    })
}
