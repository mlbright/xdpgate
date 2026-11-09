//! xdpgate-ctl - manage the pinned maps. fwknopd runs `open` and `close` for
//! each knock; an operator runs the rest, for the protected set and
//! housekeeping.
//!
//!   xdpgate-ctl open  <ip> <tcp|udp> <port> [timeout_secs]
//!   xdpgate-ctl close <ip> <tcp|udp> <port>
//!   xdpgate-ctl add-protected <ip>
//!   xdpgate-ctl del-protected <ip>
//!   xdpgate-ctl reload
//!   xdpgate-ctl export
//!   xdpgate-ctl list
//!   xdpgate-ctl gc
//!
//! The address family is detected (':' means IPv6). Addresses and ports go
//! into the maps in network byte order, as the XDP program reads them off the
//! wire, and expiries are CLOCK_MONOTONIC nanoseconds, the clock of
//! bpf_ktime_get_ns().
//!
//! protected.conf owns the protected set, not this tool: `reload` makes the
//! protected set match it, and add-protected/del-protected are runtime
//! overrides that the next reload or reboot undoes.
//!
//! Every byte this prints, and every exit code, matches the C version it
//! replaced; tests/goldens.sh holds it to that.
#![deny(unsafe_code)]

use std::cmp::Ordering;
use std::ffi::{CStr, OsStr, OsString};
use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt;

use xdpgate::glibc::{self, ENOENT};
use xdpgate::libbpf::{MapError, MapFd, Pod};
use xdpgate::protected::{DeclaredSet, ProtectedSet, conf_path};
use xdpgate::text::{self, err, out};
use xdpgate::{Reported, c_string, cat, map_error_text, pin_path};
use xdpgate_common::{
    ALLOW_V4, ALLOW_V6, GrantExpiry, GrantKey4, GrantKey6, IPPROTO_TCP, IPPROTO_UDP, PROTECTED_V4,
    PROTECTED_V6, ProtectedKey4, ProtectedKey6, ProtectedValue,
};

/// Used when fwknopd passes no $TIMEOUT.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Upper bound for a grant, chosen only so the nanosecond expiry cannot wrap
/// a u64, which would make an already-expired or never-expiring grant.
const MAX_TIMEOUT_SECS: u64 = 100 * 365 * 24 * 3600;

/// Most expired grants `gc` reaps per map in one run.
const GC_MAX_REAPED: usize = 4096;

fn main() {
    glibc::default_sigpipe();
    let args: Vec<OsString> = std::env::args_os().collect();
    text::exit(run(&args))
}

fn run(args: &[OsString]) -> i32 {
    // With no argv at all, C's printf("%s", NULL) prints "(null)".
    let argv0: &OsStr = args.first().map_or(OsStr::new("(null)"), |a| a);
    let Some(command) = args.get(1) else {
        let (a, p) = (argv0, conf_path());
        #[rustfmt::skip]
        let usage = cat!(
            "usage: ", a, " open  <ip> <tcp|udp> <port> [timeout_secs]\n",
            "       ", a, " close <ip> <tcp|udp> <port>\n",
            "       ", a, " add-protected <ip>      (transient - see reload)\n",
            "       ", a, " del-protected <ip>      (transient - see reload)\n",
            "       ", a, " reload                  apply ", p, "\n",
            "       ", a, " export                  dump the live set as config\n",
            "       ", a, " list\n",
            "       ", a, " gc\n",
        );
        err(&usage);
        return 2;
    };
    match command.as_bytes() {
        b"open" => open_close(argv0, args, true),
        b"close" => open_close(argv0, args, false),
        b"add-protected" => runtime_override(argv0, args, true),
        b"del-protected" => runtime_override(argv0, args, false),
        b"reload" => reload(),
        b"export" => export(),
        b"list" => list(),
        b"gc" => reap_expired_grants(),
        _ => {
            err(&cat!("unknown command '", command, "'\n"));
            2
        }
    }
}

/// Opens the map pinned under `name`, explaining a failure on stderr.
fn open_map<K: Pod, V: Pod>(name: &CStr) -> Result<MapFd<K, V>, Reported> {
    let path = pin_path(name);
    MapFd::open_pinned(&path).map_err(|e| {
        let why = map_error_text(&e);
        match e {
            MapError::Errno(_) => err(&cat!(
                "cannot open pinned map ",
                path,
                ": ",
                why,
                "\n  (is xdpgate-load attached?)\n"
            )),
            MapError::Layout { .. } => err(&cat!(
                "pinned map ",
                path,
                " does not match this xdpgate-ctl: ",
                why,
                "\n"
            )),
        }
        Reported
    })
}

/// A whole decimal string within [min, max]. Unlike atoi this rejects
/// trailing junk ("22x"), signs, an empty string and anything that overflows.
fn parse_ulong(s: &[u8], min: u64, max: u64) -> Option<u64> {
    if !s.first().is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let mut value: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    (min..=max).contains(&value).then_some(value)
}

fn parse_proto(s: &OsStr) -> Option<u8> {
    if s.as_bytes().eq_ignore_ascii_case(b"tcp") {
        Some(IPPROTO_TCP)
    } else if s.as_bytes().eq_ignore_ascii_case(b"udp") {
        Some(IPPROTO_UDP)
    } else {
        err(&cat!("proto must be tcp or udp, got '", s, "'\n"));
        None
    }
}

enum Addr {
    V4(u32),
    V6([u8; 16]),
}

fn parse_ip(s: &OsStr) -> Option<Addr> {
    let text = c_string(s.as_bytes());
    let addr = if text.to_bytes().contains(&b':') {
        glibc::parse_ipv6(&text).map(Addr::V6)
    } else {
        glibc::parse_ipv4(&text).map(Addr::V4)
    };
    if addr.is_none() {
        err(&cat!("bad IP address '", s, "'\n"));
    }
    addr
}

/// `open` grants, `close` revokes. Closing a grant that is already gone
/// (expired and reaped) is not an error.
fn open_close(argv0: &OsStr, args: &[OsString], opening: bool) -> i32 {
    if args.len() < 5 || (opening && args.len() > 6) {
        let timeout = if opening { " [timeout_secs]" } else { "" };
        err(&cat!(
            "usage: ",
            argv0,
            " ",
            args[1],
            " <ip> <tcp|udp> <port>",
            timeout,
            "\n"
        ));
        return 2;
    }
    let Some(addr) = parse_ip(&args[2]) else {
        return 2;
    };
    let Some(proto) = parse_proto(&args[3]) else {
        return 2;
    };
    let Some(port) = parse_ulong(args[4].as_bytes(), 1, 65535) else {
        err(&cat!("port must be 1-65535, got '", args[4], "'\n"));
        return 2;
    };
    let dport = (port as u16).to_be();

    let mut expiry = GrantExpiry { expiry_ns: 0 };
    if opening {
        let mut secs = 0; // 0 selects the default
        if args.len() == 6 {
            match parse_ulong(args[5].as_bytes(), 0, MAX_TIMEOUT_SECS) {
                Some(t) => secs = t,
                None => {
                    err(&cat!(
                        "timeout must be 0-",
                        MAX_TIMEOUT_SECS,
                        " seconds, got '",
                        args[5],
                        "'\n"
                    ));
                    return 2;
                }
            }
        }
        if secs == 0 {
            secs = DEFAULT_TIMEOUT_SECS;
        }
        expiry.expiry_ns = glibc::monotonic_ns() + secs * 1_000_000_000;
    }

    let result = match addr {
        Addr::V4(saddr) => {
            let Ok(map) = open_map::<GrantKey4, GrantExpiry>(ALLOW_V4) else {
                return 1;
            };
            let key = GrantKey4 {
                saddr,
                dport,
                proto,
            };
            if opening {
                map.update(&key, &expiry)
            } else {
                map.delete(&key)
            }
        }
        Addr::V6(saddr) => {
            let Ok(map) = open_map::<GrantKey6, GrantExpiry>(ALLOW_V6) else {
                return 1;
            };
            let key = GrantKey6 {
                saddr,
                dport,
                proto,
            };
            if opening {
                map.update(&key, &expiry)
            } else {
                map.delete(&key)
            }
        }
    };
    if let Err(errno) = result
        && (opening || errno.0 != ENOENT)
    {
        err(&cat!(args[1], " failed: ", errno.message(), "\n"));
        return 1;
    }
    0
}

/// add-protected / del-protected: change the protected set without touching
/// protected.conf. The next reload or reboot undoes it, and the warning says
/// so now rather than leave it as a surprise.
fn runtime_override(argv0: &OsStr, args: &[OsString], adding: bool) -> i32 {
    if args.len() != 3 {
        err(&cat!("usage: ", argv0, " ", args[1], " <ip>\n"));
        return 2;
    }
    let Some(addr) = parse_ip(&args[2]) else {
        return 2;
    };
    let one: ProtectedValue = 1;
    let result = match addr {
        Addr::V4(addr) => {
            let Ok(map) = open_map::<ProtectedKey4, ProtectedValue>(PROTECTED_V4) else {
                return 1;
            };
            if adding {
                map.update(&addr, &one)
            } else {
                map.delete(&addr)
            }
        }
        Addr::V6(addr) => {
            let Ok(map) = open_map::<ProtectedKey6, ProtectedValue>(PROTECTED_V6) else {
                return 1;
            };
            let key = ProtectedKey6 { addr };
            if adding {
                map.update(&key, &one)
            } else {
                map.delete(&key)
            }
        }
    };
    if let Err(errno) = result
        && (adding || errno.0 != ENOENT)
    {
        err(&cat!(args[1], " failed: ", errno.message(), "\n"));
        return 1;
    }

    let (undoes, verb, preposition) = if adding {
        ("reverts", "Add", "to")
    } else {
        ("restores", "Remove", "from")
    };
    err(&cat!(
        "warning: runtime only - the next reload or reboot ",
        undoes,
        " this.\n  ",
        verb,
        " ",
        args[2],
        " ",
        preposition,
        " ",
        conf_path(),
        " to make it durable.\n"
    ));
    0
}

/// Makes the protected set match protected.conf. Only the protected maps are
/// touched: live grants stay, which is why this exists instead of a restart.
fn reload() -> i32 {
    let path = conf_path();
    let Ok(declared) = DeclaredSet::parse(&path) else {
        return 1;
    };
    if declared.check_default_routes().is_err() {
        err(b"reload aborted; the live protected set is unchanged\n");
        return 1;
    }
    declared.warn_unassigned();

    let v4 = open_map(PROTECTED_V4);
    let v6 = open_map(PROTECTED_V6);
    let (Ok(v4), Ok(v6)) = (v4, v6) else {
        return 1;
    };
    let Ok(done) = (ProtectedSet { v4, v6 }).reconcile(&declared) else {
        return 1;
    };
    let n = declared.len();
    out(&cat!(
        "reloaded ",
        path,
        ": ",
        n,
        " address",
        if n == 1 { "" } else { "es" },
        " protected (+",
        done.added,
        ", -",
        done.removed,
        ")\n"
    ));
    0
}

/// Prints the protected set in protected.conf format, so a host whose set
/// only ever lived in the maps can capture it before its next boot needs the
/// file. In map order, as the C printed it.
fn export() -> i32 {
    let v4 = open_map::<ProtectedKey4, ProtectedValue>(PROTECTED_V4);
    let v6 = open_map::<ProtectedKey6, ProtectedValue>(PROTECTED_V6);
    let (Ok(v4), Ok(v6)) = (v4, v6) else {
        return 1;
    };
    out(b"# xdpgate protected set, exported from the live maps.\n");
    out(b"# One address per line. '#' starts a comment; CIDR is not accepted.\n");
    for key in v4.keys() {
        if v4.lookup(&key).is_ok() {
            out(&cat!(glibc::format_ipv4(key), "\n"));
        }
    }
    for key in v6.keys() {
        if v6.lookup(&key).is_ok() {
            out(&cat!(glibc::format_ipv6(&key.addr), "\n"));
        }
    }
    0
}

/// Both clocks, read once per listing: expiries are on CLOCK_MONOTONIC,
/// which means nothing as a date, so they are converted relative to this
/// pair.
struct Clocks {
    mono_ns: u64,
    wall: i64,
}

/// "2d 23h 51m 31s", without leading zero units ("0s" under a second).
fn duration_text(secs: i64) -> String {
    let (d, secs) = (secs / 86400, secs % 86400);
    let (h, secs) = (secs / 3600, secs % 3600);
    let (m, s) = (secs / 60, secs % 60);
    let mut text = String::new();
    if d != 0 {
        let _ = write!(text, "{d}d ");
    }
    if d != 0 || h != 0 {
        let _ = write!(text, "{h}h ");
    }
    if d != 0 || h != 0 || m != 0 {
        let _ = write!(text, "{m}m ");
    }
    let _ = write!(text, "{s}s");
    text
}

/// The tail of a grant's line: "expires <when> (in <how long>)", or how long
/// ago it expired, or "no expiry".
fn expiry_text(expiry_ns: u64, clocks: &Clocks) -> Vec<u8> {
    if expiry_ns == 0 {
        return b"no expiry\n".to_vec();
    }
    // Signed and wrapping, as the compiled C computed it: anything can write
    // the maps, and a junk value must not crash `list` during an incident.
    let left = (expiry_ns as i64).wrapping_sub(clocks.mono_ns as i64) / 1_000_000_000;
    let when = clocks.wall.wrapping_add(left);
    let date = glibc::local_time_text(when).unwrap_or_else(|| b"?".to_vec());
    let duration = duration_text(if left < 0 { left.wrapping_neg() } else { left });
    if left < 0 {
        cat!("expired ", date, " (", duration, " ago)\n")
    } else {
        cat!("expires ", date, " (in ", duration, ")\n")
    }
}

fn proto_name(proto: u8) -> &'static str {
    match proto {
        IPPROTO_TCP => "tcp",
        IPPROTO_UDP => "udp",
        _ => "?",
    }
}

// Listing order. Addresses compare as numbers: IPv4 in host order, IPv6
// bytewise (network order is big-endian, so bytewise is numeric). Grants from
// one source: tcp before udp, then by port.

fn cmp_v4(a: &ProtectedKey4, b: &ProtectedKey4) -> Ordering {
    u32::from_be(*a).cmp(&u32::from_be(*b))
}

fn cmp_grant4(a: &GrantKey4, b: &GrantKey4) -> Ordering {
    let key = |k: &GrantKey4| (u32::from_be(k.saddr), k.proto, u16::from_be(k.dport));
    key(a).cmp(&key(b))
}

fn cmp_grant6(a: &GrantKey6, b: &GrantKey6) -> Ordering {
    let key = |k: &GrantKey6| (k.saddr, k.proto, u16::from_be(k.dport));
    key(a).cmp(&key(b))
}

/// Every key of a map, sorted: the kernel's hash order reads as random.
fn sorted_keys<K: Pod, V: Pod>(map: &MapFd<K, V>, cmp: fn(&K, &K) -> Ordering) -> Vec<K> {
    let mut keys: Vec<K> = map.keys().collect();
    keys.sort_by(cmp);
    keys
}

/// The declared set, for annotating `list` only. A host not yet migrated to
/// protected.conf must still be able to list its maps, so a missing or broken
/// file just means no annotations.
fn declared_quietly() -> Option<DeclaredSet> {
    let path = conf_path();
    if !glibc::readable(&c_string(path.as_bytes())) {
        return None;
    }
    DeclaredSet::parse(&path).ok()
}

/// The protected set, each address tagged with where it came from. Declared
/// addresses missing from the maps print on differently-prefixed lines, so
/// tools scraping "^\s*protected v[46] <ip>" only ever see addresses that are
/// gated right now.
fn list_protected(mut declared: Option<DeclaredSet>) {
    let runtime_only = |in_file: bool| {
        if declared.is_some() && !in_file {
            "   [runtime only]"
        } else {
            ""
        }
    };

    let v4 = open_map::<ProtectedKey4, ProtectedValue>(PROTECTED_V4);
    if let Ok(map) = &v4 {
        for key in sorted_keys(map, cmp_v4) {
            if map.lookup(&key).is_ok() {
                let in_file = declared.as_ref().is_some_and(|d| d.has_v4(key));
                out(&cat!(
                    "protected v4 ",
                    glibc::format_ipv4(key),
                    runtime_only(in_file),
                    "\n"
                ));
            }
        }
    }
    let v6 = open_map::<ProtectedKey6, ProtectedValue>(PROTECTED_V6);
    if let Ok(map) = &v6 {
        for key in sorted_keys(map, ProtectedKey6::cmp) {
            if map.lookup(&key).is_ok() {
                let in_file = declared.as_ref().is_some_and(|d| d.has_v6(&key.addr));
                out(&cat!(
                    "protected v6 ",
                    glibc::format_ipv6(&key.addr),
                    runtime_only(in_file),
                    "\n"
                ));
            }
        }
    }

    let Some(declared) = declared.as_mut() else {
        return;
    };
    declared.v4.sort_by(cmp_v4);
    declared.v6.sort();
    for addr in &declared.v4 {
        if v4.as_ref().is_ok_and(|map| map.lookup(addr).is_err()) {
            out(&cat!(
                "missing   v4 ",
                glibc::format_ipv4(*addr),
                "   [in config, removed at runtime]\n"
            ));
        }
    }
    for addr in &declared.v6 {
        let key = ProtectedKey6 { addr: *addr };
        if v6.as_ref().is_ok_and(|map| map.lookup(&key).is_err()) {
            out(&cat!(
                "missing   v6 ",
                glibc::format_ipv6(addr),
                "   [in config, removed at runtime]\n"
            ));
        }
    }
}

fn list_grants(clocks: &Clocks) {
    if let Ok(map) = open_map::<GrantKey4, GrantExpiry>(ALLOW_V4) {
        for key in sorted_keys(&map, cmp_grant4) {
            if let Ok(grant) = map.lookup(&key) {
                out(&cat!(
                    "v4 ",
                    glibc::format_ipv4(key.saddr),
                    ":",
                    proto_name(key.proto),
                    "/",
                    u16::from_be(key.dport),
                    " ",
                    expiry_text(grant.expiry_ns, clocks)
                ));
            }
        }
    }
    if let Ok(map) = open_map::<GrantKey6, GrantExpiry>(ALLOW_V6) {
        for key in sorted_keys(&map, cmp_grant6) {
            if let Ok(grant) = map.lookup(&key) {
                out(&cat!(
                    "v6 [",
                    glibc::format_ipv6(&key.saddr),
                    "]:",
                    proto_name(key.proto),
                    "/",
                    u16::from_be(key.dport),
                    " ",
                    expiry_text(grant.expiry_ns, clocks)
                ));
            }
        }
    }
}

fn list() -> i32 {
    let mono_ns = glibc::monotonic_ns();
    let clocks = Clocks {
        mono_ns,
        wall: glibc::wall_now(),
    };
    list_protected(declared_quietly());
    list_grants(&clocks);
    0
}

/// An expired grant: past its expiry, and not one that never expires. The XDP
/// program already drops it; this only decides whether gc reaps it.
fn is_expired(grant: &GrantExpiry, now_ns: u64) -> bool {
    grant.expiry_ns != 0 && now_ns > grant.expiry_ns
}

/// Reaps one map's expired grants, collecting before deleting: deleting during
/// iteration is undefined.
fn reap<K: Pod>(name: &CStr) -> usize {
    let Ok(map) = open_map::<K, GrantExpiry>(name) else {
        return 0;
    };
    let now = glibc::monotonic_ns();
    let mut expired = Vec::new();
    for key in map.keys() {
        if map.lookup(&key).is_ok_and(|grant| is_expired(&grant, now)) {
            expired.push(key);
            if expired.len() == GC_MAX_REAPED {
                break;
            }
        }
    }
    for key in &expired {
        let _ = map.delete(key);
    }
    expired.len()
}

/// `gc`: frees the slots of expired grants, for when fwknopd's close never
/// came.
fn reap_expired_grants() -> i32 {
    let n = reap::<GrantKey4>(ALLOW_V4) + reap::<GrantKey6>(ALLOW_V6);
    out(&cat!(
        "gc: reaped ",
        n,
        " expired entr",
        if n == 1 { "y" } else { "ies" },
        "\n"
    ));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_parse_strictly() {
        assert_eq!(parse_ulong(b"22", 1, 65535), Some(22));
        assert_eq!(parse_ulong(b"0022", 1, 65535), Some(22));
        assert_eq!(parse_ulong(b"65535", 1, 65535), Some(65535));
        assert_eq!(parse_ulong(b"65536", 1, 65535), None);
        assert_eq!(parse_ulong(b"0", 1, 65535), None);
        assert_eq!(parse_ulong(b"0", 0, 5), Some(0));
        for junk in [&b""[..], b"22x", b"+22", b"-1", b" 22", b"22 ", b"0x10"] {
            assert_eq!(parse_ulong(junk, 0, u64::MAX), None, "{junk:?}");
        }
        assert_eq!(
            parse_ulong(b"18446744073709551615", 0, u64::MAX),
            Some(u64::MAX)
        );
        assert_eq!(parse_ulong(b"18446744073709551616", 0, u64::MAX), None);
    }

    #[test]
    fn durations_drop_leading_zero_units() {
        assert_eq!(duration_text(0), "0s");
        assert_eq!(duration_text(59), "59s");
        assert_eq!(duration_text(60), "1m 0s");
        assert_eq!(duration_text(3600), "1h 0m 0s");
        assert_eq!(
            duration_text(86400 * 2 + 23 * 3600 + 51 * 60 + 31),
            "2d 23h 51m 31s"
        );
        assert_eq!(duration_text(86400 + 5), "1d 0h 0m 5s");
    }

    #[test]
    fn junk_expiries_wrap_instead_of_crashing() {
        let clocks = Clocks {
            mono_ns: 5_000_000_000,
            wall: 1_700_000_000,
        };
        // u64::MAX reads as -1 once signed: just past, like the C.
        let far = expiry_text(u64::MAX, &clocks);
        assert!(
            far.starts_with(b"expired "),
            "{}",
            String::from_utf8_lossy(&far)
        );
        assert!(far.ends_with(b" (5s ago)\n"));
        // 2^63 reads as i64::MIN, and the subtraction wraps to the far future.
        let wrapped = expiry_text(1 << 63, &clocks);
        assert!(
            wrapped.starts_with(b"expires "),
            "{}",
            String::from_utf8_lossy(&wrapped)
        );
        assert!(wrapped.ends_with(b" (in 106751d 23h 47m 11s)\n"));
        assert_eq!(expiry_text(0, &clocks), b"no expiry\n");
    }

    #[test]
    fn listing_order_is_numeric() {
        let v4 = |s: &str| u32::from_ne_bytes(s.parse::<std::net::Ipv4Addr>().unwrap().octets());
        let mut addrs = vec![v4("192.0.2.10"), v4("192.0.2.9"), v4("10.0.0.1")];
        addrs.sort_by(cmp_v4);
        assert_eq!(addrs, [v4("10.0.0.1"), v4("192.0.2.9"), v4("192.0.2.10")]);

        let grant = |s: &str, proto, port: u16| GrantKey4 {
            saddr: v4(s),
            dport: port.to_be(),
            proto,
        };
        let mut grants = vec![
            grant("192.0.2.9", IPPROTO_UDP, 53),
            grant("192.0.2.10", IPPROTO_TCP, 22),
            grant("192.0.2.9", IPPROTO_TCP, 443),
            grant("192.0.2.9", IPPROTO_TCP, 80),
        ];
        grants.sort_by(cmp_grant4);
        assert_eq!(
            grants,
            [
                grant("192.0.2.9", IPPROTO_TCP, 80),
                grant("192.0.2.9", IPPROTO_TCP, 443),
                grant("192.0.2.9", IPPROTO_UDP, 53),
                grant("192.0.2.10", IPPROTO_TCP, 22),
            ]
        );

        let mut v6 = [[0u8; 16], [0u8; 16], [0u8; 16]];
        v6[0][15] = 0x10;
        v6[1][15] = 0x09;
        v6[2][15] = 0x0a;
        let mut keys: Vec<ProtectedKey6> = v6.iter().map(|a| ProtectedKey6 { addr: *a }).collect();
        keys.sort();
        let last: Vec<u8> = keys.iter().map(|k| k.addr[15]).collect();
        assert_eq!(last, [0x09, 0x0a, 0x10]);
    }

    #[test]
    fn expired_means_past_and_not_never() {
        assert!(is_expired(&GrantExpiry { expiry_ns: 10 }, 11));
        assert!(!is_expired(&GrantExpiry { expiry_ns: 10 }, 10));
        assert!(!is_expired(&GrantExpiry { expiry_ns: 0 }, u64::MAX));
    }
}
