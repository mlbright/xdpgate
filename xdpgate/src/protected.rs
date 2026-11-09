//! The protected set, and the declared protected set it is made to match.
//!
//! The protected set is what makes the gate a gate: an empty set means every
//! packet takes the "destination not protected -> PASS" branch, so an attached
//! program with no entries is an elaborate no-op. /etc/xdpgate/protected.conf
//! declares it, and both xdpgate-load (at attach) and xdpgate-ctl (at reload)
//! apply the file through the same three steps: [`DeclaredSet::parse`],
//! [`DeclaredSet::check_default_routes`], [`ProtectedSet::reconcile`].

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, UdpSocket};

use xdpgate_common::{PROTECTED_MAX_ENTRIES, ProtectedKey4, ProtectedKey6, ProtectedValue};

use crate::glibc::{self, E2BIG, ENOENT, Errno};
use crate::libbpf::MapFd;
use crate::text::err;
use crate::{Reported, c_string, cat};

pub const CONF_DEFAULT: &str = "/etc/xdpgate/protected.conf";
pub const CONF_ENV: &str = "XDPGATE_CONF";

/// Route-lookup targets only: connecting a UDP socket picks a source address
/// without putting anything on the wire.
const PROBE_V4: &str = "1.1.1.1:53";
const PROBE_V6: &str = "[2606:4700:4700::1111]:53";

/// `$XDPGATE_CONF` if set and non-empty, else /etc/xdpgate/protected.conf.
pub fn conf_path() -> OsString {
    std::env::var_os(CONF_ENV)
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| CONF_DEFAULT.into())
}

/// The addresses protected.conf lists, in file order and network byte order,
/// so they drop straight into the map keys the XDP program reads.
#[derive(Debug, Default, PartialEq)]
pub struct DeclaredSet {
    pub v4: Vec<ProtectedKey4>,
    pub v6: Vec<[u8; 16]>,
}

/// What one line of protected.conf holds, once comments and blanks are gone.
#[derive(Debug, PartialEq)]
enum Line<'a> {
    Blank,
    V4(ProtectedKey4),
    V6([u8; 16]),
    Cidr(&'a [u8]),
    NotOneAddress(&'a [u8]),
    BadV4(&'a [u8]),
    BadV6(&'a [u8]),
}

/// A line's content with C string semantics: it ends at its first NUL, a '#'
/// starts a comment, and blanks and tabs (plus a CR or LF at the end) are
/// trimmed.
fn content(line: &[u8]) -> &[u8] {
    let line = &line[..line.iter().position(|&b| b == 0).unwrap_or(line.len())];
    let line = &line[..line.iter().position(|&b| b == b'#').unwrap_or(line.len())];
    let start = line
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(line.len());
    let line = &line[start..];
    let end = line
        .iter()
        .rposition(|&b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .map_or(0, |i| i + 1);
    &line[..end]
}

fn parse_line(raw: &[u8]) -> Line<'_> {
    let p = content(raw);
    if p.is_empty() {
        Line::Blank
    } else if p.contains(&b'/') {
        Line::Cidr(p)
    } else if p.iter().any(|&b| b == b' ' || b == b'\t') {
        Line::NotOneAddress(p)
    } else if p.contains(&b':') {
        glibc::parse_ipv6(&c_string(p)).map_or(Line::BadV6(p), Line::V6)
    } else {
        glibc::parse_ipv4(&c_string(p)).map_or(Line::BadV4(p), Line::V4)
    }
}

fn explain_empty(path: &OsStr) {
    err(&cat!(
        "  An empty protected set gates nothing: every packet takes the\n",
        "  \"destination not protected -> PASS\" branch. There is no safe\n",
        "  default, so ",
        path,
        " must name at least one address.\n",
        "  Copy protected.conf.example and list one address per line.\n",
    ));
}

impl DeclaredSet {
    /// Parses protected.conf, explaining any problem on stderr. There is
    /// deliberately no partial success: a typo'd address that silently drops a
    /// service out of the protected set is the exact failure the file
    /// prevents. A missing file, a bad line and an empty set are all errors.
    pub fn parse(path: &OsStr) -> Result<DeclaredSet, Reported> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) => {
                let errno = Errno(e.raw_os_error().unwrap_or(0));
                err(&cat!(path, ": ", errno.message(), "\n"));
                if errno.0 == ENOENT {
                    explain_empty(path);
                }
                return Err(Reported);
            }
        };

        let mut reader = BufReader::new(file);
        let mut set = DeclaredSet::default();
        let mut raw = Vec::new();
        let mut lineno: u32 = 0;
        loop {
            raw.clear();
            // A read error ends the file, as it ends getline.
            if !matches!(reader.read_until(b'\n', &mut raw), Ok(n) if n > 0) {
                break;
            }
            lineno += 1;
            let at = |rest: &[u8]| cat!(path, ":", lineno, ": ", rest);
            let duplicate = match parse_line(&raw) {
                Line::Blank => continue,
                Line::V4(addr) if set.has_v4(addr) => true,
                Line::V4(addr) => {
                    set.v4.push(addr);
                    false
                }
                Line::V6(addr) if set.has_v6(&addr) => true,
                Line::V6(addr) => {
                    set.v6.push(addr);
                    false
                }
                Line::Cidr(p) => {
                    err(&cat!(
                        at(b"CIDR is not supported ('"),
                        p,
                        "').\n",
                        "  The protected maps are exact-match hashes; give each\n",
                        "  address its own line.\n",
                    ));
                    return Err(Reported);
                }
                Line::NotOneAddress(p) => {
                    err(&cat!(at(b"expected one address per line, got '"), p, "'\n"));
                    return Err(Reported);
                }
                Line::BadV6(p) => {
                    err(&cat!(at(b"bad IPv6 address '"), p, "'\n"));
                    return Err(Reported);
                }
                Line::BadV4(p) => {
                    err(&cat!(at(b"bad IPv4 address '"), p, "'\n"));
                    return Err(Reported);
                }
            };
            if duplicate {
                err(&cat!(
                    at(b"warning: duplicate address '"),
                    content(&raw),
                    "', ignoring\n"
                ));
            }
        }

        if set.is_empty() {
            err(&cat!(path, ": no addresses configured.\n"));
            explain_empty(path);
            return Err(Reported);
        }
        if set.v4.len() > PROTECTED_MAX_ENTRIES || set.v6.len() > PROTECTED_MAX_ENTRIES {
            err(&cat!(
                path,
                ": too many addresses (v4 ",
                set.v4.len(),
                ", v6 ",
                set.v6.len(),
                "; limit ",
                PROTECTED_MAX_ENTRIES,
                " per family).\n",
                "  Raise max_entries on protected_v4/protected_v6 in\n",
                "  xdpgate-common/src/lib.rs and rebuild if you genuinely need more.\n",
            ));
            return Err(Reported);
        }
        Ok(set)
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn has_v4(&self, addr: ProtectedKey4) -> bool {
        self.v4.contains(&addr)
    }

    pub fn has_v6(&self, addr: &[u8; 16]) -> bool {
        self.v6.contains(addr)
    }

    /// Refuses a set that would cut the host off. The gate is stateless and
    /// ingress-only, so protecting the source address the kernel picks for
    /// the default route drops the return path of every flow the host
    /// originates, including the SSH session of whoever is watching. This is
    /// the overlap whats-on-ip grades HARD. A family with no default route
    /// has no return path to break, so it passes.
    pub fn check_default_routes(&self) -> Result<(), Reported> {
        let mut refused = false;
        if let Some(IpAddr::V4(src)) = default_source(PROBE_V4, "0.0.0.0:0")
            && self.has_v4(u32::from_ne_bytes(src.octets()))
        {
            explain_default_route(
                "IPv4",
                &glibc::format_ipv4(u32::from_ne_bytes(src.octets())),
            );
            refused = true;
        }
        if let Some(IpAddr::V6(src)) = default_source(PROBE_V6, "[::]:0")
            && self.has_v6(&src.octets())
        {
            explain_default_route("IPv6", &glibc::format_ipv6(&src.octets()));
            refused = true;
        }
        if refused { Err(Reported) } else { Ok(()) }
    }

    /// Warns, never fails, about addresses not currently assigned to this
    /// host: EC2 secondary and floating addresses are legitimately attached
    /// after boot.
    pub fn warn_unassigned(&self) {
        let Some((local4, local6)) = glibc::assigned_addresses() else {
            return; // advisory only; never block on it
        };
        let warn = |ip: String| {
            err(&cat!(
                "warning: ",
                ip,
                " is not currently assigned to this host ",
                "(gating it is a no-op until it is)\n"
            ))
        };
        for addr in &self.v4 {
            if !local4.contains(addr) {
                warn(glibc::format_ipv4(*addr));
            }
        }
        for addr in &self.v6 {
            if !local6.contains(addr) {
                warn(glibc::format_ipv6(addr));
            }
        }
    }
}

/// The source address the kernel would use to reach `probe`, or `None` if
/// there is no route.
fn default_source(probe: &str, any: &str) -> Option<IpAddr> {
    let sock = UdpSocket::bind(any).ok()?;
    sock.connect(probe).ok()?;
    Some(sock.local_addr().ok()?.ip())
}

fn explain_default_route(family: &str, ip: &str) {
    err(&cat!(
        "refusing to apply: ",
        ip,
        " is this host's default ",
        family,
        " source address.\n",
        "  The gate is stateless and ingress-only, so protecting it drops the\n",
        "  return path of every connection this host originates - including\n",
        "  the session you are reading this in.\n",
        "  Move the service to a dedicated address and put that in the config.\n",
    ));
}

/// The live protected set: the two maps the XDP program looks destinations
/// up in.
pub struct ProtectedSet {
    pub v4: MapFd<ProtectedKey4, ProtectedValue>,
    pub v6: MapFd<ProtectedKey6, ProtectedValue>,
}

/// What a reconcile changed.
pub struct Reconciled {
    pub added: usize,
    pub removed: usize,
}

/// The entries to delete: every key the declared set does not name, up to the
/// protected maps' capacity per family.
fn stale<K>(live: impl Iterator<Item = K>, declared: impl Fn(&K) -> bool) -> Vec<K> {
    let mut dead = Vec::new();
    for key in live {
        if !declared(&key) {
            dead.push(key);
            if dead.len() == PROTECTED_MAX_ENTRIES {
                break;
            }
        }
    }
    dead
}

fn report_update_failure(map: &str, ip: &str, errno: Errno) {
    err(&cat!(
        map,
        ": cannot protect ",
        ip,
        ": ",
        errno.message(),
        "\n"
    ));
    if errno.0 == E2BIG {
        err(&cat!(
            "  the map is full (max_entries ",
            PROTECTED_MAX_ENTRIES,
            "); raise it in xdpgate-common/src/lib.rs and rebuild.\n"
        ));
    }
}

impl ProtectedSet {
    /// Makes the protected set equal the declared set: adds what is missing,
    /// deletes what the file does not name. Idempotent. Adds run before
    /// deletes, so a reconcile that fails part-way can only leave more gated
    /// than declared, never less. Deletes are collected first, because
    /// deleting during bpf_map_get_next_key iteration is undefined.
    pub fn reconcile(&self, declared: &DeclaredSet) -> Result<Reconciled, Reported> {
        let one: ProtectedValue = 1;
        let mut added = 0;
        for addr in &declared.v4 {
            if self.v4.lookup(addr).is_ok() {
                continue;
            }
            if let Err(errno) = self.v4.update(addr, &one) {
                report_update_failure("protected_v4", &glibc::format_ipv4(*addr), errno);
                return Err(Reported);
            }
            added += 1;
        }
        for addr in &declared.v6 {
            let key = ProtectedKey6 { addr: *addr };
            if self.v6.lookup(&key).is_ok() {
                continue;
            }
            if let Err(errno) = self.v6.update(&key, &one) {
                report_update_failure("protected_v6", &glibc::format_ipv6(addr), errno);
                return Err(Reported);
            }
            added += 1;
        }

        let dead4 = stale(self.v4.keys(), |k| declared.has_v4(*k));
        let dead6 = stale(self.v6.keys(), |k| declared.has_v6(&k.addr));
        let removed = dead4.iter().filter(|k| self.v4.delete(k).is_ok()).count()
            + dead6.iter().filter(|k| self.v6.delete(k).is_ok()).count();
        Ok(Reconciled { added, removed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> u32 {
        u32::from_ne_bytes(text.parse::<std::net::Ipv4Addr>().unwrap().octets())
    }

    #[test]
    fn content_follows_c_string_rules() {
        assert_eq!(content(b"  192.0.2.1\t# web\r\n"), b"192.0.2.1");
        assert_eq!(content(b"192.0.2.1\0# hidden\n"), b"192.0.2.1");
        assert_eq!(content(b"\x00192.0.2.1\n"), b"");
        assert_eq!(content(b"# only a comment\n"), b"");
        assert_eq!(content(b"\r192.0.2.1"), b"\r192.0.2.1");
    }

    #[test]
    fn lines_classify_like_the_c() {
        assert_eq!(parse_line(b"192.0.2.1\n"), Line::V4(v4("192.0.2.1")));
        assert_eq!(parse_line(b"   \n"), Line::Blank);
        assert_eq!(parse_line(b"192.0.2.0/24\n"), Line::Cidr(b"192.0.2.0/24"));
        assert_eq!(parse_line(b"2001:db8::/64"), Line::Cidr(b"2001:db8::/64"));
        assert_eq!(
            parse_line(b"192.0.2.1 192.0.2.2"),
            Line::NotOneAddress(b"192.0.2.1 192.0.2.2")
        );
        assert_eq!(parse_line(b"192.0.2.256"), Line::BadV4(b"192.0.2.256"));
        assert_eq!(parse_line(b"2001:db8::g"), Line::BadV6(b"2001:db8::g"));
        let Line::V6(addr) = parse_line(b"::1.2.3.4") else {
            panic!()
        };
        assert_eq!(addr[12..], [1, 2, 3, 4]);
    }

    #[test]
    fn stale_entries_stop_at_the_map_capacity() {
        let live = 0..(PROTECTED_MAX_ENTRIES as u32 + 10);
        let dead = stale(live, |k| *k == 3);
        assert_eq!(dead.len(), PROTECTED_MAX_ENTRIES);
        assert!(!dead.contains(&3));
        assert_eq!(stale(1..4, |k| *k != 2), vec![2]);
    }
}
