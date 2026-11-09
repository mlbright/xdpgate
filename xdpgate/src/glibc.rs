//! glibc, for the output the goldens freeze and the few calls std lacks.
//!
//! Error messages, addresses and expiry dates come from the same glibc
//! functions the C called (strerror, inet_pton/inet_ntop, localtime_r and
//! strftime), so they match byte for byte: Rust's own formatting differs, for
//! example `::102:304` against glibc's `::1.2.3.4`. All of xdpgate's unsafe
//! code for glibc is in this module.
#![allow(unsafe_code)]

use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::MaybeUninit;

pub use libc::{E2BIG, ENOENT};

// The libc crate does not declare these two for Linux.
unsafe extern "C" {
    fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
    fn inet_ntop(
        af: c_int,
        src: *const c_void,
        dst: *mut c_char,
        size: libc::socklen_t,
    ) -> *const c_char;
}

const INET6_ADDRSTRLEN: usize = 46;

/// An `errno` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(pub i32);

impl Errno {
    /// The calling thread's current `errno`.
    pub fn last() -> Errno {
        Errno(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    }

    /// `strerror(errno)`, e.g. "No such file or directory".
    pub fn message(self) -> Vec<u8> {
        // The tools are single-threaded, so strerror's static buffer is safe.
        unsafe { CStr::from_ptr(libc::strerror(self.0)) }
            .to_bytes()
            .to_vec()
    }
}

/// `inet_pton(AF_INET)`: the address as it sits in `s_addr`, network order.
pub fn parse_ipv4(text: &CStr) -> Option<u32> {
    let mut addr = MaybeUninit::<libc::in_addr>::uninit();
    let ok = unsafe { inet_pton(libc::AF_INET, text.as_ptr(), addr.as_mut_ptr().cast()) };
    (ok == 1).then(|| unsafe { addr.assume_init() }.s_addr)
}

/// `inet_pton(AF_INET6)`.
pub fn parse_ipv6(text: &CStr) -> Option<[u8; 16]> {
    let mut addr = [0u8; 16];
    let ok = unsafe { inet_pton(libc::AF_INET6, text.as_ptr(), addr.as_mut_ptr().cast()) };
    (ok == 1).then_some(addr)
}

fn ntop(family: i32, addr: *const c_void) -> String {
    let mut buf = [0 as c_char; INET6_ADDRSTRLEN];
    let p = unsafe { inet_ntop(family, addr, buf.as_mut_ptr(), buf.len() as u32) };
    assert!(!p.is_null(), "inet_ntop cannot fail on a full-size buffer");
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_str()
        .expect("inet_ntop writes ASCII")
        .to_owned()
}

/// `inet_ntop(AF_INET)` of an address in network order.
pub fn format_ipv4(addr: u32) -> String {
    ntop(libc::AF_INET, (&addr as *const u32).cast())
}

/// `inet_ntop(AF_INET6)`.
pub fn format_ipv6(addr: &[u8; 16]) -> String {
    ntop(libc::AF_INET6, addr.as_ptr().cast())
}

/// `clock_gettime(CLOCK_MONOTONIC)` in nanoseconds: the clock the XDP
/// program's `bpf_ktime_get_ns()` reads, and so the one grant expiries use.
pub fn monotonic_ns() -> u64 {
    let mut ts = MaybeUninit::<libc::timespec>::uninit();
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) };
    assert_eq!(rc, 0, "CLOCK_MONOTONIC is always available");
    let ts = unsafe { ts.assume_init() };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// `time(NULL)`.
pub fn wall_now() -> i64 {
    unsafe { libc::time(std::ptr::null_mut()) }
}

/// `localtime_r` then `strftime("%Y-%m-%d %H:%M:%S %Z")`, with the time zone
/// from `TZ` or /etc/localtime. `None` where localtime_r fails (a year that
/// does not fit an int).
pub fn local_time_text(when: i64) -> Option<Vec<u8>> {
    let mut tm = MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::localtime_r(&when, tm.as_mut_ptr()) }.is_null() {
        return None;
    }
    let mut buf = [0 as c_char; 64];
    let n = unsafe {
        libc::strftime(
            buf.as_mut_ptr(),
            buf.len(),
            c"%Y-%m-%d %H:%M:%S %Z".as_ptr(),
            tm.as_ptr(),
        )
    };
    Some(buf[..n].iter().map(|&c| c as u8).collect())
}

/// `access(path, R_OK) == 0`: readable by the real user, as the C checked.
pub fn readable(path: &CStr) -> bool {
    unsafe { libc::access(path.as_ptr(), libc::R_OK) == 0 }
}

/// Every address assigned to an interface on this host, from `getifaddrs`,
/// or `None` if it fails. IPv4 addresses are in network order.
pub fn assigned_addresses() -> Option<(Vec<u32>, Vec<[u8; 16]>)> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    let mut cur = head;
    while let Some(ifa) = unsafe { cur.as_ref() } {
        if let Some(sa) = unsafe { ifa.ifa_addr.as_ref() } {
            match i32::from(sa.sa_family) {
                libc::AF_INET => {
                    let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
                    v4.push(sin.sin_addr.s_addr);
                }
                libc::AF_INET6 => {
                    let sin6 = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in6>() };
                    v6.push(sin6.sin6_addr.s6_addr);
                }
                _ => {}
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    Some((v4, v6))
}

/// Puts SIGPIPE back to its default, which Rust's runtime ignores: like the C,
/// a tool writing into a closed pipe (`xdpgate-ctl list | head -1`) just
/// stops, instead of reporting a write error.
pub fn default_sigpipe() {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}
