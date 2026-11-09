//! Shared by the xdpgate tools. The only unsafe code is in the modules that
//! call C libraries, which allow it explicitly.
#![deny(unsafe_code)]

use std::ffi::{CStr, CString};

use xdpgate_common::PIN_DIR;

pub mod glibc;
pub mod libbpf;
pub mod protected;
pub mod text;

/// A failure already explained on stderr; all that is left is the exit code.
#[derive(Debug)]
pub struct Reported;

/// Where the map called `name` is pinned.
pub fn pin_path(name: &CStr) -> CString {
    let mut path = PIN_DIR.to_bytes().to_vec();
    path.push(b'/');
    path.extend_from_slice(name.to_bytes());
    CString::new(path).expect("map names contain no NUL")
}

/// `bytes` as C sees them: a string that ends at its first NUL.
pub fn c_string(bytes: &[u8]) -> CString {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    CString::new(&bytes[..end]).expect("cut at the first NUL")
}
