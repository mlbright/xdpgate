//! Shared by the xdpgate tools. The only unsafe code is in the modules that
//! call C libraries, which allow it explicitly.
#![deny(unsafe_code)]

pub mod libbpf;
