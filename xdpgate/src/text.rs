//! Output the way the C's stdio wrote it.
//!
//! Arguments, paths and config lines are printed as the raw bytes they arrived
//! as, whatever their encoding, so messages are built as byte strings with
//! [`cat!`](crate::cat). Write errors are ignored, as printf ignores them.
//! stderr is written at once; stdout is held until [`exit`] when it is not a
//! terminal, as C buffers it, so the two streams interleave the same way when
//! they share a file.

use std::cell::RefCell;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::{IsTerminal, Write};
use std::os::unix::ffi::OsStrExt;

/// Something that can be appended to a message.
pub trait Piece {
    fn put(&self, out: &mut Vec<u8>);
}

impl<T: Piece + ?Sized> Piece for &T {
    fn put(&self, out: &mut Vec<u8>) {
        (**self).put(out)
    }
}

impl Piece for str {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes())
    }
}

impl Piece for String {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes())
    }
}

impl Piece for [u8] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self)
    }
}

impl<const N: usize> Piece for [u8; N] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self)
    }
}

impl Piece for Vec<u8> {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self)
    }
}

impl Piece for OsStr {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes())
    }
}

impl Piece for OsString {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes())
    }
}

impl Piece for CStr {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.to_bytes())
    }
}

impl Piece for CString {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.to_bytes())
    }
}

macro_rules! decimal_pieces {
    ($($t:ty)*) => {$(
        impl Piece for $t {
            fn put(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(self.to_string().as_bytes())
            }
        }
    )*};
}
decimal_pieces!(u16 u32 u64 usize i32 i64);

/// Concatenates pieces into one byte string: `cat!(path, ": ", errno.message())`.
#[macro_export]
macro_rules! cat {
    ($($piece:expr),* $(,)?) => {{
        let mut out: Vec<u8> = Vec::new();
        $( $crate::text::Piece::put(&$piece, &mut out); )*
        out
    }};
}

thread_local! {
    static HELD: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Writes to stdout.
pub fn out(bytes: &[u8]) {
    if std::io::stdout().is_terminal() {
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(bytes);
        let _ = stdout.flush();
    } else {
        HELD.with_borrow_mut(|held| held.extend_from_slice(bytes));
    }
}

/// Writes to stderr, in one write.
pub fn err(bytes: &[u8]) {
    let _ = std::io::stderr().lock().write_all(bytes);
}

/// Flushes stdout and exits with `code`.
pub fn exit(code: i32) -> ! {
    HELD.with_borrow_mut(|held| {
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(held);
        let _ = stdout.flush();
    });
    std::process::exit(code)
}
