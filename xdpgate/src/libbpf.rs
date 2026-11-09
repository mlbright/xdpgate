//! The system `libbpf.so.1`, declared by hand (ADR 0003).
//!
//! The declarations must match libbpf 1.3.0's ABI, the version Ubuntu 24.04
//! ships. All of xdpgate's unsafe code for libbpf is in this module; the rest
//! of the crate calls the safe wrappers.
#![allow(unsafe_code)]

use std::ffi::{CStr, c_char, c_int, c_void};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr::{self, NonNull};

use xdpgate_common::{GrantExpiry, GrantKey4, GrantKey6, ProtectedKey6};

use crate::glibc::Errno;

/// `BPF_PROG_TYPE_XDP` from `enum bpf_prog_type`.
pub const BPF_PROG_TYPE_XDP: u32 = 6;

/// XDP attach flags from linux/if_link.h.
pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1;
pub const XDP_FLAGS_SKB_MODE: u32 = 2;

#[repr(C)]
struct bpf_object {
    _opaque: [u8; 0],
}

#[repr(C)]
struct bpf_map {
    _opaque: [u8; 0],
}

#[repr(C)]
struct bpf_program {
    _opaque: [u8; 0],
}

/// `struct bpf_object_open_opts` as of libbpf 1.3.0.
#[repr(C)]
struct bpf_object_open_opts {
    sz: usize,
    object_name: *const c_char,
    relaxed_maps: bool,
    pin_root_path: *const c_char,
    _removed_attach_prog_fd: u32,
    kconfig: *const c_char,
    btf_custom_path: *const c_char,
    kernel_log_buf: *mut c_char,
    kernel_log_size: usize,
    kernel_log_level: u32,
    // C's trailing `size_t :0`. Spelled out because libbpf rejects the options
    // unless every byte past the last field it knows is zero, and Rust leaves
    // padding undefined.
    _tail_padding: u32,
}

const _: () = assert!(size_of::<bpf_object_open_opts>() == 80);

// Linked by its soname, so building needs only the libbpf1 package that
// iproute2 already pulls in, not libbpf-dev.
#[link(name = "libbpf.so.1", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn bpf_object__open_file(
        path: *const c_char,
        opts: *const bpf_object_open_opts,
    ) -> *mut bpf_object;
    fn bpf_object__close(obj: *mut bpf_object);
    fn bpf_object__load(obj: *mut bpf_object) -> c_int;
    fn bpf_object__find_map_by_name(obj: *const bpf_object, name: *const c_char) -> *mut bpf_map;
    fn bpf_object__next_map(obj: *const bpf_object, map: *const bpf_map) -> *mut bpf_map;
    fn bpf_object__find_program_by_name(
        obj: *const bpf_object,
        name: *const c_char,
    ) -> *mut bpf_program;

    fn bpf_map__name(map: *const bpf_map) -> *const c_char;
    fn bpf_map__type(map: *const bpf_map) -> u32;
    fn bpf_map__key_size(map: *const bpf_map) -> u32;
    fn bpf_map__value_size(map: *const bpf_map) -> u32;
    fn bpf_map__max_entries(map: *const bpf_map) -> u32;
    fn bpf_map__pin_path(map: *const bpf_map) -> *const c_char;
    fn bpf_map__fd(map: *const bpf_map) -> c_int;

    fn bpf_program__type(prog: *const bpf_program) -> u32;
    fn bpf_program__fd(prog: *const bpf_program) -> c_int;

    fn bpf_xdp_attach(ifindex: c_int, prog_fd: c_int, flags: u32, opts: *const c_void) -> c_int;
    fn bpf_xdp_detach(ifindex: c_int, flags: u32, opts: *const c_void) -> c_int;

    // The low-level map calls return a negative errno on failure.
    fn bpf_obj_get(pathname: *const c_char) -> c_int;
    fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
    fn bpf_map_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_map_delete_elem(fd: c_int, key: *const c_void) -> c_int;
    fn bpf_map_get_next_key(fd: c_int, key: *const c_void, next_key: *mut c_void) -> c_int;
    fn bpf_obj_get_info_by_fd(bpf_fd: c_int, info: *mut c_void, info_len: *mut u32) -> c_int;
}

/// The start of the kernel's `struct bpf_map_info`. The kernel fills in as
/// much of it as the caller asks for.
#[repr(C)]
#[derive(Default)]
struct bpf_map_info_head {
    r#type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
}

/// `BPF_ANY`: create the entry or overwrite it.
const BPF_ANY: u64 = 0;

/// A map key or value that crosses into the kernel as raw bytes.
///
/// # Safety
///
/// Only for types with no padding, for which every bit pattern is valid.
pub unsafe trait Pod: Copy {}

unsafe impl Pod for u8 {}
unsafe impl Pod for u32 {}
unsafe impl Pod for ProtectedKey6 {}
unsafe impl Pod for GrantKey4 {}
unsafe impl Pod for GrantKey6 {}
unsafe impl Pod for GrantExpiry {}

fn check(rc: c_int) -> Result<c_int, Errno> {
    if rc < 0 { Err(Errno(-rc)) } else { Ok(rc) }
}

/// Why a map could not be used.
#[derive(Debug)]
pub enum MapError {
    Errno(Errno),
    /// The map's key or value size is not the Rust type's. The kernel copies
    /// a map's own sizes in and out of the buffers it is given, so using it
    /// anyway would let it write past them. The C never checked.
    Layout {
        key_size: u32,
        value_size: u32,
        want_key_size: usize,
        want_value_size: usize,
    },
}

impl From<Errno> for MapError {
    fn from(errno: Errno) -> Self {
        MapError::Errno(errno)
    }
}

/// A BPF map, by file descriptor, with its key and value types. Every way
/// of getting one first checks the map's key and value sizes.
pub struct MapFd<K, V> {
    fd: OwnedFd,
    _kv: PhantomData<fn() -> (K, V)>,
}

impl<K: Pod, V: Pod> MapFd<K, V> {
    /// Opens the map pinned at `path`.
    pub fn open_pinned(path: &CStr) -> Result<Self, MapError> {
        let fd = check(unsafe { bpf_obj_get(path.as_ptr()) })?;
        Self::checked(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// A handle on a map of a loaded [`Object`], usable after it closes.
    pub fn from_object(map: &Map<'_>) -> Result<Self, MapError> {
        let fd = map.fd()?.try_clone_to_owned();
        Self::checked(fd.map_err(|e| Errno(e.raw_os_error().unwrap_or(0)))?)
    }

    fn checked(fd: OwnedFd) -> Result<Self, MapError> {
        let mut info = bpf_map_info_head::default();
        let mut len = size_of::<bpf_map_info_head>() as u32;
        check(unsafe { bpf_obj_get_info_by_fd(fd.as_raw_fd(), (&raw mut info).cast(), &mut len) })?;
        if info.key_size as usize != size_of::<K>() || info.value_size as usize != size_of::<V>() {
            return Err(MapError::Layout {
                key_size: info.key_size,
                value_size: info.value_size,
                want_key_size: size_of::<K>(),
                want_value_size: size_of::<V>(),
            });
        }
        Ok(MapFd {
            fd,
            _kv: PhantomData,
        })
    }

    pub fn lookup(&self, key: &K) -> Result<V, Errno> {
        let mut value = MaybeUninit::<V>::uninit();
        check(unsafe {
            bpf_map_lookup_elem(
                self.fd.as_raw_fd(),
                (key as *const K).cast(),
                value.as_mut_ptr().cast(),
            )
        })?;
        Ok(unsafe { value.assume_init() })
    }

    /// Creates or overwrites the entry for `key`.
    pub fn update(&self, key: &K, value: &V) -> Result<(), Errno> {
        check(unsafe {
            bpf_map_update_elem(
                self.fd.as_raw_fd(),
                (key as *const K).cast(),
                (value as *const V).cast(),
                BPF_ANY,
            )
        })?;
        Ok(())
    }

    pub fn delete(&self, key: &K) -> Result<(), Errno> {
        check(unsafe { bpf_map_delete_elem(self.fd.as_raw_fd(), (key as *const K).cast()) })?;
        Ok(())
    }

    /// The key after `key` in the kernel's hash order, or the first key.
    pub fn next_key(&self, key: Option<&K>) -> Result<K, Errno> {
        let prev = key.map_or(ptr::null(), |k| (k as *const K).cast());
        let mut next = MaybeUninit::<K>::uninit();
        check(unsafe {
            bpf_map_get_next_key(self.fd.as_raw_fd(), prev, next.as_mut_ptr().cast())
        })?;
        Ok(unsafe { next.assume_init() })
    }

    /// Every key, in the kernel's hash order. Ends at the last key or at the
    /// first error, as the C's loops did. Each key is fetched only when
    /// asked for.
    pub fn keys(&self) -> impl Iterator<Item = K> + '_ {
        let mut prev: Option<K> = None;
        std::iter::from_fn(move || {
            let next = self.next_key(prev.as_ref()).ok()?;
            prev = Some(next);
            Some(next)
        })
    }
}

/// An opened BPF object file. Closing it (on drop) detaches nothing: an
/// attached program and pinned maps outlive it.
pub struct Object {
    ptr: NonNull<bpf_object>,
}

impl Object {
    /// Opens `path` without loading it. Maps that ask to be pinned by name get
    /// their pin paths under `pin_root`.
    pub fn open(path: &CStr, pin_root: &CStr) -> Result<Object, Errno> {
        let opts = bpf_object_open_opts {
            sz: size_of::<bpf_object_open_opts>(),
            object_name: ptr::null(),
            relaxed_maps: false,
            pin_root_path: pin_root.as_ptr(),
            _removed_attach_prog_fd: 0,
            kconfig: ptr::null(),
            btf_custom_path: ptr::null(),
            kernel_log_buf: ptr::null_mut(),
            kernel_log_size: 0,
            kernel_log_level: 0,
            _tail_padding: 0,
        };
        // libbpf 1.x returns NULL and sets errno.
        let obj = unsafe { bpf_object__open_file(path.as_ptr(), &opts) };
        NonNull::new(obj)
            .map(|ptr| Object { ptr })
            .ok_or_else(Errno::last)
    }

    /// Every map the object defines, in the object's order.
    pub fn maps(&self) -> impl Iterator<Item = Map<'_>> {
        let obj = self.ptr.as_ptr();
        let mut prev: *const bpf_map = ptr::null();
        std::iter::from_fn(move || {
            let next = NonNull::new(unsafe { bpf_object__next_map(obj, prev) })?;
            prev = next.as_ptr();
            Some(Map {
                ptr: next,
                _obj: PhantomData,
            })
        })
    }

    /// Creates the maps (or reuses their pins, if every parameter matches),
    /// pins them, and loads the programs into the kernel.
    pub fn load(&mut self) -> Result<(), Errno> {
        check(unsafe { bpf_object__load(self.ptr.as_ptr()) })?;
        Ok(())
    }

    pub fn find_map(&self, name: &CStr) -> Option<Map<'_>> {
        let map = unsafe { bpf_object__find_map_by_name(self.ptr.as_ptr(), name.as_ptr()) };
        NonNull::new(map).map(|ptr| Map {
            ptr,
            _obj: PhantomData,
        })
    }

    pub fn find_program(&self, name: &CStr) -> Option<Program<'_>> {
        let prog = unsafe { bpf_object__find_program_by_name(self.ptr.as_ptr(), name.as_ptr()) };
        NonNull::new(prog).map(|ptr| Program {
            ptr,
            _obj: PhantomData,
        })
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        unsafe { bpf_object__close(self.ptr.as_ptr()) }
    }
}

/// A map defined by an open [`Object`].
#[derive(Clone, Copy)]
pub struct Map<'obj> {
    ptr: NonNull<bpf_map>,
    _obj: PhantomData<&'obj Object>,
}

impl<'obj> Map<'obj> {
    pub fn name(&self) -> &'obj CStr {
        unsafe { CStr::from_ptr(bpf_map__name(self.ptr.as_ptr())) }
    }

    /// The `enum bpf_map_type` value.
    pub fn map_type(&self) -> u32 {
        unsafe { bpf_map__type(self.ptr.as_ptr()) }
    }

    pub fn key_size(&self) -> u32 {
        unsafe { bpf_map__key_size(self.ptr.as_ptr()) }
    }

    pub fn value_size(&self) -> u32 {
        unsafe { bpf_map__value_size(self.ptr.as_ptr()) }
    }

    pub fn max_entries(&self) -> u32 {
        unsafe { bpf_map__max_entries(self.ptr.as_ptr()) }
    }

    /// The map's file descriptor, once the object is loaded.
    pub fn fd(&self) -> Result<BorrowedFd<'obj>, Errno> {
        let fd = check(unsafe { bpf_map__fd(self.ptr.as_ptr()) })?;
        Ok(unsafe { BorrowedFd::borrow_raw(fd) })
    }

    /// Where libbpf will pin the map on load, or `None` if it won't.
    pub fn pin_path(&self) -> Option<&'obj CStr> {
        let path = unsafe { bpf_map__pin_path(self.ptr.as_ptr()) };
        (!path.is_null()).then(|| unsafe { CStr::from_ptr(path) })
    }
}

/// A program defined by an open [`Object`].
#[derive(Clone, Copy)]
pub struct Program<'obj> {
    ptr: NonNull<bpf_program>,
    _obj: PhantomData<&'obj Object>,
}

impl<'obj> Program<'obj> {
    /// The `enum bpf_prog_type` value.
    pub fn prog_type(&self) -> u32 {
        unsafe { bpf_program__type(self.ptr.as_ptr()) }
    }

    /// The program's file descriptor, once the object is loaded.
    pub fn fd(&self) -> Result<BorrowedFd<'obj>, Errno> {
        let fd = check(unsafe { bpf_program__fd(self.ptr.as_ptr()) })?;
        Ok(unsafe { BorrowedFd::borrow_raw(fd) })
    }
}

/// Attaches `prog` to the interface through netlink, as the C did, so either
/// version's detach removes either version's gate. It stays attached after
/// this process exits.
pub fn xdp_attach(ifindex: u32, prog: BorrowedFd<'_>, flags: u32) -> Result<(), Errno> {
    check(unsafe { bpf_xdp_attach(ifindex as c_int, prog.as_raw_fd(), flags, ptr::null()) })?;
    Ok(())
}

pub fn xdp_detach(ifindex: u32, flags: u32) -> Result<(), Errno> {
    check(unsafe { bpf_xdp_detach(ifindex as c_int, flags, ptr::null()) })?;
    Ok(())
}
