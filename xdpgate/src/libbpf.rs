//! The system `libbpf.so.1`, declared by hand (ADR 0002).
//!
//! The declarations must match libbpf 1.3.0's ABI, the version Ubuntu 24.04
//! ships. All of xdpgate's unsafe code for libbpf is in this module; the rest
//! of the crate calls the safe wrappers.
#![allow(unsafe_code)]

use std::ffi::{CStr, c_char};
use std::io;
use std::marker::PhantomData;
use std::ptr::{self, NonNull};

/// `BPF_PROG_TYPE_XDP` from `enum bpf_prog_type`.
pub const BPF_PROG_TYPE_XDP: u32 = 6;

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

    fn bpf_program__type(prog: *const bpf_program) -> u32;
}

/// An opened BPF object file. Closing it (on drop) detaches nothing: an
/// attached program and pinned maps outlive it.
pub struct Object {
    ptr: NonNull<bpf_object>,
}

impl Object {
    /// Opens `path` without loading it. Maps that ask to be pinned by name get
    /// their pin paths under `pin_root`.
    pub fn open(path: &CStr, pin_root: &CStr) -> io::Result<Object> {
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
            .ok_or_else(io::Error::last_os_error)
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

impl Program<'_> {
    /// The `enum bpf_prog_type` value.
    pub fn prog_type(&self) -> u32 {
        unsafe { bpf_program__type(self.ptr.as_ptr()) }
    }
}
