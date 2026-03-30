use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
/// FFI-stable view of one pcapng interface's parsed metadata.
///
/// Instances of this type are copied between Rust and C by value. All fields
/// are plain integers to preserve ABI stability at the FFI boundary.
pub struct pcapng_rs_interface {
    pub snaplen: u32,
    pub tsresol: u64,
    pub scale_type: i32,
    pub scale_factor: u64,
    pub tsoffset: i64,
}

#[allow(non_camel_case_types)]
/// Opaque parser state shared with C.
///
/// This owns dynamically sized memory that previously lived in C:
/// - `block_buf`: scratch space used for block reads and parsing.
/// - `interfaces`: parsed Interface Description Block metadata.
///
/// The C side treats this as an opaque handle and never dereferences it.
pub struct pcapng_rs_state {
    block_buf: Vec<u8>,
    interfaces: Vec<pcapng_rs_interface>,
}

/// Write an error message into a C-owned error buffer when one is provided.
fn write_err(errbuf: *mut c_char, errbuf_len: usize, msg: &str) {
    if errbuf.is_null() || errbuf_len == 0 {
        return;
    }

    let bytes = msg.as_bytes();
    let copy_len = bytes.len().min(errbuf_len.saturating_sub(1));

    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), errbuf as *mut u8, copy_len);
        *errbuf.add(copy_len) = 0;
    }
}

fn u32_to_usize_checked(value: u32, errbuf: *mut c_char, errbuf_len: usize, what: &str) -> Result<usize, ()> {
    match usize::try_from(value) {
        Ok(converted) => Ok(converted),
        Err(_) => {
            write_err(errbuf, errbuf_len, what);
            Err(())
        }
    }
}

#[no_mangle]
/// Allocate a new opaque parser state for C.
///
/// Returns a null pointer on allocation failure or if a panic occurs.
///
/// # Safety
/// The returned pointer must be released exactly once with
/// [`pcapng_rs_state_free`].
pub extern "C" fn pcapng_rs_state_new() -> *mut pcapng_rs_state {
    match catch_unwind(AssertUnwindSafe(|| {
        Box::into_raw(Box::new(pcapng_rs_state {
            block_buf: Vec::new(),
            interfaces: Vec::new(),
        }))
    })) {
        Ok(state) => state,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
/// Free a parser state previously allocated by [`pcapng_rs_state_new`].
///
/// # Safety
/// `state` must be null or a pointer returned by [`pcapng_rs_state_new`] that
/// has not been freed yet.
pub extern "C" fn pcapng_rs_state_free(state: *mut pcapng_rs_state) {
    if state.is_null() {
        return;
    }

    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(state));
    }));
}

#[no_mangle]
/// Ensure the internal block buffer can hold `required_len` bytes.
///
/// Returns 0 on success and -1 on validation failure, allocation failure, or
/// panic.
///
/// # Safety
/// - `state` must be a valid pointer returned by [`pcapng_rs_state_new`].
/// - `errbuf` may be null; otherwise it must point to writable storage of
///   at least `errbuf_len` bytes.
pub extern "C" fn pcapng_rs_ensure_block_capacity(
    state: *mut pcapng_rs_state,
    required_len: u32,
    max_blocksize: u32,
    errbuf: *mut c_char,
    errbuf_len: usize,
) -> i32 {
    if state.is_null() {
        write_err(errbuf, errbuf_len, "pcapng rust state is null");
        return -1;
    }

    match catch_unwind(AssertUnwindSafe(|| {
        if required_len > max_blocksize {
            write_err(errbuf, errbuf_len, "pcapng block size exceeds configured maximum");
            return -1;
        }

        let needed = match u32_to_usize_checked(
            required_len,
            errbuf,
            errbuf_len,
            "pcapng block size does not fit in platform usize",
        ) {
            Ok(value) => value,
            Err(()) => return -1,
        };

        let st = unsafe { &mut *state };

        if st.block_buf.len() < needed {
            if st.block_buf.try_reserve_exact(needed - st.block_buf.len()).is_err() {
                write_err(errbuf, errbuf_len, "out of memory");
                return -1;
            }
            st.block_buf.resize(needed, 0);
        } else {
            st.block_buf.truncate(needed);
        }

        0
    })) {
        Ok(rc) => rc,
        Err(_) => {
            write_err(errbuf, errbuf_len, "internal rust panic in ensure_block_capacity");
            -1
        }
    }
}

#[no_mangle]
/// Return a mutable pointer to the block buffer bytes.
///
/// Returns null when state is null, the buffer is empty, or a panic occurs.
///
/// # Safety
/// `state` must be null or a valid pointer returned by
/// [`pcapng_rs_state_new`].
pub extern "C" fn pcapng_rs_block_buffer_ptr(state: *mut pcapng_rs_state) -> *mut u8 {
    if state.is_null() {
        return ptr::null_mut();
    }

    match catch_unwind(AssertUnwindSafe(|| {
        let st = unsafe { &mut *state };
        if st.block_buf.is_empty() {
            ptr::null_mut()
        } else {
            st.block_buf.as_mut_ptr()
        }
    })) {
        Ok(ptr_out) => ptr_out,
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
/// Return the current block buffer length, saturated to `u32::MAX`.
///
/// Returns 0 if `state` is null or if a panic occurs.
///
/// # Safety
/// `state` must be null or a valid pointer returned by
/// [`pcapng_rs_state_new`].
pub extern "C" fn pcapng_rs_block_buffer_len(state: *const pcapng_rs_state) -> u32 {
    if state.is_null() {
        return 0;
    }

    match catch_unwind(AssertUnwindSafe(|| {
        let st = unsafe { &*state };
        u32::try_from(st.block_buf.len()).unwrap_or(u32::MAX)
    })) {
        Ok(len) => len,
        Err(_) => 0,
    }
}

#[no_mangle]
/// Drop all per-interface metadata from the current section.
///
/// # Safety
/// `state` must be null or a valid pointer returned by
/// [`pcapng_rs_state_new`].
pub extern "C" fn pcapng_rs_interfaces_clear(state: *mut pcapng_rs_state) {
    if state.is_null() {
        return;
    }

    let _ = catch_unwind(AssertUnwindSafe(|| {
        let st = unsafe { &mut *state };
        st.interfaces.clear();
    }));
}

#[no_mangle]
/// Append one parsed interface metadata record.
///
/// Returns 0 on success and -1 on validation failure, allocation failure, or
/// panic.
///
/// # Safety
/// - `state` must be a valid pointer returned by [`pcapng_rs_state_new`].
/// - `errbuf` may be null; otherwise it must point to writable storage of
///   at least `errbuf_len` bytes.
pub extern "C" fn pcapng_rs_interface_push(
    state: *mut pcapng_rs_state,
    snaplen: u32,
    tsresol: u64,
    scale_type: i32,
    scale_factor: u64,
    tsoffset: i64,
    errbuf: *mut c_char,
    errbuf_len: usize,
) -> i32 {
    if state.is_null() {
        write_err(errbuf, errbuf_len, "pcapng rust state is null");
        return -1;
    }

    match catch_unwind(AssertUnwindSafe(|| {
        let st = unsafe { &mut *state };

        if u32::try_from(st.interfaces.len()).is_err() {
            write_err(errbuf, errbuf_len, "too many interfaces in file");
            return -1;
        }

        if st.interfaces.try_reserve(1).is_err() {
            write_err(errbuf, errbuf_len, "out of memory for per-interface information");
            return -1;
        }

        st.interfaces.push(pcapng_rs_interface {
            snaplen,
            tsresol,
            scale_type,
            scale_factor,
            tsoffset,
        });
        0
    })) {
        Ok(rc) => rc,
        Err(_) => {
            write_err(errbuf, errbuf_len, "internal rust panic while appending interface");
            -1
        }
    }
}

#[no_mangle]
/// Return number of parsed interfaces, saturated to `u32::MAX`.
///
/// Returns 0 if `state` is null or if a panic occurs.
///
/// # Safety
/// `state` must be null or a valid pointer returned by
/// [`pcapng_rs_state_new`].
pub extern "C" fn pcapng_rs_interface_count(state: *const pcapng_rs_state) -> u32 {
    if state.is_null() {
        return 0;
    }

    match catch_unwind(AssertUnwindSafe(|| {
        let st = unsafe { &*state };
        u32::try_from(st.interfaces.len()).unwrap_or(u32::MAX)
    })) {
        Ok(count) => count,
        Err(_) => 0,
    }
}

#[no_mangle]
/// Copy one interface metadata record to C.
///
/// Returns 0 on success and -1 on null pointers, out-of-range index, or panic.
///
/// # Safety
/// - `state` must be a valid pointer returned by [`pcapng_rs_state_new`].
/// - `out_iface` must be a valid writable pointer to
///   [`pcapng_rs_interface`].
pub extern "C" fn pcapng_rs_interface_get(
    state: *const pcapng_rs_state,
    index: u32,
    out_iface: *mut pcapng_rs_interface,
) -> i32 {
    if state.is_null() || out_iface.is_null() {
        return -1;
    }

    match catch_unwind(AssertUnwindSafe(|| {
        let st = unsafe { &*state };
        let index = match usize::try_from(index) {
            Ok(value) => value,
            Err(_) => return -1,
        };

        if let Some(iface) = st.interfaces.get(index) {
            unsafe {
                *out_iface = *iface;
            }
            0
        } else {
            -1
        }
    })) {
        Ok(rc) => rc,
        Err(_) => -1,
    }
}
