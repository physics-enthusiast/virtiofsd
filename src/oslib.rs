// SPDX-License-Identifier: BSD-3-Clause

use std::ffi::{CStr, CString};
use std::io::{Error, Result};
use std::os::unix::io::{AsRawFd, RawFd};

// A helper function that check the return value of a C function call
// and wraps it in a `Result` type, returning the `errno` code as `Err`.
fn check_retval<T: From<i8> + PartialEq>(t: T) -> Result<T> {
    if t == T::from(-1_i8) {
        Err(Error::last_os_error())
    } else {
        Ok(t)
    }
}

/// Simple object to collect basic facts about the OS,
/// such as available syscalls.
pub struct OsFacts {
    pub has_openat2: bool,
}

#[allow(clippy::new_without_default)]
impl OsFacts {
    /// This object should only be constructed using new.
    #[must_use]
    pub fn new() -> Self {
        // Checking for `openat2()` since it first appeared in Linux 5.6.
        // SAFETY: all-zero byte-pattern is a valid `libc::open_how`
        let how: libc::open_how = unsafe { std::mem::zeroed() };
        let cwd = CString::new(".").unwrap();
        // SAFETY: `cwd.as_ptr()` points to a valid NUL-terminated string,
        // and the `how` pointer is a valid pointer to an `open_how` struct.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                cwd.as_ptr(),
                std::ptr::addr_of!(how),
                std::mem::size_of::<libc::open_how>(),
            )
        };

        let has_openat2 = fd >= 0;
        if has_openat2 {
            // SAFETY: `fd` is an open file descriptor
            unsafe {
                libc::close(fd as libc::c_int);
            }
        }

        Self { has_openat2 }
    }
}

/// Safe wrapper for `mount(2)`
///
/// # Errors
///
/// Will return `Err(errno)` if `mount(2)` fails.
/// Each filesystem type may have its own special errors and its own special behavior,
/// see `mount(2)` and the linux source kernel for details.
///
/// # Panics
///
/// This function panics if the strings `source`, `target` or `fstype` contain an internal 0 byte.
pub fn mount(source: Option<&str>, target: &str, fstype: Option<&str>, flags: u64) -> Result<()> {
    let source = CString::new(source.unwrap_or("")).unwrap();
    let source = source.as_ptr();

    let target = CString::new(target).unwrap();
    let target = target.as_ptr();

    let fstype = CString::new(fstype.unwrap_or("")).unwrap();
    let fstype = fstype.as_ptr();

    // Safety: `source`, `target` or `fstype` are a valid C string pointers
    check_retval(unsafe { libc::mount(source, target, fstype, flags, std::ptr::null()) })?;
    Ok(())
}

/// Safe wrapper for `umount2(2)`
///
/// # Errors
///
/// Will return `Err(errno)` if `umount2(2)` fails.
/// Each filesystem type may have its own special errors and its own special behavior,
/// see `umount2(2)` and the linux source kernel for details.
///
/// # Panics
///
/// This function panics if the strings `target` contains an internal 0 byte.
pub fn umount2(target: &str, flags: i32) -> Result<()> {
    let target = CString::new(target).unwrap();
    let target = target.as_ptr();

    // Safety: `target` is a valid C string pointer
    check_retval(unsafe { libc::umount2(target, flags) })?;
    Ok(())
}

/// Safe wrapper for `fchdir(2)`
///
/// # Errors
///
/// Will return `Err(errno)` if `fchdir(2)` fails.
/// Each filesystem type may have its own special errors, see `fchdir(2)` for details.
pub fn fchdir(fd: RawFd) -> Result<()> {
    check_retval(unsafe { libc::fchdir(fd) })?;
    Ok(())
}

/// Safe wrapper for `umask(2)`
pub fn umask(mask: u32) -> u32 {
    // SAFETY: this call doesn't modify any memory and there is no need
    // to check the return value because this system call always succeeds.
    unsafe { libc::umask(mask) }
}

/// An RAII implementation of a scoped file mode creation mask (umask), it set the
/// new umask. When this structure is dropped (falls out of scope), it set the previous
/// value of the mask.
pub struct ScopedUmask {
    umask: libc::mode_t,
}

impl ScopedUmask {
    pub fn new(new_umask: u32) -> Self {
        Self {
            umask: umask(new_umask),
        }
    }
}

impl Drop for ScopedUmask {
    fn drop(&mut self) {
        umask(self.umask);
    }
}

/// Safe wrapper around `openat(2)`.
///
/// # Errors
///
/// Will return `Err(errno)` if `openat(2)` fails,
/// see `openat(2)` for details.
pub fn openat(dir: &impl AsRawFd, pathname: &CStr, flags: i32, mode: Option<u32>) -> Result<RawFd> {
    let mode = u64::from(mode.unwrap_or(0));

    // SAFETY: `pathname` points to a valid NUL-terminated string.
    // However, the caller must ensure that `dir` can provide a valid file descriptor.
    check_retval(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            pathname.as_ptr(),
            flags as libc::c_int,
            mode,
        )
    })
}

/// An utility function that uses `openat2(2)` to restrict the how the provided pathname
/// is resolved. It uses the following flags:
/// - `RESOLVE_IN_ROOT`: Treat the directory referred to by dirfd as the root directory while
/// resolving pathname. This has the effect as though virtiofsd had used chroot(2) to modify its
/// root directory to dirfd.
/// - `RESOLVE_NO_MAGICLINKS`: Disallow all magic-link (i.e., proc(2) link-like files) resolution
/// during path resolution.
///
/// Additionally, the flags `O_NOFOLLOW` and `O_CLOEXEC` are added.
///
/// # Error
///
/// Will return `Err(errno)` if `openat2(2)` fails, see the man page for details.
///
/// # Safety
///
/// The caller must ensure that dirfd is a valid file descriptor.
pub fn do_open_relative_to(
    dir: &impl AsRawFd,
    pathname: &CStr,
    flags: i32,
    mode: Option<u32>,
) -> Result<RawFd> {
    // `openat2(2)` returns an error if `how.mode` contains bits other than those in range 07777,
    // let's ignore the extra bits to be compatible with `openat(2)`.
    let mode = u64::from(mode.unwrap_or(0)) & 0o7777;

    // SAFETY: all-zero byte-pattern represents a valid `libc::open_how`
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
    how.flags = flags as u64;
    how.mode = mode;

    // SAFETY: `pathname` points to a valid NUL-terminated string, and the `how` pointer is a valid
    // pointer to an `open_how` struct. However, the caller must ensure that `dir` can provide a
    // valid file descriptor (this can be changed to BorrowedFd).
    check_retval(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            pathname.as_ptr(),
            std::ptr::addr_of!(how),
            std::mem::size_of::<libc::open_how>(),
        )
    } as RawFd)
}
