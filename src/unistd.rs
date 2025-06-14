use std::os::fd::{AsRawFd, BorrowedFd};

use libc::{size_t};

use crate::errno;

////////////////////////////////////////////////////////////////////////////////
//// Structures


////////////////////////////////////////////////////////////////////////////////
//// Functions


pub fn read(
    sock: BorrowedFd,
    buf: &mut [u8],
    count: size_t,
) -> errno::Result<size_t> {
    let ret = unsafe {
        libc::read(sock.as_raw_fd(), buf.as_mut_ptr() as _, count)
    };

    if ret == -1 {
        Err(errno::last_os_error())?
    }

    Ok(ret as size_t)
}
