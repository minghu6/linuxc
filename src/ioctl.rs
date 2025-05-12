////////////////////////////////////////////////////////////////////////////////
//// Constants

/* SIOC G(et) IF INDEX */
// pub const SIOCGIFINDEX: u64 = 0x8933;
// pub const SIOCGIFHWADDR: u64 = 0x8933;

////////////////////////////////////////////////////////////////////////////////
//// Structures

use std::{
    any::Any,
    ffi::c_void,
    os::fd::{AsRawFd, BorrowedFd},
};

use int_enum::IntEnum;
use libc::{c_int, SIOCGIFINDEX};

use crate::errno;

#[derive(Debug, IntEnum)]
#[repr(usize)]
#[non_exhaustive]
pub enum IoctlOpcode {
    SIOCGIFINDEX = 0x00008933,
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

////////////////////////////////////////////////////////////////////////////////
//// Functions

pub fn ioctl(fd: BorrowedFd, op: IoctlOpcode, anydata: Option<&dyn Any>) -> errno::Result<c_int> {
    unsafe {
        let argp = if let Some(any) = anydata {
            any as *const dyn Any as *const c_void
        }
        else {
            std::ptr::null()
        };

        let ret =
            libc::ioctl(fd.as_raw_fd(), Into::<usize>::into(op) as _, argp);

        if ret == -1 {
            Err(errno::last_os_error())
        }
        else {
            Ok(ret)
        }
    }
}
