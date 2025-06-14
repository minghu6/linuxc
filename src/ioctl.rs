use std::{
    any::Any,
    ffi::{ c_void, c_int },
    os::fd::{AsRawFd, BorrowedFd},
};

////////////////////////////////////////////////////////////////////////////////
//// Constants


////////////////////////////////////////////////////////////////////////////////
//// Structures

use int_enum::IntEnum;

use crate::errno;

#[derive(Debug, IntEnum)]
#[repr(usize)]
#[non_exhaustive]
pub enum IoctlOpcode {
    /// get ifindex
    GetIfaceIndex = 0x00008933,
    /// get hardware address
    GetIfaceHwAddr = 0x00008927,
    /// get ipv4 address
    GetIfaceAddr = 0x00008915,
    /// get ethernet MTU
    GetIfMTU = 0x00008921,
    
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

////////////////////////////////////////////////////////////////////////////////
//// Functions

pub fn ioctl(fd: BorrowedFd, op: IoctlOpcode, anydata: Option<&mut dyn Any>) -> errno::Result<c_int> {
    unsafe {
        let argp = if let Some(any) = anydata {
            any as *mut dyn Any as *mut c_void
        }
        else {
            std::ptr::null_mut()
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
