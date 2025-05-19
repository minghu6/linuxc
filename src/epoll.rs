use std::{
    ffi::{c_int, c_void},
    fmt::Debug,
    ops::{BitAnd, BitOr, BitOrAssign},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
};

use libc::{
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, epoll_event,
};
use m6tobytes::derive_to_bits;
use strum::{EnumIter, IntoEnumIterator};

use crate::{errno, signal::SignalSet};


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EpollEvent {
    pub events: EpollEvents,
    pub data: EpollData,
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EpollEvents(i32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
#[derive_to_bits(i32)]
#[repr(i32)]
pub enum EpollFlag {
    In = 0x1,
    Pri = 0x2,
    Out = 0x4,
    Err = 0x8,
    Hup = 0x10,
    Rdnorm = 0x40,
    Rdbrand = 0x80,
    Wrnorm = 0x100,
    Wrband = 0x200,
    Msg = 0x400,
    Rdhup = 0x2000,
    Exclusive = 0x1000_0000,
    Wakeup = 0x2000_0000,
    Oneshot = 0x4000_0000,
    /// 符号溢出但不影响
    Et = 0x8000_0000u32 as i32,
}

/// unsafe structure
#[derive(Clone, Copy)]
pub union EpollData {
    pub fd: c_int,
    pub u64: u64,
    pub u32: u32,
    pub ptr: *mut c_void,
}

pub struct Epoll {
    epfd: OwnedFd,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl Epoll {
    /// create with EPOLL_CLOEXEC flag
    pub fn create() -> errno::Result<Self> {
        let ret = unsafe { libc::epoll_create1(EPOLL_CLOEXEC) };

        if ret == -1 {
            Err(errno::last_os_error())?
        }

        Ok(Self {
            epfd: unsafe { OwnedFd::from_raw_fd(ret) },
        })
    }

    pub fn insert(&mut self, fd: BorrowedFd, event: EpollEvent) -> errno::Result<()> {
        let ret = unsafe {
            libc::epoll_ctl(
                self.epfd.as_raw_fd(),
                EPOLL_CTL_ADD,
                fd.as_raw_fd(),
                &event as *const EpollEvent as *mut epoll_event,
            )
        };

        if ret == -1 {
            Err(errno::last_os_error())?
        }

        Ok(())
    }

    pub fn pwait<'a>(
        &self,
        events: &'a mut [EpollEvent],
        timeout: c_int,
        sigmask: SignalSet,
    ) -> errno::Result<&'a [EpollEvent]> {
        epoll_pwait(self.epfd.as_fd(), events, timeout, sigmask)
    }
}

impl Default for EpollEvent {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl BitAnd<EpollFlag> for EpollEvent {
    type Output = bool;

    fn bitand(self, rhs: EpollFlag) -> Self::Output {
        self.events & rhs
    }
}

impl BitAnd<EpollFlag> for &EpollEvent {
    type Output = bool;

    fn bitand(self, rhs: EpollFlag) -> Self::Output {
        self.events & rhs
    }
}

impl PartialEq<EpollFlag> for EpollEvent {
    fn eq(&self, other: &EpollFlag) -> bool {
        self.events.eq(other)
    }
}

impl PartialOrd<EpollFlag> for EpollEvent {
    fn partial_cmp(&self, other: &EpollFlag) -> Option<std::cmp::Ordering> {
        self.events.partial_cmp(other)
    }
}

impl PartialEq<EpollFlag> for &EpollEvent {
    fn eq(&self, other: &EpollFlag) -> bool {
        self.events.eq(other)
    }
}

impl PartialOrd<EpollFlag> for &EpollEvent {
    fn partial_cmp(&self, other: &EpollFlag) -> Option<std::cmp::Ordering> {
        self.events.partial_cmp(other)
    }
}

impl EpollData {
    pub fn new_as_fd(fd: c_int) -> Self {
        Self { fd }
    }
}

impl Debug for EpollData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", unsafe { self.u64 })
    }
}

impl BitAnd<EpollFlag> for EpollEvents {
    type Output = bool;

    fn bitand(self, rhs: EpollFlag) -> Self::Output {
        self.0 & rhs.to_bits() != 0
    }
}

impl BitAnd<EpollFlag> for &EpollEvents {
    type Output = bool;

    fn bitand(self, rhs: EpollFlag) -> Self::Output {
        self.0 & rhs.to_bits() != 0
    }
}

impl BitOr<EpollFlag> for EpollEvents {
    type Output = Self;

    fn bitor(self, rhs: EpollFlag) -> Self::Output {
        Self(self.0 | rhs.to_bits())
    }
}

impl BitOrAssign<EpollFlag> for &mut EpollEvents {
    fn bitor_assign(&mut self, rhs: EpollFlag) {
        self.0 |= rhs.to_bits()
    }
}

impl PartialEq<EpollFlag> for EpollEvents {
    fn eq(&self, other: &EpollFlag) -> bool {
        self.0.eq(&other.to_bits())
    }
}

impl PartialOrd<EpollFlag> for EpollEvents {
    fn partial_cmp(&self, other: &EpollFlag) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.to_bits())
    }
}

impl PartialEq<EpollFlag> for &EpollEvents {
    fn eq(&self, other: &EpollFlag) -> bool {
        self.0.eq(&other.to_bits())
    }
}

impl PartialOrd<EpollFlag> for &EpollEvents {
    fn partial_cmp(&self, other: &EpollFlag) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.to_bits())
    }
}

impl EpollEvents {
    pub fn new() -> Self {
        Self(0)
    }

    ///
    /// 0x1
    pub fn epoll_in(self) -> Self {
        self | EpollFlag::In
    }

    /// for monitor our-of-brand data
    ///
    /// 0x2
    pub fn epoll_pri(self) -> Self {
        self | EpollFlag::Pri
    }

    /// 0x4
    pub fn epoll_out(self) -> Self {
        self | EpollFlag::Out
    }

    ///
    /// Err (auto registered by kernel)
    ///
    /// 0x8
    pub fn epoll_err(self) -> Self {
        self | EpollFlag::Err
    }

    /// fd complete hup
    pub fn epoll_hup(self) -> Self {
        self | EpollFlag::Hup
    }

    pub fn epoll_rdnorm(self) -> Self {
        self | EpollFlag::Rdnorm
    }

    pub fn epoll_rdbrand(self) -> Self {
        self | EpollFlag::Rdbrand
    }

    pub fn epoll_wrnorm(self) -> Self {
        self | EpollFlag::Wrnorm
    }

    pub fn epoll_wrbrand(self) -> Self {
        self | EpollFlag::Wrband
    }

    pub fn epoll_msg(self) -> Self {
        self | EpollFlag::Msg
    }

    pub fn epoll_rdhup(self) -> Self {
        self | EpollFlag::Rdhup
    }

    pub fn epoll_exclusive(self) -> Self {
        self | EpollFlag::Exclusive
    }

    pub fn epoll_wakeup(self) -> Self {
        self | EpollFlag::Wakeup
    }
    pub fn epoll_oneshot(self) -> Self {
        self | EpollFlag::Oneshot
    }
    pub fn epoll_et(self) -> Self {
        self | EpollFlag::Et
    }
}

impl Debug for EpollEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, e) in EpollFlag::iter().filter(|e| self & *e).enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }

            write!(f, "{e:?}")?;
        }

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

pub fn epoll_pwait<'a>(
    epfd: BorrowedFd,
    events: &'a mut [EpollEvent],
    timeout: c_int,
    sigmask: SignalSet,
) -> errno::Result<&'a [EpollEvent]> {
    let ret = unsafe {
        libc::epoll_pwait(
            epfd.as_raw_fd(),
            events.as_mut_ptr() as *mut epoll_event,
            events.len() as c_int,
            timeout,
            sigmask.as_ptr(),
        )
    };

    if ret == -1 {
        Err(errno::last_os_error())?
    }

    Ok(&events[..ret as usize])
}
