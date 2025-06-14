use std::{
    fmt::Debug,
    mem::zeroed,
    ops::{BitAnd, BitOr},
};

use int_enum::IntEnum;
use libc::sigset_t;
use m6tobytes::{derive_from_bits, derive_to_bits};
use strum::{EnumIter, IntoEnumIterator};

use crate::errno::{self, PosixError};


////////////////////////////////////////////////////////////////////////////////
//// Constants


////////////////////////////////////////////////////////////////////////////////
//// Structures


#[derive(Debug, EnumIter, Clone, Copy, PartialEq, Eq, Hash, IntEnum)]
#[derive_to_bits(i32)]
#[derive_from_bits(i32)]
#[repr(i32)]
pub enum Signal {
    /// mordern os merged into with SIGIOT
    SIGABRT = 6,
    SIGALRM = 14,
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGBUS = 7,
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGCHLD = 17,
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGCONT = 18,
    // SIGEMT
    ///
    /// SIGFPE
    ///
    /// Erroneous arithmetic operation
    SIGFPE = 8,
    /// SIGHUP
    ///
    /// Hangup detected on controlling terminalor death of controlling process
    SIGHUP = 1,
    SIGILL = 4,
    SIGINT = 2,
    SIGIO = 29,
    SIGKILL = 9,
    // /// File lock lost (unused)
    // SIGLOST,
    SIGPIPE = 13,
    /// Profiling timer expired
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGPROF = 27,
    /// Power failure (System V)
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGPWR = 30,
    /// Quit from keyboard
    SIGQUIT = 3,
    /// Invalid memory reference
    SIGSEGV = 11,
    /// Stack fault on coprocessor (unused)
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGSTKFLT = 16,
    /// Stop process
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGSTOP = 19,
    /// Stop typed at terminal
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGTSTP = 20,
    /// Bad system call (SVr4)
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGSYS = 31,
    /// Termination signal
    SIGTERM = 15,
    SIGTRAP = 5,
    /// Terminal input for background process
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGTTIN = 21,
    /// Terminal output for background process
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGTTOU = 22,
    /// Urgent condition on socket (4.2BSD)
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGURG = 23,
    /// User-defined signal 1
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGUSR1 = 10,
    /// User-defined signal 2
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGUSR2 = 12,
    /// Virtual alarm clock (4.2BSD)
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGVTALRM = 26,
    /// CPU time limit exceeded (4.2BSD)
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGXCPU = 24,
    /// File size limit exceeded (4.2BSD)
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGXFSZ = 25,
    /// Window resize signal (4.3BSD, Sun)
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    SIGWINCH = 28,
}

#[derive(PartialEq, Eq, Clone, Copy, Hash)]
#[repr(transparent)]
pub struct SignalSet(sigset_t);

#[derive(Debug, IntEnum, Default, Clone, Copy)]
#[repr(i32)]
pub enum SigMaskHow {
    #[default]
    BLOCK = 0,
    UNBLOCK = 1,
    SETMASK = 2,
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

impl BitOr<Signal> for Signal {
    type Output = SignalSet;

    fn bitor(self, rhs: Signal) -> Self::Output {
        let mut set = SignalSet::empty();

        set.insert(self);
        set.insert(rhs);

        set
    }
}

impl Into<SignalSet> for Signal {
    fn into(self) -> SignalSet {
        SignalSet::empty() | self
    }
}

impl SignalSet {
    pub fn as_ptr(&self) -> *const sigset_t {
        &self.0 as *const sigset_t
    }

    pub fn as_mut_ptr(&mut self) -> *mut sigset_t {
        &mut self.0 as *mut sigset_t
    }

    pub fn empty() -> Self {
        let mut sigset: sigset_t = unsafe { zeroed() };

        let ret = unsafe { libc::sigemptyset(&mut sigset as *mut sigset_t) };

        if ret != 0 {
            panic!("{:?}", errno::last_os_error());
        }

        Self(sigset)
    }

    pub const fn is_empty(&self) -> bool {
        unsafe {
            std::mem::transmute::<sigset_t, [u8; size_of::<sigset_t>()]>(
                self.0,
            )
        }
        .is_empty()
    }

    pub fn is_member(&self, sig: Signal) -> bool {
        let ret = unsafe {
            libc::sigismember(&self.0 as *const sigset_t, sig.to_bits() as _)
        };

        if ret == -1 {
            panic!("{:?}", errno::last_os_error());
        }

        if ret == 1 {
            true
        }
        // ret == 0
        else {
            false
        }
    }

    /// True for signal is also member of it
    pub fn insert(&mut self, sig: Signal) -> bool {
        let ret = unsafe {
            libc::sigaddset(&mut self.0 as *mut sigset_t, sig.to_bits() as _)
        };

        if ret == -1 {
            panic!("{:?}", errno::last_os_error());
        }

        if ret == 1 {
            true
        }
        // ret == 0
        else {
            false
        }
    }

    pub fn wait(&self) -> Signal {
        let mut sig = 0;

        let ret = unsafe { libc::sigwait(self.as_ptr(), &mut sig as _) };

        if ret != 0 {
            panic!("EINVAL {self:?}");
        }

        Signal::try_from(sig).unwrap()
    }
}

impl BitAnd<Signal> for &SignalSet {
    type Output = bool;

    fn bitand(self, rhs: Signal) -> Self::Output {
        self.is_member(rhs)
    }
}

impl BitOr<Signal> for SignalSet {
    type Output = Self;

    fn bitor(mut self, rhs: Signal) -> Self::Output {
        self.insert(rhs);
        self
    }
}

impl Debug for SignalSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, sig) in Signal::iter().filter(|sig| self & *sig).enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }

            write!(f, "{sig:?}")?;
        }

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

/// return old sigmask
pub fn pthread_sigmask(
    how: SigMaskHow,
    set: SignalSet,
) -> errno::Result<SignalSet> {
    let mut oldset = SignalSet::empty();

    let ret = unsafe {
        libc::pthread_sigmask(how.into(), set.as_ptr(), oldset.as_mut_ptr())
    };

    if ret != 0 {
        Err(PosixError::try_from(ret).unwrap())?
    }

    Ok(oldset)
}

pub fn raise(
    sig: Signal,
) -> bool {
    let ret = unsafe {
        libc::raise(sig.into())
    };

    ret == 0
}
