
use std::{fmt::Debug, mem::zeroed, ops::BitAnd};

use libc::{sigset_t};
use m6tobytes::derive_to_bits;
use strum::{EnumIter, IntoEnumIterator};

use crate::errno;


////////////////////////////////////////////////////////////////////////////////
//// Constants


////////////////////////////////////////////////////////////////////////////////
//// Structures


#[derive(Debug, EnumIter, Clone, Copy, PartialEq, Eq, Hash)]
#[derive_to_bits(i32)]
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
    SIGWINCH = 28
}

#[derive(PartialEq, Eq, Clone, Copy, Hash)]
#[repr(transparent)]
pub struct SignalSet(sigset_t);

////////////////////////////////////////////////////////////////////////////////
//// Functions


impl SignalSet {
    pub fn as_ptr(&self) -> *const sigset_t {
        &self.0 as *const sigset_t
    }

    pub fn empty() -> Self {
        let mut sigset: sigset_t = unsafe { zeroed() };

        let ret = unsafe {
            libc::sigemptyset(&mut sigset as *mut sigset_t)
        };

        if ret != 0 {
            panic!("{:?}", errno::last_os_error());
        }

        Self(sigset)
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

}

impl BitAnd<Signal> for &SignalSet {
    type Output = bool;

    fn bitand(self, rhs: Signal) -> Self::Output {
        self.is_member(rhs)
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
