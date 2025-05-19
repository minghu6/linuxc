use derive_more::derive::Error;
use int_enum::IntEnum;
use libc::__errno_location;
use strum::{Display, EnumString};


pub type Result<T> = std::result::Result<T, PosixError>;

////////////////////////////////////////////////////////////////////////////////
//// Structures

/// Refer from [man7.org](https://man7.org/linux/man-pages/man3/errno.3.html)
#[derive(
    Debug, Display, Clone, Copy, PartialEq, Eq, Hash, Error, EnumString, IntEnum
)]
#[strum(serialize_all = "UPPERCASE")]
#[repr(i32)]
pub enum PosixError {
    /// Argument list too long
    E2BIG =7,
    /// Permission denied
    EACCES = 13,
    ///  Address already in use
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EADDRINUSE = 98,
    /// Address not available
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EADDRNOTAVAIL = 99,
    /// Address family not supported
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EAFNOSUPPORT = 97,
    /// Resource temporarily unavailable
    ///
    /// Try Again (may be the same value as EWOULDBLOCK)
    EAGAIN = 11,
    /// Connection already in progress
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EALREADY = 114,
    /// Invalid exchange
    ///
    /// Bad Exchange
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EBADE = 52,
    /// Bad file descriptor
    ///
    /// Bad File descriptor
    EBADF = 9,
    /// File descriptor in bad state
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EBADFD = 77,
    /// Bad message
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EBADMSG = 74,
    /// Invalid request descriptor
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EBADR = 53,
    /// Invalid request code
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EBADRQC = 56,
    /// Invalid slot
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EBADSLT = 57,
    /// Device or resource busy
    EBUSY = 16,
    /// Operation canceled
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ECANCELED = 125,
    /// No child processes
    ECHILD = 10,
    /// Channel number out of range
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ECHRNG = 44,
    /// Communication error on send
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ECOMM = 70,
    /// Connection aborted
    ///
    /// ConnectionAborted
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ECONNABORTED = 103,
    /// Connection refused
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ECONNREFUSED = 111,
    /// Connection reset
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ECONNRESET = 104,
    /// Resource deadlock avoided
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EDEADLK = 35,
    // ///  On most architectures, a synonym for EDEADLK.  On some
    // /// architectures (e.g., Linux MIPS, PowerPC, SPARC), it is a
    // /// separate error code "File locking deadlock error".
    // EDEADLOCK,
    /// Destination address required
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EDESTADDRREQ = 89,
    /// Mathematics argument out of domain of function
    EDOM = 33,
    /// Disk quota exceeded
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EDQUOT = 122,
    /// File exists
    EEXIST = 17,
    /// Bad address
    EFAULT = 14,
    /// File too large
    EFBIG = 27,
    /// Host is down
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EHOSTDOWN = 112,
    /// No such host.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EHOSTUNREACH = 113,
    /// Memory page has hardware error
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EHWPOISON = 133,
    /// Identifier removed.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EIDRM = 43,
    /// Illegal byte sequence.
    ///
    /// or Invalid or incomplete multibyte or wide character in glibc error
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EILSEQ = 84,
    /// Operation in progress
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EINPROGRESS = 115,
    /// Interrupted function call.
    EINTR = 4,
    /// Invalid argument.
    EINVAL = 22,
    /// I/O error.
    EIO = 5,
    /// Socket is connected.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EISCONN = 106,
    /// Is a directory.
    EISDIR = 21,
    /// Is a named type file.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EISNAM = 120,
    /// Key has expired.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EKEYEXPIRED = 127,
    /// Key was rejected by service.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EKEYREJECTED = 129,
    /// Key has been revoked.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EKEYREVOKED = 128,
    /// Level 2 halted.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EL2HLT = 51,
    /// Level 2 not synchronized.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EL2NSYNC = 45,
    /// Level 3 halted.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EL3HLT = 46,
    /// Level 3 reset.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EL3RST = 47,
    /// Cannot access a needed shared library.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ELIBACC = 79,
    /// Accessing a corrupted shared library.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ELIBBAD = 80,
    /// Attempting to link in too many shared libraries.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ELIBMAX = 82,
    /// .lib section in a.out corrupted
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ELIBSCN = 81,
    /// Cannot exec a shared library directly.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ELIBEXEC = 83,
    /// Link number out of range.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ELNRNG = 48,
    /// Too many levels of symbolic links (POSIX.1-2001).
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ELOOP = 40,
    /// Wrong medium type.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EMEDIUMTYPE = 124,
    /// Too many open files.
    EMFILE = 24,
    /// Too many links
    EMLINK = 31,
    /// Message too long.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EMSGSIZE = 90,
    /// Multihop attempted.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EMULTIHOP = 72,
    /// Filename too long.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENAMETOOLONG = 36,
    /// Network is down.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENETDOWN = 100,
    /// Connection aborted by network.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENETRESET = 102,
    /// Network is unreachable.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENETUNREACH = 101,
    /// Too many open files in system.
    ENFILE = 23,
    /// No anode.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOANO = 55,
    /// No buffer space available.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOBUFS = 105,
    /// No message is available on the STREAM head read queue.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENODATA = 61,
    /// No such device.
    ENODEV = 19,
    /// No such file or directory.
    ENOENT = 2,
    /// Executable file format error.
    ENOEXEC = 8,
    /// Required key not available.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOKEY = 126,
    /// No locks available.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOLCK = 37,
    /// Link has been severed.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOLINK = 67,
    /// No medium found.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOMEDIUM = 123,
    /// Not enough space.
    ///
    /// cannot allocate memory
    ENOMEM = 12,
    /// No message of the desired type.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOMSG = 42,
    /// Machine is not on the network.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENONET = 64,
    /// Package not installed.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOPKG = 65,
    /// Protocol not available.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOPROTOOPT = 92,
    /// No space left on device.
    ENOSPC = 28,
    /// No STREAM resources.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOSR = 63,
    /// Not a STREAM.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOSTR = 60,
    /// Function not implemented.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOSYS = 38,
    /// Block device required.
    ENOTBLK = 15,
    /// The socket is not connected.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOTCONN = 107,
    /// Not a directory.
    ENOTDIR = 20,
    /// Directory not empty.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOTEMPTY = 39,
    /// State not recoverable.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOTRECOVERABLE = 131,
    /// Not a socket.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOTSOCK = 88,
    // /// Not supported.
    // ///
    // /// (ENOTSUP and EOPNOTSUPP have the same value on Linux, but
    // /// according to POSIX.1 these error values should be
    // /// distinct.)
    // ENOTSUP,
    /// Inappropriate I/O control operation.
    ENOTTY = 25,
    /// Name not unique on network.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ENOTUNIQ = 76,
    /// No such device or address.
    ENXIO = 6,
    /// Operation not supported on socket.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EOPNOTSUPP = 95,
    /// Value too large to be stored in data type.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EOVERFLOW = 75,
    /// Owner died.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EOWNERDEAD = 130,
    /// Operation not permitted.
    EPERM = 1,
    /// Protocol family not supported.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EPFNOSUPPORT = 96,
    /// Broken pipe.
    EPIPE = 32,
    /// Protocol error.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EPROTO = 71,
    /// Protocol not supported.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EPROTONOSUPPORT = 93,
    /// Protocol wrong type for socket
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EPROTOTYPE = 91,
    /// Result too large.
    ERANGE = 34,
    /// Remote address changed.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EREMCHG = 78,
    /// Object is remote.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EREMOTE = 66,
    /// Remote I/O error.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EREMOTEIO = 121,
    /// Interrupted system call should be restarted.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ERESTART = 85,
    /// Operation not possible due to RF-kill.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ERFKILL = 132,
    /// Read-only file system.
    EROFS = 30,
    /// Cannot send after transport endpoint shutdown.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ESHUTDOWN = 108,
    /// Invalid seek.
    ESPIPE = 29,
    /// Socket type not supported.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ESOCKTNOSUPPORT = 94,
    /// No such process.
    ESRCH = 3,
    /// Stale file handle reference.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ESTALE = 116,
    /// Streams pipe error.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ESTRPIPE = 86,
    /// Stream timed out.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ETIME = 62,
    /// Connection timed out.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ETIMEDOUT = 110,
    /// Too many references: cannot splice.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    ETOOMANYREFS = 109,
    /// Text file busy.
    ETXTBSY = 26,
    /// Structure needs cleaning.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EUCLEAN = 117,
    /// Protocol driver not attached.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EUNATCH = 49,
    /// Too many users.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EUSERS = 87,
    /// Operation would block.
    ///
    /// (may be same value as EAGAIN)
    #[cfg(not(target_os = "linux"))]
    EWOULDBLOCK,
    /// Invalid cross-device link.
    EXDEV = 18,
    /// Exchange full.
    #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
    EXFULL = 54,
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl PosixError {
    /// Retrieves the standard POSIX error description
    ///
    /// # Returns
    /// - `&'static str`: Error description text
    pub fn description(&self) -> &'static str {
        use PosixError::*;

        match self {
            E2BIG => "Argument list too long",
            EACCES => "Permission denied",
            EADDRINUSE => "Address already in use",
            EADDRNOTAVAIL => "Address not available",
            EAFNOSUPPORT => "Address family not supported",
            EAGAIN => "Resource temporarily unavailable",
            EALREADY => "Connection already in progress",
            EBADE => "Invalid exchange",
            EBADF => "Bad file descriptor",
            EBADFD => "File descriptor in bad state",
            EBADMSG => "Bad message",
            EBADR => "Invalid request descriptor",
            EBADRQC => "Invalid request code",
            EBADSLT => "Invalid slot",
            EBUSY => "Device or resource busy",
            ECANCELED => "Operation canceled",
            ECHILD => "No child processes",
            ECHRNG => "Channel number out of range",
            ECOMM => "Communication error on send",
            ECONNABORTED => "Software caused connection abort",
            ECONNREFUSED => "Connection refused",
            ECONNRESET => "Connection reset by peer",
            EDEADLK => "Resource deadlock would occur",
            // EDEADLOCK => "File locking deadlock error",
            EDESTADDRREQ => "Destination address required",
            EDOM => "Math argument out of domain",
            EDQUOT => "Quota exceeded",
            EEXIST => "File exists",
            EFAULT => "Bad address",
            EFBIG => "File too large",
            EHOSTDOWN => "Host is down",
            EHOSTUNREACH => "Host unreachable",
            EHWPOISON => "Memory hardware error",
            EIDRM => "Identifier removed",
            EILSEQ => "Invalid or incomplete multibyte or wide character",
            EINPROGRESS => "Operation in progress",
            EINTR => "Interrupted system call",
            EINVAL => "Invalid argument",
            EIO => "I/O error",
            EISCONN => "Transport endpoint connected",
            EISDIR => "Is a directory",
            EISNAM => "Is a named type file",
            EKEYEXPIRED => "Key expired",
            EKEYREVOKED => "Key revoked",
            EKEYREJECTED => "Key rejected by service",
            EL2HLT => "Level 2 halted",
            EL2NSYNC => "Level 2 not synchronized",
            EL3HLT => "Level 3 halted",
            EL3RST => "Level 3 reset",
            ELIBACC => "Cannot access a needed shared library",
            ELIBBAD => "Accessing a corrupted shared library",
            ELIBMAX => "Attempting to link in too many shared libraries",
            ELIBSCN => ".lib section in a.out corrupted",
            ELIBEXEC => "Cannot exec a shared library directly",
            ELNRNG => "Link number out of range",
            ELOOP => "Too many symbolic links",
            EMEDIUMTYPE => "Wrong medium type",
            EMFILE => "Too many open files",
            EMLINK => "Too many links",
            EMSGSIZE => "Message too long",
            EMULTIHOP => "Multihop attempted",
            ENAMETOOLONG => "Filename too long",
            ENETDOWN => "Network is down",
            ENETRESET => "Network dropped connection",
            ENETUNREACH => "Network unreachable",
            ENFILE => "File table overflow",
            ENOANO => "No anode",
            ENOBUFS => "No buffer space",
            ENODATA => "No message is available on the STREAM head read queue",
            ENODEV => "No such device",
            ENOENT => "No such file or directory",
            ENOEXEC => "Executable format error",
            ENOKEY => "Required key unavailable",
            ENOLCK => "No locks available",
            ENOLINK => "Link has been severed",
            ENOMEDIUM => "No medium found",
            ENOMEM => "Out of memory",
            ENOMSG => "No message of the desired type",
            ENONET => "Machine is not on the network",
            ENOPKG => "Package not installed",
            ENOPROTOOPT => "Protocol not available",
            ENOSPC => "No space left on device",
            ENOSR => "No STREAM resources",
            ENOSTR => "Not a STREAM",
            ENOSYS => "Function not implemented",
            ENOTBLK => "Block device required",
            ENOTCONN => "Transport endpoint not connected",
            ENOTDIR => "Not a directory",
            ENOTEMPTY => "Directory not empty",
            ENOTRECOVERABLE => "State not recoverable",
            ENOTSOCK => "Not a socket",
            // ENOTSUP => "Operation not supported",
            ENOTTY => "Not a terminal",
            ENOTUNIQ => "Name not unique on network",
            ENXIO => "No such device or address",
            EOPNOTSUPP => "Operation not supported",
            EOVERFLOW => "Value too large to be stored in data type",
            EOWNERDEAD => "Owner terminated",
            EPERM => "Operation not permitted",
            EPFNOSUPPORT => "Protocol family not supported",
            EPIPE => "Broken pipe",
            EPROTO => "Protocol error",
            EPROTONOSUPPORT => "Protocol not supported",
            EPROTOTYPE => "Protocol wrong type",
            ERANGE => "Math result not representable",
            EREMCHG => "Remote address changed",
            EREMOTE => "Object is remote",
            EREMOTEIO => "Remote I/O error",
            ERESTART => "Interrupted system call should be restarted",
            ERFKILL => "RF-Kill condition",
            EROFS => "Read-only file system",
            ESHUTDOWN => "Endpoint shutdown",
            ESPIPE => "Illegal seek",
            ESOCKTNOSUPPORT => "Socket type not supported",
            ESRCH => "No such process",
            ESTALE => "Stale file handle",
            ESTRPIPE => "Streams pipe error",
            ETIME => "Timer expired",
            ETIMEDOUT => "Connection timed out",
            ETOOMANYREFS => "Too many references",
            ETXTBSY => "Text file busy",
            EUCLEAN => "Structure needs cleaning",
            EUNATCH => "Protocol driver not attached",
            EUSERS => "Too many users",
            #[cfg(not(target_os = "linux"))]
            EWOULDBLOCK => "Operation would block",
            EXDEV => "Cross-device link",
            EXFULL => "Exchange full"
        }
    }
}


////////////////////////////////////////////////////////////////////////////////
//// Functions

/// Panic if no error occurs.
pub(crate) fn last_os_error() -> PosixError {
    unsafe {
        let errno = *__errno_location();

        assert!(errno > 0, "found {errno}");

        PosixError::try_from(errno).unwrap()
    }
}
