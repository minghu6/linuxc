use std::{
    ffi::{CStr, CString},
    fmt::Debug,
    mem::ManuallyDrop,
    ops::{BitAnd, BitOr, BitOrAssign},
    ptr::null_mut,
    str::FromStr,
};

use derive_more::derive::{Deref, DerefMut, Display, Error};
use int_enum::IntEnum;
use m6tobytes::derive_to_bits;
use nonempty::NonEmpty;
pub use osimodel::application::http::uri::Scheme;
use strum::{EnumIter, IntoEnumIterator};

use crate::{
    errno::{self, PosixError},
    socket::{SockAddr, SocketProtocol, SocketType},
};

////////////////////////////////////////////////////////////////////////////////
//// Constants


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug)]
pub enum NameOrPort {
    Name(Scheme),
    Port(u16),
}

#[derive(Debug)]
pub struct AddrInfo {
    flags: AIFlags,
    family: AIFamilies,
    socktype: SocketType,
    protocol: SocketProtocol,
    sockaddr: Option<SockAddr>,
    canonname: Option<String>,
}

#[derive(Debug, IntEnum)]
#[repr(i32)]
pub enum AIFamilies {
    /// for both INET and INET6
    UNSPEC = 0,
    INET = 2,
    INET6 = 10,
}

/// Address Information Flags
#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
#[derive_to_bits(i32)]
#[repr(transparent)]
pub struct AIFlags(i32);

/// Address Information Flag
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
#[derive_to_bits(i32)]
#[non_exhaustive]
#[repr(i32)]
pub enum AIFlag {
    /// Indicates the returned address is intended for bind()
    PASSIVE = 0x1,
    /// Requests the canonical name of the host.
    CANNONAME = 0x2,
    /// Forces nodename to be treated as a numeric address, bypassing DNS lookup
    NUMERICHOST = 0x4,
    /// If IPv6 addresses are unavailable, returns IPv4 addresses mapped to IPv6 format
    V4MAPPED = 0x8,
    /// Combines IPv4 and IPv6 addresses (requires AI_V4MAPPED for IPv4-mapped results)
    ALL = 0x10,
    /// Returns addresses only for the IP versions configured on the system
    ADDRCONFIG = 0x20,
    /// This flag is used to inhibit the invocation of a name resolution
    /// service in cases where it is known not to be required.
    NUMERICSERV = 0x0400,
}

#[derive(Debug, Deref, DerefMut)]
pub struct AddrInfoTbl(NonEmpty<AddrInfo>);

#[derive(Debug, Display, Error)]
pub enum AddrInfoError {
    /// The name server returned a temporary failure indication.
    /// Try again later.
    AGAIN,
    /// hints.flags contains invalid flags;
    /// or, hints.ai_flags
    /// included AI_CANONNAME and node was NULL.
    BADFLAGS,
    /// The name server returned a permanent failure indication.
    FAIL,
    /// The requested address family is not supported.
    FAMILY,
    /// Out of memory.
    MEMORY,
    /// The specified network host exists, but does not have any
    /// network addresses defined.
    NODATA,
    /// 1. The node or service is not known;
    ///
    /// 2. both node and service are NULL
    ///
    /// 3. AI_NUMERICSERV was specified in hints.ai_flags
    /// and service was not a numeric port-number string.
    NONAME,
    /// The requested service is not available for the requested socket type.
    SERVICE,
    /// The requested socket type is not supported.
    SOCKTYPE,
    /// Other system error;
    /// errno is set to indicate the error. -11
    SYSTEM(PosixError),
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl AddrInfo {
    pub fn request(
        flags: AIFlags,
        family: AIFamilies,
        socktype: SocketType,
        protocol: SocketProtocol,
    ) -> Self {
        Self {
            flags,
            family,
            socktype,
            protocol,
            sockaddr: None,
            canonname: None,
        }
    }
}

/// Need manuallly drop
impl Into<libc::addrinfo> for AddrInfo {
    fn into(self) -> libc::addrinfo {
        libc::addrinfo {
            ai_flags: self.flags.to_bits(),
            ai_family: self.family.into(),
            ai_socktype: self.socktype.into(),
            ai_protocol: self.protocol.to_protocol(),
            ai_addrlen: self
                .sockaddr
                .as_ref()
                .map(|sockaddr| sockaddr.address_len() as _)
                .unwrap_or_default(),
            ai_addr: self
                .sockaddr
                .map(|sockaddr| ManuallyDrop::new(sockaddr).as_mut_ptr())
                .unwrap_or_default(),
            ai_canonname: self
                .canonname
                .map(|canonname| {
                    ManuallyDrop::new(CString::new(canonname).unwrap())
                        .as_ptr() as _
                })
                .unwrap_or_default(),
            ai_next: null_mut(),
        }
    }
}

impl From<&libc::addrinfo> for AddrInfo {
    fn from(value: &libc::addrinfo) -> Self {
        Self {
            flags: AIFlags(value.ai_flags),
            family: AIFamilies::try_from(value.ai_family).unwrap(),
            socktype: SocketType::try_from(value.ai_socktype).unwrap(),
            protocol: SocketProtocol::try_from(value.ai_protocol).unwrap(),
            sockaddr: if value.ai_addr.is_null() {
                None
            }
            else {
                Some(SockAddr::from_raw_parts(value.ai_addr, value.ai_addrlen))
            },
            canonname: if value.ai_canonname.is_null() {
                None
            }
            else {
                Some(unsafe {
                    CStr::from_ptr(value.ai_canonname)
                        .to_str()
                        .unwrap()
                        .to_owned()
                })
            },
        }
    }
}

impl From<libc::addrinfo> for AddrInfoTbl {
    /// create without dealloc
    fn from(value: libc::addrinfo) -> Self {
        let head = AddrInfo::from(&value);

        let mut tail = vec![];
        let mut p = value.ai_next;

        unsafe {
            while !p.is_null() {
                let raw = *p;

                tail.push(AddrInfo::from(&raw));
                p = raw.ai_next;
            }
        }

        Self(NonEmpty { head, tail })
    }
}

impl Debug for AIFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, e) in AIFlag::iter().filter(|e| self & *e).enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }

            write!(f, "{e:?}")?;
        }

        Ok(())
    }
}

impl BitAnd<AIFlag> for AIFlags {
    type Output = bool;

    fn bitand(self, rhs: AIFlag) -> Self::Output {
        self.0 & rhs.to_bits() != 0
    }
}

impl BitAnd<AIFlag> for &AIFlags {
    type Output = bool;

    fn bitand(self, rhs: AIFlag) -> Self::Output {
        self.0 & rhs.to_bits() != 0
    }
}

impl BitOr<AIFlag> for AIFlags {
    type Output = Self;

    fn bitor(self, rhs: AIFlag) -> Self::Output {
        Self(self.0 | rhs.to_bits())
    }
}

impl BitOrAssign<AIFlag> for &mut AIFlags {
    fn bitor_assign(&mut self, rhs: AIFlag) {
        self.0 |= rhs.to_bits()
    }
}

impl BitOr<AIFlag> for AIFlag {
    type Output = AIFlags;

    fn bitor(self, rhs: AIFlag) -> Self::Output {
        AIFlags(self.to_bits() | rhs.to_bits())
    }
}

impl std::fmt::Display for NameOrPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameOrPort::Name(scheme) => write!(f, "{scheme}"),
            NameOrPort::Port(port) => write!(f, "{port}"),
        }
    }
}

impl From<Scheme> for NameOrPort {
    fn from(value: Scheme) -> Self {
        Self::Name(value)
    }
}

impl From<u16> for NameOrPort {
    fn from(value: u16) -> Self {
        Self::Port(value)
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

pub fn getaddrinfo(
    node: Option<&str>,
    service: Option<NameOrPort>,
    hints: Option<AddrInfo>,
) -> Result<AddrInfoTbl, AddrInfoError> {
    let mut res = null_mut::<libc::addrinfo>();

    let ret = unsafe {
        let node = node
            .map(|s| ManuallyDrop::new(CString::from_str(s).unwrap()).as_ptr())
            .unwrap_or_default();

        let service = service
            .map(|service| {
                ManuallyDrop::new(CString::new(service.to_string()).unwrap())
                    .as_ptr()
            })
            .unwrap_or_default();

        let hints_opt: Option<libc::addrinfo> =
            hints.map(|hints| hints.into());

        let hints = hints_opt
            .as_ref()
            .map(|hints| hints as *const libc::addrinfo)
            .unwrap_or_default();

        let ret = libc::getaddrinfo(
            node,
            service,
            hints,
            &mut res as *mut *mut libc::addrinfo,
        );

        if !node.is_null() {
            let _ = CString::from_raw(node as _);
        }

        if !service.is_null() {
            let _ = CString::from_raw(service as _);
        }

        if !hints.is_null() {
            assert!((*hints).ai_addr.is_null());
            assert!((*hints).ai_canonname.is_null())
        }

        ret
    };

    if ret == 0 {
        let tbl = AddrInfoTbl::from(unsafe { *res });

        unsafe {
            libc::freeaddrinfo(res);
        }

        Ok(tbl)
    }
    else {
        Err(match ret {
            -3 => AddrInfoError::AGAIN,
            -1 => AddrInfoError::BADFLAGS,
            -4 => AddrInfoError::FAIL,
            -6 => AddrInfoError::FAMILY,
            -10 => AddrInfoError::FAMILY,
            -5 => AddrInfoError::NODATA,
            -2 => AddrInfoError::NONAME,
            -8 => AddrInfoError::SERVICE,
            -7 => AddrInfoError::SOCKTYPE,
            -11 => AddrInfoError::SYSTEM(errno::last_os_error()),
            x => unimplemented!("EAI code: {x}"),
        })
    }
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_getaddrinfo() {
        use AIFlag::*;

        let tbl =
            getaddrinfo(Some("alibaba.com"), Some(Scheme::HTTP.into()), None)
                .unwrap();

        println!("{tbl:#?}");

        let tbl = getaddrinfo(
            Some("baidu.com"),
            Some(Scheme::HTTP.into()),
            Some(AddrInfo::request(
                ALL | V4MAPPED,
                AIFamilies::UNSPEC,
                SocketType::ZERO,
                SocketProtocol::Zero,
            )),
        )
        .unwrap();

        println!("{tbl:#?}");
    }
}
