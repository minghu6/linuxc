//! Socket Address Family

use std::{
    error::Error, ffi::{c_int, c_void}, fmt::Debug, mem::{transmute, transmute_copy}, net::{Ipv4Addr, Ipv6Addr}, ops::{BitAnd, BitOr}, os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd}, ptr
};

use derive_more::derive::Deref;
use int_enum::IntEnum;
use libc::{
    SOCK_CLOEXEC, SOCK_NONBLOCK, in_addr, sa_family_t, size_t, sockaddr,
    sockaddr_in, socklen_t,
};
use m6tobytes::{derive_from_bits, derive_to_bits};
use osimodel::{
    datalink::{EthType, EthTypeSpec, Mac},
    network::{ip, IPv4Addr},
};
use strum::EnumIter;

use crate::{
    be::{EthTypeBe, HTypeBe, U16Be, U32Be},
    errno,
};


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[derive_to_bits(u16)]
#[derive_from_bits(u16)]
#[non_exhaustive]
#[repr(u16)]
/// Some field has been elimited, from x86_64 linux gnu
pub enum SaFamily {
    /// AF_UNSPEC 0
    #[default]
    UnSpec,
    /// AF_LOCAL (including synonym AF_UNIX, AF_FILE) 1
    Local = 1,
    /// AF_INET 2 (sockaddr_in, ipv4)
    Inet = 2,
    /// AF_INET 10
    Inet6 = 10,
    /// AF_PACKET 17 (rx/tx raw packets at the Layer 2)
    Packet = 17,
}

#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[derive_to_bits(u8)]
// #define PACKET_HOST		0		/* To us		*/
// #define PACKET_BROADCAST	1		/* To all		*/
// #define PACKET_MULTICAST	2		/* To group		*/
// #define PACKET_OTHERHOST	3		/* To someone else 	*/
// #define PACKET_OUTGOING		4	/* Outgoing of any type */
// #define PACKET_LOOPBACK		5	/* MC/BRD frame looped back */
// #define PACKET_USER		6		/* To user space	*/
// #define PACKET_KERNEL		7	/* To kernel space	*/
// /* Unused, PACKET_FASTROUTE and PACKET_LOOPBACK are invisible to user space */
// #define PACKET_FASTROUTE	6		/* Fastrouted frame	*/
#[repr(u8)]
pub enum PktType {
    #[default]
    Host = 0,
    Broadcast = 1,
    Multicast = 2,
    OtherHost = 3,
    Outgoing = 4,
    Loopback = 5,
    User = 6,
    Kernel = 7,
}

#[derive(Debug)]
#[repr(C)]
#[non_exhaustive]
pub enum SockAddr {
    Inet(SockAddrIn),
    Inet6(SockAddrIn6),
    Unix(SockAddrUn),
    Packet(SockAddrLL),
}

/// Synonym libc::sockaddr_in
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct SockAddrIn {
    /// In Native Order for it's not be transmit
    pub family: SaFamily,
    pub port: U16Be,
    /// IPv4 Address
    pub addr: InAddr,
    pub padding: [u8; 8],
}

#[derive(Default, Clone, Copy, Eq, PartialEq, Hash, Deref)]
pub struct InAddr(U32Be);

/// Synonym libc::sockaddr_in6
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct SockAddrIn6 {
    pub family: SaFamily,
    pub port: U16Be,
    pub flowinfo: U32Be,
    pub addr: InAddr6,
    pub scope_id: u32,
}

#[derive(Default, Clone, Copy, Eq, PartialEq, Hash, Deref)]
pub struct InAddr6([u8; 16]);

#[derive(Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct SockAddrUn {
    pub family: SaFamily,
    pub path: [u8; 108],
}

///
/// Socket Address Link Layer (sockaddr_ll)
#[derive(Debug)]
#[repr(C)]
pub struct SockAddrLL {
    /// unsigned short be
    pub family: SaFamily,
    /// unsigned short be
    pub protocol: EthTypeBe,
    /// native order
    pub ifindex: i32,
    pub hatype: HTypeBe,
    pub pkttype: PktType,
    /// size of address size (for Mac is 6)
    pub halen: u8,
    /// physical layer address
    pub addr: PhyAddr,
}

#[derive(Debug)]
#[repr(transparent)]
pub struct PhyAddr([u8; 8]);

/// Ref [address_families](https://man7.org/linux/man-pages/man7/address_families.7.html)
///
#[derive(Debug, IntEnum)]
#[repr(i32)]
pub enum AddressFamilies {
    UNSPEC = 0,
    /// = LOCAL
    UNIX = 1,
    INET = 2,
    AX25 = 3,
    IPX = 4,
    /// AppleTalk For further information
    APPLETALK = 5,
    /// AX.25 packet layer protocol.
    NETROM = 6,
    /// Can't be used for creating sockets; mostly used for bridge
    /// links in rtnetlink(7) protocol commands.
    BRIDGE = 7,
    ATMPVC = 8,
    X25 = 9,
    INET6 = 10,
    ROSE = 11,
    /// Yes it's Pascal Case
    DECnet = 12,
    NETBEUI = 13,
    SECURITY = 14,
    KEY = 15,
    /// = ROUTE
    NETLINK = 16,
    PACKET = 17,
    ASH,
    ECONET,
    ATMSVC,
    RDS,
    SNA,
    RDA,
    PPPOX,
    WANPIPE = 25,
    LLC,
    CAN,
    TIPC,
    BLUETOOTH = 31,
    IUCV,
    RXRPC,
    ISDN,
    /// Nokia cellular modem IPC/RPC interface
    PHONET,
    IEEE802154,
    CAIF,
    /// Interface to kernel crypto API
    ALG = 38,
    #[cfg(target_env = "gnu")]
    VSOCK = 40,
    #[cfg(target_env = "gnu")]
    XDP = 44,
}

#[derive(Debug, IntEnum)]
#[repr(i32)]
#[non_exhaustive]
pub enum SocketType {
    ZERO = 0,
    STREAM = 1,
    DGRAM = 2,
    RAW = 3,
    RDM = 4,
    SEQPACKET = 5,
}

#[derive(Default)]
pub struct ExtraBehavior {
    pub non_block: bool,
    pub close_on_exec: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum SocketProtocol {
    IP(ip::ProtocolSpec),
    Eth(EthTypeSpec),
    Zero,
}

#[derive(Debug, EnumIter, PartialEq, Eq, Hash)]
#[derive_to_bits(i32)]
#[repr(i32)]
pub enum Msg {
    OOB = 1,
    PEEK = 2,
    DONTROUTE = 4,
    CTRUNC = 8,
    TRUNC = 0x20,
    DONTWAIT = 0x40,
    FIN = 0x200,
    SYN = 0x400,
    CONFIRM = 0x800,
    RST = 0x1000,
    ERRQUEUE = 0x2000,
    NOSIGNAL = 0x4000,
    MORE = 0x8000,
    WAITFORNE = 0x10_000,
    FASTOPEN = 0x20000000,
    /// MSG_CMSG_CLOEXEC
    CLOEXEC = 0x40000000,
}

#[derive(Debug, Default, PartialEq, Eq, Hash)]
#[derive_to_bits(i32)]
#[repr(transparent)]
pub struct Flags(i32);

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl BitOr<Msg> for Flags {
    type Output = Self;

    fn bitor(self, rhs: Msg) -> Self::Output {
        Self(self.0 | rhs.to_bits())
    }
}

impl BitAnd<Msg> for &Flags {
    type Output = bool;

    fn bitand(self, rhs: Msg) -> Self::Output {
        self.0 & rhs.to_bits() != 0
    }
}

impl SocketProtocol {
    pub fn to_protocol(&self) -> c_int {
        use SocketProtocol::*;

        match self {
            IP(protocol_spec) => protocol_spec.to_bits() as _,
            Eth(eth_type_spec) => {
                EthTypeBe::new(*eth_type_spec).to_bits() as _
            }
            Zero => 0,
        }
    }
}

impl TryFrom<c_int> for SocketProtocol {
    type Error = Box<dyn Error>;

    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        Ok(if value == 0 {
            Self::Zero
        }
        else if value <= u8::MAX as c_int {
            Self::IP(unsafe { ip::Protocol::from_bits(value as u8).into() } )
        }
        else {
            Self::Eth(unsafe { EthType::from_bits(value as u16).into() })
        })
    }
}

impl Default for SocketProtocol {
    fn default() -> Self {
        Self::Zero
    }
}

impl From<sockaddr> for SockAddrIn {
    fn from(value: sockaddr) -> Self {
        unsafe { transmute(value) }
    }
}

impl From<sockaddr_in> for SockAddrIn {
    fn from(value: sockaddr_in) -> Self {
        unsafe { transmute(value) }
    }
}

impl ExtraBehavior {
    pub fn non_block(mut self) -> Self {
        self.non_block = true;
        self
    }

    pub fn close_on_exec(mut self) -> Self {
        self.close_on_exec = true;
        self
    }

    pub fn to_bits(self) -> i32 {
        let mut init = 0;

        if self.non_block {
            init |= SOCK_NONBLOCK;
        }

        if self.close_on_exec {
            init |= SOCK_CLOEXEC
        }

        init
    }
}

impl SockAddrUn {
    pub fn from_raw_parts(
        sockaddr: *const sockaddr,
        addrlen: socklen_t,
    ) -> Self {
        assert!(addrlen as usize > size_of::<sa_family_t>());

        let mut it = Self {
            family: unsafe {
                SaFamily::from_bits(ptr::read(sockaddr as *const sa_family_t))
            },
            path: [0; 108],
        };

        it.path.copy_from_slice(unsafe {
            std::slice::from_raw_parts(
                sockaddr.byte_add(size_of::<sa_family_t>()) as _,
                addrlen as usize - size_of::<sa_family_t>(),
            )
        });

        it
    }
}

impl SockAddr {
    pub fn address(&self) -> sockaddr {
        use SockAddr::*;

        match self {
            Inet(sock_addr_in) => unsafe { transmute_copy(sock_addr_in) },
            Inet6(sock_addr_in6) => unsafe { transmute_copy(sock_addr_in6) },
            Unix(sock_addr_un) => unsafe { transmute_copy(sock_addr_un) },
            Packet(sock_addr_ll) => unsafe { transmute_copy(sock_addr_ll) },
        }
    }

    pub fn as_ptr(&self) -> *const sockaddr {
        use SockAddr::*;

        match self {
            Inet(sock_addr_in) => sock_addr_in as *const SockAddrIn as _ ,
            Inet6(sock_addr_in6) => sock_addr_in6 as *const SockAddrIn6 as _,
            Unix(sock_addr_un) => sock_addr_un as *const SockAddrUn as _,
            Packet(sock_addr_ll) => sock_addr_ll as *const SockAddrLL as _,
        }
    }

    pub fn as_mut_ptr(&mut self) -> *mut sockaddr {
        self.as_ptr() as _
    }

    pub fn address_len(&self) -> usize {
        use SockAddr::*;

        match self {
            Inet(..) => size_of::<SockAddrIn>(),
            Inet6(..) => size_of::<SockAddrIn6>(),
            Unix(..) => size_of::<SockAddrUn>(),
            Packet(..) => size_of::<SockAddrLL>(),
        }
    }

    /// just copy without heap owneship move (need manually free for sockaddr)
    pub fn from_raw_parts(
        sockaddr: *const sockaddr,
        addrlen: socklen_t,
    ) -> Self {
        assert!(addrlen >= 2);
        assert!(!sockaddr.is_null());

        let family = unsafe { SaFamily::from_bits((*sockaddr).sa_family) };

        match family {
            SaFamily::UnSpec => panic!("unsupported type sockaddr"),
            SaFamily::Local => unsafe {
                assert_eq!(addrlen as usize, size_of::<SockAddrLL>());
                Self::Packet(ptr::read(sockaddr as *const SockAddrLL))
            },
            SaFamily::Inet => unsafe {
                assert_eq!(addrlen as usize, size_of::<SockAddrIn>());
                Self::Inet(ptr::read(sockaddr as *const SockAddrIn))
            },
            SaFamily::Inet6 => unsafe {
                assert_eq!(addrlen as usize, size_of::<SockAddrIn6>());
                Self::Inet6(ptr::read(sockaddr as *const SockAddrIn6))
            },
            SaFamily::Packet => Self::Unix(SockAddrUn::from_raw_parts(sockaddr, addrlen))
        }
    }
}

impl From<Mac> for PhyAddr {
    fn from(value: Mac) -> Self {
        Self(value.into_arr8())
    }
}

impl std::fmt::Debug for InAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<Ipv4Addr>::into(*self))
    }
}

impl std::fmt::Display for InAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<in_addr> for InAddr {
    fn from(value: in_addr) -> Self {
        Self(U32Be::from_be(value.s_addr))
    }
}

impl From<Ipv4Addr> for InAddr {
    fn from(value: Ipv4Addr) -> Self {
        Self(U32Be::from_ne(value.to_bits()))
    }
}

impl From<IPv4Addr> for InAddr {
    fn from(value: IPv4Addr) -> Self {
        InAddr(U32Be::new(value.to_bits()))
    }
}

impl Into<Ipv4Addr> for InAddr {
    fn into(self) -> Ipv4Addr {
        Ipv4Addr::from_bits(self.to_ne())
    }
}

impl Into<IPv4Addr> for InAddr {
    fn into(self) -> IPv4Addr {
        IPv4Addr::from_bits(self.to_ne())
    }
}

impl Into<Ipv6Addr> for InAddr6 {
    fn into(self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.0)
    }
}

impl Debug for InAddr6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", Into::<Ipv6Addr>::into(*self))
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

pub fn socket(
    domain: AddressFamilies,
    socktype: SocketType,
    extra_behavior: ExtraBehavior,
    protocol: SocketProtocol,
) -> errno::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            Into::<c_int>::into(domain),
            Into::<c_int>::into(socktype) | extra_behavior.to_bits() as c_int,
            protocol.to_protocol() as c_int,
        )
    };

    if fd == -1 {
        Err(errno::last_os_error())
    }
    else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

pub fn recvfrom(
    sock: BorrowedFd,
    buf: &mut [u8],
    flags: Flags,
    addr: SockAddr,
) -> errno::Result<size_t> {
    let ret = unsafe {
        libc::recvfrom(
            sock.as_raw_fd(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            flags.to_bits() as i32,
            &mut addr.address() as *mut sockaddr,
            &mut (addr.address_len() as u32) as *mut socklen_t,
        )
    };

    if ret < 0 {
        Err(errno::last_os_error())?
    }

    Ok(ret as usize)
}

pub fn recv(
    sock: BorrowedFd,
    buf: &mut [u8],
    flags: Flags,
) -> errno::Result<size_t> {
    let ret = unsafe {
        libc::recv(
            sock.as_raw_fd(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            flags.to_bits() as i32,
        )
    };

    if ret < 0 {
        Err(errno::last_os_error())?
    }

    Ok(ret as usize)
}

pub fn sendto(
    sock: BorrowedFd,
    msg: &[u8],
    flags: Flags,
    addr: SockAddr,
) -> errno::Result<size_t> {
    let ret = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            msg.as_ptr() as *const c_void,
            msg.len(),
            flags.to_bits() as i32,
            &addr.address() as *const sockaddr,
            addr.address_len() as socklen_t,
        )
    };

    if ret < 0 {
        Err(errno::last_os_error())?
    }

    Ok(ret as usize)
}

pub fn send(
    sock: BorrowedFd,
    msg: &[u8],
    flags: Flags,
) -> errno::Result<size_t> {
    let ret = unsafe {
        libc::send(
            sock.as_raw_fd(),
            msg.as_ptr() as *const c_void,
            msg.len(),
            flags.to_bits() as i32,
        )
    };

    if ret < 0 {
        Err(errno::last_os_error())?
    }

    Ok(ret as usize)
}
