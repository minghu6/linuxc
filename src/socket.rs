//! Socket Address Family

use std::{
    ffi::{c_int, c_void},
    fmt::Debug,
    mem::{transmute, transmute_copy},
    net::{Ipv4Addr, Ipv6Addr},
    ops::{BitAnd, BitOr},
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    ptr,
};

use derive_more::derive::{Deref, DerefMut};
use int_enum::IntEnum;
use libc::{
    SOCK_CLOEXEC, SOCK_NONBLOCK, in_addr, pid_t, sa_family_t, size_t,
    sockaddr, sockaddr_in, socklen_t,
};
use m6tobytes::{derive_from_bits, derive_to_bits};
use osimodel::{
    be::{U16Be, U32Be},
    datalink::{EthType, Mac, arp::HType},
    network::{
        IPv4Addr,
        ip::ProtocolKind,
    },
};
use strum::EnumIter;

use crate::{
    errno::{self, PosixError},
    ether::EthTypeKind,
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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
#[non_exhaustive]
pub enum SockAddr {
    Inet(SockAddrIn),
    Inet6(SockAddrIn6),
    Unix(SockAddrUn),
    Packet(SockAddrLL),
    #[cfg(target_os = "linux")]
    Netlink(SockAddrNL),
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

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
#[repr(C)]
pub struct SockAddrUn {
    pub family: SaFamily,
    pub path: [u8; 108],
}

///
/// Socket Address Link Layer (sockaddr_ll)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SockAddrLL {
    /// unsigned short be
    pub family: SaFamily,
    /// unsigned short be
    pub protocol: EthType,
    /// native order
    pub ifindex: i32,
    pub hatype: HType,
    pub pkttype: PktType,
    /// size of address size (for Mac is 6)
    pub halen: u8,
    /// physical layer address
    pub addr: PhyAddr,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SockAddrNL {
    pub family: SaNlFamily,
    pub _padding: u16,
    pub portid: pid_t,
    /// Multicast groups mask
    pub groups: u32,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(i32)]
pub enum SaNlFamily {
    #[default]
    NetlinkRoute = 16,
}

#[derive(Debug, Clone, Copy, Deref, DerefMut)]
#[repr(transparent)]
pub struct PhyAddr([u8; 8]);

/// Ref [address_families](https://man7.org/linux/man-pages/man7/address_families.7.html)
///
#[derive(Debug, IntEnum)]
#[repr(i32)]
pub enum AddressFamily {
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

///
/// Mapping Linux constant `ETH_P_XX`, these raw constant values exist overlap
///
/// and also convert to native or netword oder depend on context.
///
#[derive(Clone, Copy, Debug)]
pub enum SocketProtocol {
    IP(ProtocolKind),
    Eth(EthTypeKind),
    Zero,
    /// 0
    NetlinkRoute
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

#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Copy)]
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
    /// to raw protocol value:
    ///
    /// Transport Layer: keep native order (TCP, UDP)
    ///
    /// IP Layer: big endian (network order) (IP, ARP)
    ///
    pub fn to_protocol(&self) -> c_int {
        use SocketProtocol::*;

        match self {
            IP(protocol_spec) => protocol_spec.to_bits() as _,
            Eth(eth_type_spec) => eth_type_spec.to_bits().to_be() as _,
            Zero | NetlinkRoute => 0,
        }
    }

    pub fn from_raw_ip(value: u8) -> Self {
        Self::IP(ProtocolKind::from(value))
    }
}

impl From<EthTypeKind> for SocketProtocol {
    fn from(value: EthTypeKind) -> Self {
        Self::Eth(value)
    }
}

impl From<ProtocolKind> for SocketProtocol {
    fn from(value: ProtocolKind) -> Self {
        Self::IP(value)
    }
}

impl Default for SocketProtocol {
    fn default() -> Self {
        Self::Zero
    }
}

impl SockAddrIn {
    pub unsafe fn from_raw(raw: *const sockaddr) -> Self {
        unsafe { core::ptr::read(raw as *const Self) }
    }
}

impl From<Ipv4Addr> for SockAddrIn {
    fn from(value: Ipv4Addr) -> Self {
        Self {
            family: SaFamily::Inet,
            port: 0.into(),
            addr: value.into(),
            padding: Default::default(),
        }
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

impl Into<SockAddr> for SockAddrIn {
    fn into(self) -> SockAddr {
        SockAddr::Inet(self)
    }
}

impl ExtraBehavior {
    pub fn new() -> Self {
        Self::default()
    }

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

impl Into<SockAddr> for SockAddrUn {
    fn into(self) -> SockAddr {
        SockAddr::Unix(self)
    }
}

impl SockAddrIn6 {
    pub unsafe fn from_raw(raw: *const sockaddr) -> Self {
        unsafe { core::ptr::read(raw as *const Self) }
    }
}

impl Into<SockAddr> for SockAddrIn6 {
    fn into(self) -> SockAddr {
        SockAddr::Inet6(self)
    }
}

impl SockAddrLL {
    pub unsafe fn from_raw(raw: *const sockaddr) -> Self {
        unsafe { core::ptr::read(raw as *const Self) }
    }
}

impl Into<SockAddr> for SockAddrLL {
    fn into(self) -> SockAddr {
        SockAddr::Packet(self)
    }
}

impl Into<SockAddr> for SockAddrNL {
    fn into(self) -> SockAddr {
        SockAddr::Netlink(self)
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
            #[cfg(target_os = "linux")]
            Netlink(sock_addr_nl) => unsafe { transmute_copy(sock_addr_nl) },
        }
    }

    pub fn as_ptr(&self) -> *const sockaddr {
        use SockAddr::*;

        match self {
            Inet(sock_addr_in) => sock_addr_in as *const SockAddrIn as _,
            Inet6(sock_addr_in6) => sock_addr_in6 as *const SockAddrIn6 as _,
            Unix(sock_addr_un) => sock_addr_un as *const SockAddrUn as _,
            Packet(sock_addr_ll) => sock_addr_ll as *const SockAddrLL as _,
            #[cfg(target_os = "linux")]
            Netlink(sock_addr_nl) => sock_addr_nl as *const SockAddrNL as _,
        }
    }

    pub fn as_mut_ptr(&mut self) -> *mut sockaddr {
        self.as_ptr() as _
    }

    pub fn address_len(&self) -> socklen_t {
        use SockAddr::*;

        match self {
            Inet(..) => size_of::<SockAddrIn>() as _,
            Inet6(..) => size_of::<SockAddrIn6>() as _,
            Unix(..) => size_of::<SockAddrUn>() as _,
            Packet(..) => size_of::<SockAddrLL>() as _,
            #[cfg(target_os = "linux")]
            Netlink(..) => size_of::<SockAddrNL>() as _
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
                Self::Packet(SockAddrLL::from_raw(sockaddr))
            },
            SaFamily::Inet => unsafe {
                assert_eq!(addrlen as usize, size_of::<SockAddrIn>());
                Self::Inet(SockAddrIn::from_raw(sockaddr))
            },
            SaFamily::Inet6 => unsafe {
                assert_eq!(addrlen as usize, size_of::<SockAddrIn6>());
                Self::Inet6(SockAddrIn6::from_raw(sockaddr))
            },
            SaFamily::Packet => {
                Self::Unix(SockAddrUn::from_raw_parts(sockaddr, addrlen))
            }
        }
    }
}

impl From<Mac> for PhyAddr {
    fn from(value: Mac) -> Self {
        Self(value.into_arr8())
    }
}

impl Into<Mac> for PhyAddr {
    fn into(self) -> Mac {
        Mac::from_bytes(&self[..6])
    }
}

impl InAddr {
    pub fn to_bits(&self) -> u32 {
        self.0.to_ne()
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
        Self(U32Be::new(value.to_bits()))
    }
}

impl From<IPv4Addr> for InAddr {
    fn from(value: IPv4Addr) -> Self {
        InAddr(U32Be::new(value.to_bits()))
    }
}

impl Into<IPv4Addr> for InAddr {
    fn into(self) -> IPv4Addr {
        IPv4Addr::from_bits(self.to_bits())
    }
}

impl Into<Ipv4Addr> for InAddr {
    fn into(self) -> Ipv4Addr {
        Ipv4Addr::from_bits(self.to_ne())
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
    domain: AddressFamily,
    socktype: SocketType,
    extra_behavior: ExtraBehavior,
    protocol: SocketProtocol,
) -> errno::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            Into::<c_int>::into(domain),
            Into::<c_int>::into(socktype) | extra_behavior.to_bits() as c_int,
            protocol.to_protocol(),
        )
    };

    if fd == -1 {
        Err(errno::last_os_error())
    }
    else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

pub fn bind(sock: BorrowedFd, addr: SockAddr) -> errno::Result<()> {
    let ret = unsafe {
        libc::bind(sock.as_raw_fd(), addr.as_ptr(), addr.address_len())
    };

    if ret == -1 {
        Err(errno::last_os_error())?
    }

    Ok(())
}

pub fn recvfrom(
    sock: BorrowedFd,
    buf: &mut [u8],
    flags: Flags,
    mut addr: Option<SockAddr>,
) -> errno::Result<size_t> {
    let mut addrlen = addr.as_ref().map(|addr| addr.address_len());

    let ret = unsafe {
        libc::recvfrom(
            sock.as_raw_fd(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            flags.to_bits() as i32,
            addr.as_mut()
                .map(|addr| addr.as_mut_ptr())
                .unwrap_or_default(),
            addrlen
                .as_mut()
                .map(|addrlen_mut| core::ptr::from_mut(addrlen_mut))
                .unwrap_or_default(),
        )
    };

    // for now impl, addrlen is just be ignored since we don't handle this complicated case.

    if ret < 0 {
        Err(errno::last_os_error())?
    }

    Ok(ret as usize)
}

/// for non-blocking recvfrom all buf
pub fn recvfrom_all(
    sock: BorrowedFd,
    buf: &mut [u8],
    flags: Flags,
    addr: Option<SockAddr>,
) -> errno::Result<size_t> {
    let mut cnt = 0;

    loop {
        match recvfrom(sock, &mut buf[cnt..], flags, addr) {
            Ok(0) => break,
            Ok(n) => cnt += n,
            Err(ref err) if matches!(err, PosixError::EAGAIN) => break,
            Err(ref err) if matches!(err, PosixError::EINTR) => continue,
            Err(err) => Err(err)?,
        }
    }

    Ok(cnt)
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

pub fn recv_all(
    sock: BorrowedFd,
    buf: &mut [u8],
    flags: Flags,
) -> errno::Result<size_t> {
    let mut cnt = 0;

    loop {
        match recv(sock, &mut buf[cnt..], flags) {
            Ok(0) => break,
            Ok(n) => cnt += n,
            Err(ref err) if matches!(err, PosixError::EAGAIN) => break,
            Err(ref err) if matches!(err, PosixError::EINTR) => continue,
            Err(err) => Err(err)?,
        }
    }

    Ok(cnt)
}

pub fn sendto(
    sock: BorrowedFd,
    msg: &[u8],
    flags: Flags,
    addr: Option<SockAddr>,
) -> errno::Result<size_t> {
    let ret = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            msg.as_ptr() as *const c_void,
            msg.len(),
            flags.to_bits() as i32,
            addr.map(|addr| addr.as_ptr()).unwrap_or_default(),
            addr.map(|addr| addr.address_len()).unwrap_or_default(),
        )
    };

    if ret < 0 {
        Err(errno::last_os_error())?
    }

    Ok(ret as usize)
}

/// for non-blocking senfto all buf
pub fn sendto_all(
    sock: BorrowedFd,
    msg: &[u8],
    flags: Flags,
    addr: Option<SockAddr>,
) -> errno::Result<size_t> {
    let mut cnt = 0;

    loop {
        cnt += sendto(sock, &msg[cnt..], flags, addr)?;

        if cnt >= msg.len() {
            break;
        }
    }

    Ok(cnt)
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

pub fn send_all(
    sock: BorrowedFd,
    msg: &[u8],
    flags: Flags,
) -> errno::Result<size_t> {
    let mut cnt = 0;

    loop {
        cnt += send(sock, &msg[cnt..], flags)?;

        if cnt >= msg.len() {
            break;
        }
    }

    Ok(cnt)
}
