//! Socket Address Family

use std::{
    net::Ipv4Addr,
    os::fd::{FromRawFd, OwnedFd},
};

use derive_more::derive::Deref;
use int_enum::IntEnum;
use libc::{
    SOCK_CLOEXEC, SOCK_NONBLOCK, c_int,
};
use m6tobytes::{derive_from_bits, derive_to_bits};
use osimodel::{datalink::Mac, network::ip::ProtocolSpec};

use crate::{
    be::{EthTypeBe, HTypeBe, SaFamilyBe, U16Be, U32Be},
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

/// Synonym libc::sockaddr_in
#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct SockAddrIn {
    /// In Native Order for it's not be transmit
    pub family: SaFamily,
    pub port: U16Be,
    /// IPv4 Address
    pub addr: InAddr,
    pub zero_pading: [u8; 8],
}

#[derive(Default, Clone, Copy, Eq, PartialEq, Hash, Deref)]
pub struct InAddr(U32Be);

///
/// Socket Address Link Layer (sockaddr_ll)
#[repr(C)]
pub struct SockAddrLL {
    /// unsigned short be
    pub family: SaFamilyBe,
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

#[repr(transparent)]
pub struct PhyAddr([u8; 8]);

/// Ref [address_families](https://man7.org/linux/man-pages/man7/address_families.7.html)
///
#[derive(Debug, IntEnum)]
#[repr(u32)]
pub enum AdressFamilies {
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
#[repr(u32)]
#[non_exhaustive]
pub enum SocketType {
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

////////////////////////////////////////////////////////////////////////////////
//// Implementations

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

impl From<Mac> for PhyAddr {
    fn from(value: Mac) -> Self {
        Self(value.into_arr8())
    }
}

impl std::fmt::Debug for InAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, b) in self.to_ne_bytes().iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }

            write!(f, "{b}")?;
        }

        Ok(())
    }
}

impl Into<Ipv4Addr> for InAddr {
    fn into(self) -> Ipv4Addr {
        Ipv4Addr::from_bits(self.to_ne())
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

pub fn socket(
    domain: AdressFamilies,
    r#type: SocketType,
    extra_behavior: ExtraBehavior,
    protocol: ProtocolSpec,
) -> errno::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            Into::<u32>::into(domain) as c_int,
            Into::<u32>::into(r#type) as c_int
                | extra_behavior.to_bits() as c_int,
            protocol.to_bits() as c_int,
        )
    };

    if fd == -1 {
        Err(errno::last_os_error())
    }
    else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
