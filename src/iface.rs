//!
//!

use std::{
    ffi::{CStr, c_int},
    fmt::Debug,
    net::{Ipv4Addr, Ipv6Addr},
    ops::BitAnd,
    os::fd::AsFd,
    ptr::null_mut,
};

use derive_more::derive::{Deref, DerefMut};
use ifstructs::ifreq;
use int_enum::IntEnum;
use libc::{freeifaddrs, getifaddrs, sockaddr_in, sockaddr_in6};
use m6tobytes::derive_to_bits;
use osimodel::datalink::Mac;
use strum::{EnumIter, IntoEnumIterator};

use crate::{
    errno::{self, PosixError},
    ioctl::{IoctlOpcode, ioctl},
    socket::{
        AddressFamily, InAddr, SaFamily, SockAddrIn, SockAddrLL, SocketType,
        socket,
    },
};

////////////////////////////////////////////////////////////////////////////////
//// Constants


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug, Deref, DerefMut)]
#[repr(transparent)]
pub struct IfAddrTbl(Vec<IfAddr>);

/// Support AF_INET, AF_INET6, AF_PACKET
#[derive(Debug)]
pub enum IfAddr {
    Inet {
        name: String,
        addr: Ipv4Addr,
        mask: Ipv4Addr,
        flags: IfFlags,
    },
    Inet6 {
        name: String,
        addr: Ipv6Addr,
        mask: Ipv6Addr,
        flags: IfFlags,
    },
    /// Linux Spec `RtnlLinkStats`
    #[cfg(target_os = "linux")]
    Packet {
        name: String,
        ifindex: c_int,
        addr: Mac,
        flags: IfFlags,
        stats: RtnlLinkStats,
    },
}

/// for IFF_XXX (Interface Flag XXX)
#[derive(Debug, IntEnum, EnumIter, Clone, Copy)]
#[derive_to_bits(u32)]
#[repr(u32)]
pub enum IfFlag {
    /// Software/admin state (interface enabled)
    ///
    /// be independent with `Running`
    Up = 0x1,
    Broadcast = 0x2,
    Debug = 0x4,
    Loopback = 0x8,
    PointToPoint = 0x10,
    /// ​​Trailer encapsulation​​ (or ​​trailer protocols​​) is an ​​obsolete
    /// network optimization technique​​
    NoTrailer = 0x20,
    /// Hardware/physical state (link operational)
    ///
    /// be independent with `Up`
    Running = 0x40,
    /// Interface doesn't support ARP
    NoARP = 0x80,
    /// Interface in promiscuous mode (receives all packets)
    Promisc = 0x100,
    /// Forces a network interface to ​​receive all multicast packets​​ on the network segment
    ///
    /// Similar to promiscuous mode (IFF_PROMISC) but limited to multicast traffic only.
    AllMulti = 0x200,
    #[cfg(target_os = "linux")]
    Master = 0x400,
    #[cfg(target_os = "linux")]
    Slave = 0x800,
    Multicast = 0x1000,
    /// Port Selection
    #[cfg(target_os = "linux")]
    PortSel = 0x2000,
    /// Auto media selection active
    #[cfg(target_os = "linux")]
    AutoMedia = 0x4000,
    #[cfg(target_os = "linux")]
    Dynamic = 0x8000,
}

#[derive(Clone, Copy)]
#[derive_to_bits(u32)]
#[repr(transparent)]
pub struct IfFlags(u32);

#[derive(Default, Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RtnlLinkStats {
    rx_packets: u32,
    tx_packets: u32,
    rx_bytes: u32,
    tx_bytes: u32,
    rx_errors: u32,
    tx_errors: u32,
    rx_dropped: u32,
    tx_dropped: u32,
    multicast: u32,
    collisions: u32,
    /* detailed rx_errors: */
    rx_length_errors: u32,
    rx_over_errors: u32,
    rx_crc_errors: u32,
    rx_frame_errors: u32,
    rx_fifo_errors: u32,
    rx_missed_errors: u32,
    /* detailed tx_errors */
    tx_aborted_errors: u32,
    tx_carrier_errors: u32,
    tx_fifo_errors: u32,
    tx_heartbeat_errors: u32,
    tx_window_errors: u32,
    /* for cslip etc */
    rx_compressed: u32,
    tx_compressed: u32,
    rx_nohandler: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct HwAddr {
    pub ty: HwType,
    pub addr: Mac,
}

/// Mapping from `ARPHRD_XXX`
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, IntEnum)]
#[repr(u16)]
#[non_exhaustive]
pub enum HwType {
    Ether = 1,
    /// Point to Point Protocol
    PPP = 512,
    Tunnel = 768,
    Tunnel6 = 769,
    Loopback = 772,
    /// Wi-Fi
    IEEE80211 = 801,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl IntoIterator for IfAddrTbl {
    type Item = IfAddr;

    type IntoIter = impl Iterator<Item = IfAddr>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl BitAnd<IfFlag> for IfFlags {
    type Output = bool;

    fn bitand(self, rhs: IfFlag) -> Self::Output {
        self.to_bits() & rhs.to_bits() != 0
    }
}

impl BitAnd<IfFlag> for &IfFlags {
    type Output = bool;

    fn bitand(self, rhs: IfFlag) -> Self::Output {
        self.clone() & rhs
    }
}

impl Debug for IfFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut builder = &mut f.debug_list();

        for flag in IfFlag::iter() {
            if self & flag {
                builder = builder.entry(&flag);
            }
        }

        builder.finish()
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

pub fn get_ifaddrtbl() -> errno::Result<IfAddrTbl> {
    unsafe {
        let mut ifa = null_mut();

        getifaddrs(&mut ifa);

        let mut items = vec![];

        while !ifa.is_null() {
            if (*ifa).ifa_addr.is_null() {
                ifa = (*ifa).ifa_next;
                continue;
            }

            let family = SaFamily::from_bits((*(*ifa).ifa_addr).sa_family);

            let name =
                CStr::from_ptr((*ifa).ifa_name).to_str().unwrap().to_owned();

            let flags = IfFlags((*ifa).ifa_flags);

            let item = if family == SaFamily::Inet {
                IfAddr::Inet {
                    name,
                    addr: InAddr::from(
                        (*((*ifa).ifa_addr as *mut sockaddr_in)).sin_addr,
                    )
                    .into(),
                    mask: InAddr::from(
                        (*((*ifa).ifa_addr as *mut sockaddr_in)).sin_addr,
                    )
                    .into(),
                    flags,
                }
            }
            else if family == SaFamily::Inet6 {
                IfAddr::Inet6 {
                    name,
                    addr: Ipv6Addr::from(
                        (*((*ifa).ifa_addr as *mut sockaddr_in6))
                            .sin6_addr
                            .s6_addr,
                    ),
                    mask: Ipv6Addr::from(
                        (*((*ifa).ifa_netmask as *mut sockaddr_in6))
                            .sin6_addr
                            .s6_addr,
                    ),
                    flags,
                }
            }
            else if family == SaFamily::Packet && !(*ifa).ifa_data.is_null()
            {
                let sockaddr = SockAddrLL::from_raw((*ifa).ifa_addr);

                let ifindex = sockaddr.ifindex;
                let addr = sockaddr.addr.into();

                IfAddr::Packet {
                    name,
                    stats: *((*ifa).ifa_data as *const RtnlLinkStats),
                    ifindex,
                    addr,
                    flags,
                }
            }
            else {
                unimplemented!()
            };

            items.push(item);

            ifa = (*ifa).ifa_next;
        }

        freeifaddrs(ifa);

        Ok(IfAddrTbl(items))
    }
}

///
/// It's derivation function of `get_ifaddrtbl`
///
pub fn get_available_ipv4_ifname() -> errno::Result<Vec<String>> {
    get_ifaddrtbl().map(|tbl| {
        tbl.into_iter()
            .filter_map(|ifaddr| {
                if let IfAddr::Inet { name, flags, .. } = ifaddr {
                    if flags & IfFlag::Up
                        && flags & IfFlag::Running
                        && !(flags & IfFlag::Loopback)
                    {
                        Some(name)
                    }
                    else {
                        None
                    }
                }
                else {
                    None
                }
            })
            .collect()
    })
}

pub(crate) fn ifreq(name: &str) -> errno::Result<ifreq> {
    ifreq::from_name(name).map_err(|_| PosixError::EINVAL)
}

pub fn get_ifindex(name: &str) -> errno::Result<c_int> {
    let mut ifr = ifreq(name)?;

    let fd = socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        Default::default(),
        Default::default(),
    )?;

    ioctl(fd.as_fd(), IoctlOpcode::GetIfaceIndex, Some(&mut ifr))?;

    Ok(unsafe { ifr.ifr_ifru.ifr_ifindex })
}

pub fn get_ifhwaddr(name: &str) -> errno::Result<HwAddr> {
    let mut ifr = ifreq(name)?;

    let fd = socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        Default::default(),
        Default::default(),
    )?;

    ioctl(fd.as_fd(), IoctlOpcode::GetIfaceHwAddr, Some(&mut ifr))?;

    let ty = HwType::try_from(unsafe { ifr.ifr_ifru.ifr_hwaddr.sa_family })
        .unwrap();
    let addr = Mac::from(unsafe { ifr.ifr_ifru.ifr_hwaddr.sa_data });

    Ok(HwAddr { ty, addr })
}

pub fn get_ifmtu(name: &str) -> errno::Result<c_int> {
    let mut ifr = ifreq(name)?;

    let fd = socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        Default::default(),
        Default::default(),
    )?;

    ioctl(fd.as_fd(), IoctlOpcode::GetIfMTU, Some(&mut ifr))?;

    Ok(unsafe { ifr.ifr_ifru.ifr_mtu })
}

pub fn get_ifip(name: &str) -> errno::Result<InAddr> {
    let mut ifr = ifreq(name)?;

    let fd = socket(
        AddressFamily::INET,
        SocketType::DGRAM,
        Default::default(),
        Default::default(),
    )?;

    ioctl(fd.as_fd(), IoctlOpcode::GetIfaceAddr, Some(&mut ifr))?;

    Ok(SockAddrIn::from(unsafe { ifr.ifr_ifru.ifr_addr }).addr)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_addr_tbl() {
        let tbl = get_ifaddrtbl().unwrap();

        println!("{tbl:#?}");

        println!("{:?}", get_available_ipv4_ifname());
    }

    #[test]
    fn test_getifaddrs() {
        let name = "enp3s0";
        println!("{name}:");
        println!("{:?}", get_ifhwaddr(name));
        println!("{:?}", get_ifindex(name));
        println!("{:?}", get_ifip(name));

        let name = "lo";
        println!("{name}:");
        println!("{:?}", get_ifhwaddr(name));
        println!("{:?}", get_ifindex(name));
        println!("{:?}", get_ifip(name));

        let name = "wlp2s0";
        println!("{name}:");
        println!("{:?}", get_ifhwaddr(name));
        println!("{:?}", get_ifindex(name));
        println!("{:?}", get_ifip(name));
    }
}
