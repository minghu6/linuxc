//!
//!

use std::{
    ffi::{ CStr, c_int },
    net::{Ipv4Addr, Ipv6Addr},
    os::fd::AsFd,
    ptr::null_mut,
};

use derive_more::derive::{Deref, DerefMut};
use ifstructs::ifreq;
use int_enum::IntEnum;
use libc::{freeifaddrs, getifaddrs, sockaddr_in, sockaddr_in6};
use osimodel::datalink::Mac;

use crate::{
    errno::{self, PosixError},
    ioctl::{ioctl, IoctlOpcode},
    socket::{socket, AddressFamily, InAddr, SaFamily, SockAddrIn, SockAddrLL, SocketType},
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
    },
    Inet6 {
        name: String,
        addr: Ipv6Addr,
        mask: Ipv6Addr,
    },
    /// Linux Spec `RtnlLinkStats`
    #[cfg(target_os = "linux")]
    Packet { name: String, ifindex: c_int, addr: Mac, stats: RtnlLinkStats },
}

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
    pub addr: Mac
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

            let item = if family == SaFamily::Inet {
                IfAddr::Inet {
                    name,
                    addr: InAddr::from((*((*ifa).ifa_addr as *mut sockaddr_in)).sin_addr).into(),
                    mask: InAddr::from((*((*ifa).ifa_addr as *mut sockaddr_in)).sin_addr).into(),
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

    let ty = HwType::try_from(unsafe { ifr.ifr_ifru.ifr_hwaddr.sa_family }).unwrap();
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
