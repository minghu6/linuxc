//! aaa
//!

use std::net::{Ipv4Addr, Ipv6Addr};

use derive_more::derive::{Deref, DerefMut};
use ifstructs::ifreq;

use crate::errno::{self, PosixError};

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
    #[cfg(target_os = "linux")]
    Packet {
        name: String,
        stats: RtnlLinkStats,
    },
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

////////////////////////////////////////////////////////////////////////////////
//// Implementations

////////////////////////////////////////////////////////////////////////////////
//// Functions

pub fn ifreq(name: &str) -> errno::Result<ifreq> {
    ifreq::from_name(name).map_err(|_| PosixError::EINVAL)
}
