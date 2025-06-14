//! Refer [RFC-3549](https://datatracker.ietf.org/doc/html/rfc3549)

use std::{
    ffi::c_int,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::BitOr,
    os::fd::AsFd,
};

use int_enum::IntEnum;
use libc::size_t;
use m6ptr::{AlignedRawBufRef, RawBufRef};
use m6tobytes::derive_to_bits;
use osimodel::network::ip::ToS;
use strum::EnumIter;

use crate::{errno, iface::get_ifindex, socket::*};


pub const NLMSG_ALIGNTO: usize = 4;
pub const RTA_ALIGNTO: usize = 4;

////////////////////////////////////////////////////////////////////////////////
//// Traits

/// for Protocol Specific Data Structure map to bytes to comunication
pub trait FillBuf {
    /// how long buffer would be occupied
    fn buf_len(&self) -> usize;

    fn fill_buf(&self, buf: &mut [u8]);
}

////////////////////////////////////////////////////////////////////////////////
//// Structures

/// 4 bytes align
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct NlMsgHdr {
    /// Message Length (header included)
    pub len: u32,
    /// Message type
    pub ty: NlMsgType,
    pub flags: NlMsgFlags,
    /// be used to track messages
    pub seq: u32,
    /// Note that there isn't a 1:1 relationship between nlmsg_pid and
    /// the PID of the process if the message originated from a netlink socket
    pub pid: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[derive_to_bits(u16)]
#[repr(transparent)]
pub struct NlMsgType(u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NlMsgTypeKind {
    Ctrl(NlMsgCtrlType),
    Route(NlMsgRouteType),
    Oth(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntEnum)]
#[repr(u16)]
#[non_exhaustive]
pub enum NlMsgCtrlType {
    NoOp = 0x1,
    Error = 0x2,
    Done = 0x3,
    OverRun = 0x4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntEnum)]
#[repr(u16)]
#[non_exhaustive]
pub enum NlMsgRouteType {
    NewRoute = 24,
    GetRoute = 26,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive_to_bits(u16)]
#[repr(transparent)]
pub struct NlMsgFlags(u16);

#[derive(Clone, Copy, PartialEq, Eq, Debug, IntEnum, EnumIter)]
#[derive_to_bits(u16)]
#[repr(u16)]
pub enum NlMsgStdFlag {
    /// Must be set on all requests
    Request = 0x1,
    /// Multipart message,terminated by `NLMSG_DONE`
    Multi = 0x2,
    /// Reply with Ack (Acknowledge)
    Ack = 0x4,
    /// Echo this request
    Echo = 0x8,
    /// Dump was inconsistent (state changed during retrieval)
    DumpIntr = 0x10,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, IntEnum)]
#[derive_to_bits(u16)]
#[repr(u16)]
pub enum NlMsgGetFlag {
    /// Return complete table instead of single entry
    Root = 0x100,
    /// Return all entries matching criteria
    Match = 0x200,
    /// Return atomic snapshot (obsolete in modern kernels)
    Atomic = 0x400,
    /// Root + Match
    Dump = 0x300,
}

/// For Creation/Modification
#[derive(Clone, Copy, PartialEq, Eq, Debug, IntEnum)]
#[derive_to_bits(u16)]
#[repr(u16)]
pub enum NlMsgNewFlag {
    /// Replace existing matching configuration
    Replace = 0x100,
    /// Do not replace if exists
    Exec = 0x200,
    /// Create object if it doesn't exist
    Create = 0x400,
    /// Add to end of list
    Append = 0x800,
}

/// 4 bytes align
/// (Netlink) Route Message
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct RtMsgHdr {
    pub family: RtFamily,
    /// Length of destination subnet mask, 0 for wild
    pub dst_len: u8,
    /// Length of source subnet mask, 0 for wild
    pub src_len: u8,
    pub tos: ToS,
    pub table: RtMsgTable,
    pub protocol: RtMsgProto,
    pub scope: RtMsgScope,
    pub ty: RtType,
    pub flags: RtMsgFlags,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, IntEnum)]
#[repr(u8)]
pub enum RtFamily {
    Unspec = 0,
    IPv4 = 2,
    IPv6 = 10,
}

/// Route Message Table
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct RtMsgTable(u8);

/// Route Message Table
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct RtMsgProto(u8);

/// Route Message Table
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, IntEnum)]
#[repr(u8)]
pub enum RtMsgScope {
    #[default]
    Universe = 0,
    Site = 200,
    Link = 253,
    Host = 254,
    Nowhere = 255,
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, IntEnum)]
#[repr(u8)]
pub enum RtType {
    #[default]
    Unspec = 0,
    Unicast = 1,
    Local = 2,
    Broadcast = 3,
    Anycast = 4,
    Multicast = 5,
    Blackhole = 6,
    Unreachable = 7,
    Prohibit = 8,
    Throw,
    Nat,
    Xresolve = 11,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[derive_to_bits(u32)]
#[repr(transparent)]
pub struct RtMsgFlags(u32);

#[derive(Clone, Copy, PartialEq, Eq, IntEnum, EnumIter, Debug)]
#[derive_to_bits(u32)]
#[repr(u32)]
pub enum RtMsgFlag {
    Notify = 0x100,
    Cloned = 0x200,
    Equalize = 0x400,
    Prefix = 0x800,
}

/// align 4 bytes
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RtAttrHdr {
    pub len: u16,
    pub ty: RtAttrType,
}

#[derive(Clone, Copy)]
#[derive_to_bits(u16)]
#[repr(transparent)]
pub struct RtAttrType(u16);

/// Route Attribute Type
#[derive(Clone, Copy, PartialEq, Eq, EnumIter, Debug)]
#[derive_to_bits(u16)]
#[repr(u16)]
#[non_exhaustive]
pub enum RtAttrKind {
    Iif = 3,
    Oif = 4,
    Gateway = 5,
    Oth(u16),
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum RtReqAttr {
    /// Output Interface
    OIf(c_int),
    /// Input Inetrface
    IIf(c_int),
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum RtRespAttr {
    Gateway(IpAddr),
    OIf(c_int),
    Oth,
}

// pub struct NetlinkResponse {
//     pub hdr: NlMessageHeader,
//     pub payload: Option<NlMessagePayload>,
// }

// pub enum NlMessagePayload {
//     Route(RouteMessage),
//     Oth(Vec<u8>),
// }

pub(crate) struct NlMsgRaw {
    pub hdr: NlMsgHdr,
    pub payload: AlignedRawBufRef,
}

pub(crate) struct RtMsgRaw {
    pub hdr: RtMsgHdr,
    pub attrs: Vec<RtAttrRaw>,
}

pub(crate) struct RtAttrRaw {
    pub hdr: RtAttrHdr,
    pub payload: RawBufRef,
}

pub struct RtMsg {
    pub hdr: RtMsgHdr,
    pub attrs: Vec<RtRespAttr>,
}

pub(crate) struct RtRespMsg {
    pub hdr: RtMsgHdr,
    pub attrs: Vec<RtRespAttr>,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl RtAttrType {
    pub fn to_kind(&self) -> RtAttrKind {
        let x = self.to_bits();

        match x {
            3 | 4 | 5 => unsafe { core::mem::transmute(x as u32) },
            _ => RtAttrKind::Oth(x),
        }
    }
}

impl std::fmt::Debug for RtAttrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_kind())
    }
}

impl Into<RtAttrType> for RtAttrKind {
    fn into(self) -> RtAttrType {
        RtAttrType(self.to_bits())
    }
}

impl RtRespAttr {
    pub(crate) fn parse_from_raw_rta(rth: RtMsgHdr, rta: RtAttrRaw) -> Self {
        let RtAttrRaw { hdr, payload } = rta;

        match hdr.ty.to_kind() {
            RtAttrKind::Iif => todo!(),
            RtAttrKind::Oif => {
                Self::OIf(payload.cast::<i32>().read_unaligned())
            }
            RtAttrKind::Gateway => Self::Gateway(match rth.family {
                RtFamily::Unspec => unimplemented!(),
                RtFamily::IPv4 => IpAddr::V4(Ipv4Addr::from_octets(
                    payload.head_slice().try_into().unwrap(),
                )),
                RtFamily::IPv6 => IpAddr::V6(Ipv6Addr::from_octets(
                    payload.head_slice().try_into().unwrap(),
                )),
            }),
            RtAttrKind::Oth(_) => Self::Oth,
        }
    }
}

impl NlMsgHdr {
    pub const fn payload_len(&self) -> usize {
        if (self.len as usize) < size_of::<Self>() {
            0
        }
        else {
            self.len as usize - size_of::<Self>()
        }
    }
}

impl RtAttrHdr {
    pub const fn payload_len(&self) -> usize {
        if (self.len as usize) < size_of::<Self>() {
            0
        }
        else {
            self.len as usize - size_of::<Self>()
        }
    }
}

impl RtReqAttr {
    pub fn kind(&self) -> RtAttrKind {
        use RtAttrKind::*;

        match self {
            RtReqAttr::OIf(..) => Oif,
            RtReqAttr::IIf(..) => Iif,
        }
    }

    pub fn header(&self, data_len: usize) -> RtAttrHdr {
        RtAttrHdr {
            len: rta_len(data_len) as _,
            ty: self.kind().into(),
        }
    }
}

impl FillBuf for RtReqAttr {
    fn buf_len(&self) -> usize {
        use RtReqAttr::*;

        match self {
            OIf(..) | IIf(..) => rta_len(4),
        }
    }

    fn fill_buf(&self, buf: &mut [u8]) {
        assert!(buf.len() >= self.buf_len());

        todo!()
    }
}

impl RtMsg {
    /// Assume gateway address is IPv4
    pub fn get_gateway(&self) -> Option<IpAddr> {
        self.attrs.iter().find_map(|attr| {
            if let RtRespAttr::Gateway(ip) = attr {
                Some(*ip)
            }
            else {
                None
            }
        })
    }
}

impl PartialEq<RtAttrKind> for &RtAttrKind {
    fn eq(&self, other: &RtAttrKind) -> bool {
        *self == other
    }
}

impl PartialEq<&Self> for RtAttrKind {
    fn eq(&self, other: &&Self) -> bool {
        self == *other
    }
}

impl BitOr<RtMsgFlag> for RtMsgFlags {
    type Output = Self;

    fn bitor(self, rhs: RtMsgFlag) -> Self::Output {
        Self(self.to_bits() | rhs.to_bits())
    }
}

impl BitOr<RtMsgFlag> for RtMsgFlag {
    type Output = RtMsgFlags;

    fn bitor(self, rhs: RtMsgFlag) -> Self::Output {
        RtMsgFlags(self.to_bits() | rhs.to_bits())
    }
}

impl RtMsgProto {
    pub const UNSPEC: Self = Self(0);
    pub const REDIRECT: Self = Self(0);
    pub const KERNEL: Self = Self(0);
    pub const BOOT: Self = Self(0);
    pub const STATIC: Self = Self(0);

    pub fn custom(v: u8) -> Self {
        assert!(v >= 5);

        Self(v)
    }
}

impl RtMsgTable {
    pub const UNSPEC: Self = Self(0);
    pub const COMPAT: Self = Self(252);
    pub const DEFAULT: Self = Self(253);
    pub const MAIN: Self = Self(254);
    pub const LOCAL: Self = Self(255);

    pub fn custom(v: u8) -> Self {
        assert!(v > 0 && v <= 251);

        Self(v)
    }
}

impl BitOr<NlMsgStdFlag> for NlMsgFlags {
    type Output = Self;

    fn bitor(self, rhs: NlMsgStdFlag) -> Self::Output {
        Self(self.to_bits() | rhs.to_bits())
    }
}

impl BitOr<NlMsgGetFlag> for NlMsgFlags {
    type Output = Self;

    fn bitor(self, rhs: NlMsgGetFlag) -> Self::Output {
        Self(self.to_bits() | rhs.to_bits())
    }
}

impl BitOr<NlMsgNewFlag> for NlMsgFlags {
    type Output = Self;

    fn bitor(self, rhs: NlMsgNewFlag) -> Self::Output {
        Self(self.to_bits() | rhs.to_bits())
    }
}

impl BitOr<NlMsgStdFlag> for NlMsgStdFlag {
    type Output = NlMsgFlags;

    fn bitor(self, rhs: NlMsgStdFlag) -> Self::Output {
        NlMsgFlags(self.to_bits() | rhs.to_bits())
    }
}

impl BitOr<NlMsgGetFlag> for NlMsgStdFlag {
    type Output = NlMsgFlags;

    fn bitor(self, rhs: NlMsgGetFlag) -> Self::Output {
        NlMsgFlags(self.to_bits() | rhs.to_bits())
    }
}

impl BitOr<NlMsgNewFlag> for NlMsgStdFlag {
    type Output = NlMsgFlags;

    fn bitor(self, rhs: NlMsgNewFlag) -> Self::Output {
        NlMsgFlags(self.to_bits() | rhs.to_bits())
    }
}

impl NlMsgType {
    pub fn to_kind(&self) -> NlMsgTypeKind {
        (*self).into()
    }
}

impl std::fmt::Debug for NlMsgType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_kind())
    }
}

impl PartialEq<NlMsgCtrlType> for NlMsgType {
    fn eq(&self, other: &NlMsgCtrlType) -> bool {
        self.to_bits() == (*other).into()
    }
}

impl Into<NlMsgType> for NlMsgRouteType {
    fn into(self) -> NlMsgType {
        NlMsgType(self.into())
    }
}

impl From<NlMsgType> for NlMsgTypeKind {
    fn from(value: NlMsgType) -> Self {
        use NlMsgTypeKind::*;

        let v = value.to_bits();

        match v {
            0..=4 => Ctrl(NlMsgCtrlType::try_from(v).unwrap()),
            26 => Route(NlMsgRouteType::GetRoute),
            _ => Oth(v),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

/// C macro NLMSG_ALIGN
///
/// 4 bytes align
pub const fn nlmsg_align(len: size_t) -> size_t {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

///
/// C macro NLMSG_LENGTH
///
/// Given the payload size, size, this macro returns the aligned size to store in the nlmsg_len
/// field of the nlmsghdr.
///
pub const fn nlmsg_length(size: size_t) -> usize {
    nlmsg_align(core::mem::size_of::<NlMsgHdr>()) + size
}

// /// forward ptr to nlmsg data
// pub const fn nlmsg_data(buf: &mut AlignedRawBufRef) {
//     buf.forward_bytes(core::mem::size_of::<NlMessageHeader>());
// }

pub const fn nlmsg_ok(buf: &AlignedRawBufRef) -> bool {
    let len = buf.rem_len();

    if len >= size_of::<NlMsgHdr>() {
        let nlh_len = buf.cast_ref::<NlMsgHdr>().len as usize;

        nlh_len >= size_of::<NlMsgHdr>() && nlh_len <= len
    }
    else {
        false
    }
}


// /// forward ptr to rtmsg header
// pub const fn rtm_rta(buf: &mut AlignedRawBufRef) {
//     buf.forward_bytes(core::mem::size_of::<RtMessageHeader>());
// }

pub const fn rta_ok(buf: &AlignedRawBufRef) -> bool {
    let len = buf.rem_len();

    if len >= size_of::<RtAttrHdr>() {
        let rta_len = buf.cast_ref::<RtAttrHdr>().len as usize;

        rta_len >= size_of::<RtAttrHdr>() && rta_len <= len
    }
    else {
        false
    }
}

///
/// C macro style RTA_LENGTH
///
/// size: rta payload length
///
pub fn rta_len(size: size_t) -> size_t {
    size_of::<RtAttrHdr>() + size
}

/// ```no_main
/// ┌───────────────────┐
/// │ nlmsghdr (16)     │
/// ├───────────────────┤
/// │ rtmsg (12)        │
/// ├───────────────────┤
/// │ Attribute 1       │
/// │  - rta header (4) │
/// │  - data (4)       │
/// ├───────────────────┤
/// │ Attribute 2       │
/// └───────────────────┘
/// ```
/// Low-level Netlink implementation
pub fn get_gateway_ipv4_by_ifname(
    ifname: &str,
) -> errno::Result<Option<Ipv4Addr>> {
    let ifindex = get_ifindex(ifname)?;

    let sock = socket(
        AddressFamily::NETLINK,
        SocketType::RAW,
        ExtraBehavior::new().non_block(),
        SocketProtocol::NetlinkRoute,
    )?;

    // 3. Bind socket to kernel
    let addr = SockAddrNL::default();

    bind(sock.as_fd(), addr.into())?;

    // 4. Build route request message

    let mut nlh = NlMsgHdr {
        len: 0,
        ty: NlMsgRouteType::GetRoute.into(),
        flags: NlMsgStdFlag::Request | NlMsgGetFlag::Dump,
        seq: Default::default(),
        pid: Default::default(),
    };

    let rth = RtMsgHdr {
        family: RtFamily::IPv4,
        dst_len: Default::default(),
        src_len: Default::default(),
        tos: ToS::default(),
        table: RtMsgTable::MAIN,
        protocol: RtMsgProto::UNSPEC,
        scope: RtMsgScope::Universe,
        ty: RtType::Unspec,
        flags: RtMsgFlags::default(),
    };

    let oif_attr = RtReqAttr::OIf(ifindex).header(size_of::<u32>());

    nlh.len =
        nlmsg_length(size_of::<RtMsgHdr>() + oif_attr.len as size_t) as _;

    let mut buf = [0u8; 1024];
    let mut buf_ref = AlignedRawBufRef::from_slice(&mut buf, NLMSG_ALIGNTO);

    buf_ref.consume::<NlMsgHdr>().write(nlh);
    buf_ref.consume::<RtMsgHdr>().write(rth);

    buf_ref.consume::<RtAttrHdr>().write(oif_attr);
    // native order u32
    buf_ref.consume::<u32>().write(ifindex as _);

    // 5. Send

    send_all(sock.as_fd(), buf_ref.consumed_slice(), Default::default())?;

    // 6 Recv

    buf.fill(0);

    let rev_len = recv_all(sock.as_fd(), &mut buf, Default::default())?;

    // 6. Parse route response message

    let nlmsgs = parse_nlm_raw(&buf[..rev_len]);
    let rtmsgs_raw = parse_rtm_raw(nlmsgs);
    let rtmsgs_resp = parse_rtm_resp(rtmsgs_raw);

    for RtRespMsg { hdr: rtmh, attrs } in rtmsgs_resp {
        if rtmh.family != RtFamily::IPv4 {
            continue
        }

        let Some(outifindex) = attrs.iter().find_map(|attr| {
            if let RtRespAttr::OIf(ifindex) = attr {
                Some(*ifindex)
            }
            else {
                None
            }
        })
        else {
            continue;
        };

        if ifindex != outifindex {
            continue
        }

        if let Some(ip) = attrs.iter().find_map(|attr| {
            if let RtRespAttr::Gateway(ipaddr) = attr {
                Some(match ipaddr {
                    IpAddr::V4(ipv4_addr) => *ipv4_addr,
                    IpAddr::V6(_ipv6_addr) => unreachable!(),
                })
            }
            else {
                None
            }
        }) {
            return Ok(Some(ip));
        }
    }

    Ok(None)
}

pub(crate) fn parse_nlm_raw<'a>(buf: &'a [u8]) -> Vec<NlMsgRaw> {
    let mut buf = AlignedRawBufRef::from_slice(buf, NLMSG_ALIGNTO);
    let mut nlmsgs = vec![];

    while nlmsg_ok(&buf) {
        let nlh = buf.consume::<NlMsgHdr>().read();

        if nlh.ty == NlMsgCtrlType::Done {
            break;
        }

        nlmsgs.push(NlMsgRaw {
            hdr: nlh,
            payload: buf.consume_bytes(nlh.payload_len()),
        });
    }

    nlmsgs
}

pub(crate) fn parse_rtm_raw<'a>(nlmsgs: Vec<NlMsgRaw>) -> Vec<RtMsgRaw> {
    let mut rtmsgs = vec![];

    for NlMsgRaw {
        hdr: _nlh,
        payload: mut buf,
    } in nlmsgs
    {
        let rtmh = buf.consume::<RtMsgHdr>().read();

        // let attrs_len = nlh.payload_len() - size_of::<RtMsgHdr>();
        let mut attrs = vec![];

        while rta_ok(&buf) {
            let rtah = buf.consume::<RtAttrHdr>().read();

            attrs.push(RtAttrRaw {
                hdr: rtah,
                payload: buf.consume_bytes(rtah.payload_len()).into(),
            });
        }

        rtmsgs.push(RtMsgRaw { hdr: rtmh, attrs });
    }

    rtmsgs
}

pub(crate) fn parse_rtm_resp<'a>(raw_rtmsgs: Vec<RtMsgRaw>) -> Vec<RtRespMsg> {
    let mut rtmsgs = vec![];

    for RtMsgRaw { hdr, attrs } in raw_rtmsgs {
        let attrs = attrs
            .into_iter()
            .map(|rta| RtRespAttr::parse_from_raw_rta(hdr, rta))
            .collect();

        rtmsgs.push(RtRespMsg { hdr, attrs });
    }

    rtmsgs
}


#[cfg(test)]
mod tests {
    use crate::netlink::get_gateway_ipv4_by_ifname;

    #[test]
    fn test_get_gateway() {
        let ip_maybe  = get_gateway_ipv4_by_ifname("wlp2s0");

        println!("{ip_maybe:?}");
    }
}
