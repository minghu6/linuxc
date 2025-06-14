
use int_enum::IntEnum;
use m6tobytes::derive_to_bits;
use osimodel::datalink::{ EthProto, EthType};

////////////////////////////////////////////////////////////////////////////////
//// Structures

/// withc IEEE protocol numnber + IEEE reserved Linux spec number
///
/// ref [IEEE-802](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, IntEnum)]
#[derive_to_bits(u16)]
#[repr(u16)]
#[non_exhaustive]
pub enum EthTypeSpec {
    ALL = 0x0003,

    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl EthTypeSpec {
    pub fn into_proto(self) -> EthProto {
        let ety: EthType = self.into();
        ety.into()
    }
}

impl Into<EthType> for EthTypeSpec {
    fn into(self) -> EthType {
        unsafe { EthType::new_unchecked(self.to_bits()) }
    }
}

impl TryFrom<EthType> for EthTypeSpec {
    type Error = u16;

    fn try_from(value: EthType) -> Result<Self, Self::Error> {
        EthTypeSpec::try_from(value.to_ne())
    }
}
