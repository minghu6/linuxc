//! Big Endianess

use m6tobytes::derive_to_bits;
use osimodel::datalink::{arp::HTypeSpec, EthType, EthTypeSpec};

////////////////////////////////////////////////////////////////////////////////
//// Macros

macro_rules! define_unsigned_be {
    ($( {
        struct_name=$struct_name: ident,
        storage_type=$origin_type: ty

    } ),* $(,)?) => {
        $(
            #[derive(Default, Clone, Copy, Hash, PartialEq, Eq)]
            #[repr(transparent)]
            pub struct $struct_name($origin_type);

            impl $struct_name {
                /// from from_ne
                pub const fn new(x: $origin_type) -> Self {
                    Self::from_ne(x)
                }

                pub const fn from_ne(x: $origin_type) -> Self {
                    Self(x.to_be())
                }

                pub const fn from_le(x: $origin_type) -> Self {
                    Self::new(<$origin_type>::from_le(x))
                }

                pub const fn from_be(x: $origin_type) -> Self {
                    Self::new(<$origin_type>::from_be(x))
                }

                pub const fn to_ne(&self) -> $origin_type {
                    <$origin_type>::from_be(self.0)
                }

                pub const fn to_ne_bytes(&self) -> [u8; std::mem::size_of::<$origin_type>()] {
                    self.to_ne().to_ne_bytes()
                }
            }

            impl std::fmt::Debug for $struct_name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "{}", self.to_ne())
                }
            }
        )*
    };
}

// macro_rules! define_be_wrapper {
//     ({
//         struct_name=$struct_name: ident,
//         storage_type=$storage_type: ty,
//         foreign_spec_type=$foreign_spec_type: ty,
//         to_foreign_spec_type_name=$to_foreign_spec_type_name: ident
//     }) => {
//         #[derive(Clone, Copy, Hash, PartialEq, Eq)]
//         #[repr(transparent)]
//         pub struct $struct_name($storage_type);

//         impl $struct_name {
//             pub fn new(t: $foreign_spec_type) -> Self {
//                 Self($storage_type::new(t.to_bits()))
//             }

//             pub fn $to_foreign_spec_type_name(self) -> $foreign_spec_type {
//                 unsafe { $struct_name::from_bits(self.0.to_ne()) }
//             }
//         }

//         impl std::fmt::Debug for $struct_name {
//             fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//                 write!(f, "{:?}", self.to_family())
//             }
//         }
//     }
// }

////////////////////////////////////////////////////////////////////////////////
//// Structures

define_unsigned_be! {
    { struct_name = U16Be, storage_type=u16 },
    { struct_name = U32Be, storage_type=u32 },
    { struct_name = U64Be, storage_type=u64 },
}

#[derive(Default, Clone, Copy, Hash, PartialEq, Eq)]
#[derive_to_bits(u16)]
#[repr(transparent)]
pub struct EthTypeBe(U16Be);

#[derive(Default, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct HTypeBe(U16Be);

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl HTypeBe {
    pub fn new(t: HTypeSpec) -> Self {
        Self(U16Be::new(t.to_bits()))
    }
}

impl From<HTypeSpec> for HTypeBe {
    fn from(value: HTypeSpec) -> Self {
        Self::new(value)
    }
}

impl EthTypeBe {
    pub fn new(t: EthTypeSpec) -> Self {
        Self(U16Be::new(t.to_bits()))
    }

    pub fn to_eth_type(self) -> EthTypeSpec {
        // If SaFamilyBe create with a valid SaFamily value
        unsafe { EthType::from_bits(self.0.to_ne()).into() }
    }
}

impl From<EthTypeSpec> for EthTypeBe {
    fn from(value: EthTypeSpec) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Debug for EthTypeBe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_eth_type())
    }
}

