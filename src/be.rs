//! Big Endianess

////////////////////////////////////////////////////////////////////////////////
//// Macros

use osimodel::datalink::{EthType, EthTypeSpec};

use crate::socket::SaFamily;

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
                pub const fn new(x: $origin_type) -> Self {
                    Self::from_ne(x)
                }

                pub const fn from_ne(x: $origin_type) -> Self {
                    Self(x.to_be())
                }

                pub const fn from_le(x: $origin_type) -> Self {
                    Self::from_ne(<$origin_type>::from_le(x))
                }

                pub const fn from_be(x: $origin_type) -> Self {
                    Self::from_ne(<$origin_type>::from_be(x))
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
#[repr(transparent)]
pub struct SaFamilyBe(U16Be);

#[derive(Default, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct EthTypeBe(U16Be);

#[derive(Default, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct HTypeBe(U16Be);

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl SaFamilyBe {
    pub fn new(t: SaFamily) -> Self {
        Self(U16Be::new(t.to_bits()))
    }

    pub fn to_family(self) -> SaFamily {
        // If SaFamilyBe create with a valid SaFamily value
        unsafe { SaFamily::from_bits(self.0.to_ne()) }
    }
}

impl std::fmt::Debug for SaFamilyBe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_family())
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

impl std::fmt::Debug for EthTypeBe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_eth_type())
    }
}

