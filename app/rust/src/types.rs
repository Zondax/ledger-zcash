pub type Diversifier = [u8; 11];

pub fn diversifier_zero() -> Diversifier {
    [0u8; 11]
}

// FIXME: This is not good design. Mayeb something like
// #[repr(C)]
// pub struct DiversifierList<const N: usize>(pub [u8; N * 11]);
pub type DiversifierList4 = [u8; 44];
pub type DiversifierList10 = [u8; 110];

pub type DiversifierList20 = [u8; 220];

pub fn diversifier_list10_zero() -> DiversifierList10 {
    [0u8; 110]
}

pub type AskBytes = [u8; 32];

pub type NskBytes = [u8; 32];

pub type AkBytes = [u8; 32];

pub type NkBytes = [u8; 32];

pub type IvkBytes = [u8; 32];

pub type OvkBytes = [u8; 32];

pub type DkBytes = [u8; 32];

pub type Zip32SeedBytes = [u8; 32];

use ztruct::create_ztruct;

pub type Zip32MasterSpendingKey = [u8; 32];
pub type Zip32MasterChainCode = [u8; 32];

create_ztruct! {
    pub struct Zip32MasterKey {
        pub spending_key: Zip32MasterSpendingKey,
        pub chain_code: Zip32MasterChainCode,
    }
}

create_ztruct! {
    pub struct FullViewingKey {
        pub ak: AkBytes,
        pub nk: NkBytes,
        pub ovk: OvkBytes,
    }
}

create_ztruct! {
    pub struct ExpandedSpendingKey {
        pub ask: AskBytes,
        pub nsk: NskBytes,
        pub ovk: OvkBytes,
    }
}
