pub type Diversifier = [u8; 11];

pub fn diversifier_zero() -> Diversifier {
    [0u8; 11]
}

// FIXME: This is not good design
pub type DiversifierList = [u8; 110];

pub fn diversifier_list_zero() -> DiversifierList {
    [0u8; 110]
}

pub type AskBytes = [u8; 32];

pub type NskBytes = [u8; 32];

pub type AkBytes = [u8; 32];

pub type NkBytes = [u8; 32];

pub type IvkBytes = [u8; 32];

pub type OvkBytes = [u8; 32];

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
