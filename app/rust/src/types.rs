use ztruct::create_ztruct;

pub type Diversifier = [u8; 11];

pub fn diversifier_zero() -> Diversifier {
    [0u8; 11]
}

// FIXME: This is not good design. Mayeb something like
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

// This can be between 32 and 252 bytes
// FIXME: move to 64 to align with ed25519 private key?
pub type Zip32Seed = [u8; 32];

pub type Zip32MasterSpendingKey = [u8; 32];
pub type Zip32MasterChainCode = [u8; 32];

create_ztruct! {
    //  I based on https://zips.z.cash/zip-0032#sapling-master-key-generation
    pub struct Zip32MasterKey {
        //  I_L based on https://zips.z.cash/zip-0032#sapling-master-key-generation
        pub spending_key: Zip32MasterSpendingKey,
        // I_R based on https://zips.z.cash/zip-0032#sapling-master-key-generation
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

// https://zips.z.cash/zip-0032#specification-sapling-key-derivation
create_ztruct! {
    pub struct SaplingExtendedFullViewingKey {
        pub ak: AkBytes,
        pub nk: NkBytes,
        pub ovk: OvkBytes,
        pub dk: DkBytes,
        pub chain_code: Zip32MasterChainCode,
    }
}

// https://zips.z.cash/zip-0032#specification-sapling-key-derivation
create_ztruct! {
    pub struct SaplingExpandedSpendingKey {
        pub ask: AskBytes,
        pub nsk: NskBytes,
        pub ovk: OvkBytes,
    }
}

// https://zips.z.cash/zip-0032#specification-sapling-key-derivation
create_ztruct! {
    pub struct SaplingExtendedSpendingKey {
        pub ask: AskBytes,
        pub nsk: NskBytes,
        pub ovk: OvkBytes,
        pub dk: DkBytes,
        pub chain_code: Zip32MasterChainCode,
    }
}
