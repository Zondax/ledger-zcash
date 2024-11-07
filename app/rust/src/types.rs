use ztruct::create_ztruct;

pub type Diversifier = [u8; 11];

pub fn diversifier_zero() -> Diversifier {
    [0u8; 11]
}

pub type DiversifierList4 = [u8; 44];
pub type DiversifierList10 = [u8; 110];

pub type DiversifierList20 = [u8; 220];

pub fn diversifier_list20_zero() -> DiversifierList20 {
    [0u8; 220]
}

pub type AskBytes = [u8; 32];

pub type NskBytes = [u8; 32];

pub type AkBytes = [u8; 32];

pub type NkBytes = [u8; 32];

pub type IvkBytes = [u8; 32];

pub type OvkBytes = [u8; 32];

pub type DkBytes = [u8; 32];

pub type NfBytes = [u8; 32];

// This can be between 32 and 252 bytes
// TODO: move to 64 to align with ed25519 private key?
pub type Zip32Seed = [u8; 32];

pub type Zip32Path = [u32];

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

create_ztruct! {
    pub struct DiversifiableFullViewingKey {
        pub ak: AkBytes,
        pub nk: NkBytes,
        pub ovk: OvkBytes,
        pub dk: DkBytes
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

create_ztruct! {
    pub struct SaplingKeyBundle {
        pub ask: AskBytes,
        pub nsk: NskBytes,
        pub ovk: OvkBytes,
        pub dk: DkBytes,
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

create_ztruct! {
    pub struct CompactNoteExt {
        pub version: u8,
        pub diversifier: Diversifier,
        pub value: [u8; 8],
        pub rcm: DkBytes,
        pub memotype: u8
    }
}
