use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::*;
use ff::PrimeField;
use group::GroupEncoding;

use zcash_primitives::transaction::TransactionData;

const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashOutputsHash";
const ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSOutputHash";

const SIGHASH_NONE: u32 = 2;
const SIGHASH_SINGLE: u32 = 3;
const SIGHASH_MASK: u32 = 0x1f;
const SIGHASH_ANYONECANPAY: u32 = 0x80;

const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C4_8270;
const SAPLING_VERSION_GROUP_ID: u32 = 0x892F_2085;
const SAPLING_TX_VERSION: u32 = 4;

#[derive(Clone)]
pub struct TransactionDataSighash {
    pub header: [u8; 4],
    pub version_id: [u8; 4],
    pub prevoutshash: [u8; 32],
    pub sequencehash: [u8; 32],
    pub outputshash: [u8; 32],
    pub joinsplitshash: [u8; 32],
    pub shieldedspendhash: [u8; 32],
    pub shieldedoutputhash: [u8; 32],
    pub lock_time: [u8; 4],
    pub expiry_height: [u8; 4],
    pub value_balance: [u8; 8],
    pub hash_type: [u8; 4],
}

impl Default for TransactionDataSighash {
    fn default() -> TransactionDataSighash {
        TransactionDataSighash {
            header: [0u8; 4],
            version_id: [0u8; 4],
            prevoutshash: [0u8; 32],
            sequencehash: [0u8; 32],
            outputshash: [0u8; 32],
            joinsplitshash: [0u8; 32],
            shieldedspendhash: [0u8; 32],
            shieldedoutputhash: [0u8; 32],
            lock_time: [0u8; 4],
            expiry_height: [0u8; 4],
            value_balance: [0u8; 8],
            hash_type: [0u8; 4],
        }
    }
}

impl TransactionDataSighash {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(220);
        data.extend_from_slice(&self.header);
        data.extend_from_slice(&self.version_id);
        data.extend_from_slice(&self.prevoutshash);
        data.extend_from_slice(&self.sequencehash);
        data.extend_from_slice(&self.outputshash);
        data.extend_from_slice(&self.joinsplitshash);
        data.extend_from_slice(&self.shieldedspendhash);
        data.extend_from_slice(&self.shieldedoutputhash);
        data.extend_from_slice(&self.lock_time);
        data.extend_from_slice(&self.expiry_height);
        data.extend_from_slice(&self.value_balance);
        data.extend_from_slice(&self.hash_type);
        data
    }
}

macro_rules! write_u32 {
    ($h:expr, $value:expr, $tmp:expr) => {
        //LittleEndian::write_u32(&mut $tmp[..4],$value);
        (&mut $tmp[..4]).write_u32::<LittleEndian>($value).unwrap();
        $h.copy_from_slice(&$tmp[..4]);
    };
}

macro_rules! update_data {
    ($h:expr, $cond:expr, $value:expr) => {
        if $cond {
            $h.copy_from_slice(&$value.as_ref());
        } else {
            $h.copy_from_slice(&[0; 32]);
        }
    };
}

#[derive(PartialEq)]
enum SigHashVersion {
    Sprout,
    Overwinter,
    Sapling,
}

impl SigHashVersion {
    fn from_tx(tx: &TransactionData) -> Self {
        if tx.overwintered {
            match tx.version_group_id {
                OVERWINTER_VERSION_GROUP_ID => SigHashVersion::Overwinter,
                SAPLING_VERSION_GROUP_ID => SigHashVersion::Sapling,
                _ => unimplemented!(),
            }
        } else {
            SigHashVersion::Sprout
        }
    }
}

fn prevout_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(tx.vin.len() * 36);
    for t_in in &tx.vin {
        t_in.prevout.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_PREVOUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn sequence_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(tx.vin.len() * 4);
    for t_in in &tx.vin {
        (&mut data)
            .write_u32::<LittleEndian>(t_in.sequence)
            .unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SEQUENCE_HASH_PERSONALIZATION)
        .hash(&data)
}

fn outputs_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(tx.vout.len() * 34);
    for t_out in &tx.vout {
        t_out.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}


fn joinsplits_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(
        tx.joinsplits.len()
            * if tx.version < SAPLING_TX_VERSION {
                1802 // JSDescription with PHGR13 proof
            } else {
                1698 // JSDescription with Groth16 proof
            },
    );
    for js in &tx.joinsplits {
        js.write(&mut data).unwrap();
    }
    data.extend_from_slice(&tx.joinsplit_pubkey.unwrap());
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_JOINSPLITS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn shielded_spends_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(tx.shielded_spends.len() * 384);
    for s_spend in &tx.shielded_spends {
        data.extend_from_slice(&s_spend.cv.to_bytes());
        data.extend_from_slice(s_spend.anchor.to_repr().as_ref());
        data.extend_from_slice(&s_spend.nullifier);
        s_spend.rk.write(&mut data).unwrap();
        data.extend_from_slice(&s_spend.zkproof);
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION)
        .hash(&data)
}

fn shielded_outputs_hash(tx: &TransactionData) -> Blake2bHash {
    let mut data = Vec::with_capacity(tx.shielded_outputs.len() * 948);
    for s_out in &tx.shielded_outputs {
        s_out.write(&mut data).unwrap();
    }
    Blake2bParams::new()
        .hash_length(32)
        .personal(ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION)
        .hash(&data)
}

pub fn signature_hash_input_data(tx: &TransactionData, hash_type: u32) -> TransactionDataSighash {
    let mut txdata_sighash = TransactionDataSighash::default();
    let mut tmp = [0; 8];
    let sigversion = SigHashVersion::from_tx(tx);
    match sigversion {
        SigHashVersion::Overwinter | SigHashVersion::Sapling => {
            let mut header = tx.version;
            if tx.overwintered {
                header |= 1 << 31;
            }

            write_u32!(txdata_sighash.header, header, tmp);
            write_u32!(txdata_sighash.version_id, tx.version_group_id, tmp);
            update_data!(
                txdata_sighash.prevoutshash,
                hash_type & SIGHASH_ANYONECANPAY == 0,
                prevout_hash(tx)
            ); //true for sighash_all

            update_data!(
                txdata_sighash.sequencehash,
                hash_type & SIGHASH_ANYONECANPAY == 0
                    && (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                    && (hash_type & SIGHASH_MASK) != SIGHASH_NONE,
                sequence_hash(tx)
            ); //true for sighash_all

            if (hash_type & SIGHASH_MASK) != SIGHASH_SINGLE
                && (hash_type & SIGHASH_MASK) != SIGHASH_NONE
            {
                txdata_sighash
                    .outputshash
                    .copy_from_slice(outputs_hash(tx).as_ref()); //true for sighash all
            } else {
                txdata_sighash.outputshash.copy_from_slice(&[0; 32]);
            };
            update_data!(
                txdata_sighash.joinsplitshash,
                !tx.joinsplits.is_empty(),
                joinsplits_hash(tx)
            );
            if sigversion == SigHashVersion::Sapling {
                update_data!(
                    txdata_sighash.shieldedspendhash,
                    !tx.shielded_spends.is_empty(),
                    shielded_spends_hash(tx)
                );
                update_data!(
                    txdata_sighash.shieldedoutputhash,
                    !tx.shielded_outputs.is_empty(),
                    shielded_outputs_hash(tx)
                );
            }
            write_u32!(txdata_sighash.lock_time, tx.lock_time, tmp);
            write_u32!(txdata_sighash.expiry_height, tx.expiry_height, tmp);
            if sigversion == SigHashVersion::Sapling {
                txdata_sighash
                    .value_balance
                    .copy_from_slice(&tx.value_balance.to_i64_le_bytes());
            }
            write_u32!(txdata_sighash.hash_type, hash_type, tmp);
        }
        SigHashVersion::Sprout => unimplemented!(),
    }
    txdata_sighash
}