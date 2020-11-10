use jubjub::{Fr, SubgroupPoint};
use zcash_primitives::legacy::*;
use zcash_primitives::transaction::components::{Amount, OutPoint};

use group::GroupEncoding;
use serde::{de::Error, Deserialize, Deserializer, Serializer};
use std::str::*;
use zcash_primitives::keys::OutgoingViewingKey;
use zcash_primitives::note_encryption::Memo;
use zcash_primitives::primitives::*;
use zcash_primitives::redjubjub::Signature;
use zcash_primitives::merkle_tree::IncrementalWitness;
use zcash_primitives::sapling::Node;

pub fn outpoint_deserialize<'de, D>(deserializer: D) -> Result<OutPoint, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 36];
    hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;
    OutPoint::read(&bytes[..]).map_err(D::Error::custom)
}

pub fn t_pk_deserialize<'de, D>(deserializer: D) -> Result<secp256k1::PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    secp256k1::PublicKey::from_str(&str).map_err(D::Error::custom)
}

pub fn script_deserialize<'de, D>(deserializer: D) -> Result<Script, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 26];
    hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;
    Script::read(&bytes[..]).map_err(D::Error::custom)
}

pub fn amount_deserialize<'de, D>(deserializer: D) -> Result<Amount, D::Error>
where
    D: Deserializer<'de>,
{
    let v = u64::deserialize(deserializer)?;
    let r = Amount::from_u64(v);
    match r {
        Ok(a) => Ok(a),
        Err(_) => Err(D::Error::custom("error deserializing hex to amount")),
    }
}

pub fn fr_deserialize<'de, D>(deserializer: D) -> Result<Fr, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;
    let f = Fr::from_bytes(&bytes);
    match f.is_some().into()
    {
        true => Ok(f.unwrap()),
        false => Err(D::Error::custom("error deserializing to fr")),
    }
}

pub fn pgk_deserialize<'de, D>(deserializer: D) -> Result<ProofGenerationKey, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 64];
    hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;

    let mut akb = [0u8; 32];
    akb.copy_from_slice(&bytes[0..32]);
    let mut nskb = [0u8; 32];
    nskb.copy_from_slice(&bytes[32..64]);

    let ak = SubgroupPoint::from_bytes(&akb);
    let nsk = jubjub::Fr::from_bytes(&nskb);
    match ak.is_some().into() && nsk.is_some().into() {
        true => Ok(ProofGenerationKey {
            ak: ak.unwrap(),
            nsk: nsk.unwrap(),
        }),
        false =>
        Err(D::Error::custom("error deserializing to pgk"))
    }
}

pub fn s_address_deserialize<'de, D>(deserializer: D) -> Result<PaymentAddress, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8; 43];
    hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;

    let p = PaymentAddress::from_bytes(&bytes);
    match p.is_some().into() {
        true => Ok(p.unwrap()),
        false => Err(D::Error::custom("error deserializing to shielded address")),
    }
}

pub fn ovk_deserialize<'de, D>(deserializer: D) -> Result<Option<OutgoingViewingKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let str: Option<String> = Option::deserialize(deserializer)?;
    match str.is_some().into(){
        true => {
            let s = str.unwrap();
            let mut bytes = [0u8;32];
            hex::decode_to_slice(&s, &mut bytes).map_err(D::Error::custom);
            return Ok(Some(OutgoingViewingKey(bytes)))
        },
        false => Ok(None),
    }
}

pub fn memo_deserialize<'de, D>(deserializer: D) -> Result<Option<Memo>, D::Error>
where
    D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;

    match str.len() == 4 || str.len() % 2 != 0 {
        true => Ok(None),
        false => {
            let mut bytes = Vec::with_capacity(str.len() / 2);
            hex::decode_to_slice(&str, &mut bytes).map_err(D::Error::custom)?;
            return Ok(Memo::from_bytes(&bytes[..]))
        }
    }
}

pub fn witness_deserialize<'de, D>(deserializer: D) -> Result<IncrementalWitness<Node>, D::Error>
    where
        D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let v = hex::decode(str).map_err(D::Error::custom)?;
    let witness= IncrementalWitness::read(&v[..]).map_err(D::Error::custom).unwrap();
    Ok(witness)
}

pub fn rseed_deserialize<'de, D>(deserializer: D) -> Result<Rseed, D::Error>
    where
        D: Deserializer<'de>,
{
    let str = String::deserialize(deserializer)?;
    let mut bytes = [0u8;32];
    hex::decode_to_slice(str, &mut bytes).map_err(D::Error::custom)?;
    let rseed = Rseed::AfterZip212(bytes);
    Ok(rseed)
}

pub fn t_sig_deserialize<'de, D>(deserializer: D) -> Result<Vec<secp256k1::Signature>, D::Error>
where
    D: Deserializer<'de>,
{
    let str: Vec<String> = Deserialize::deserialize(deserializer)?;
    if str.len() == 0 {
        return Ok(Vec::new());
    } else {
        let n = str.len();
        let mut v = Vec::new();
        for i in 0..n {
            if str[i].len() != 128 {
                return Err(D::Error::custom(
                    "not enough bytes deserializing to transparent sig",
                ));
            }
            let mut bytes = [0u8; 64];
            hex::decode_to_slice(&str[i], &mut bytes);
            let s = secp256k1::Signature::from_compact(&bytes).map_err(D::Error::custom)?;
            v.push(s);
        }
        return Ok(v);
    }
}

pub fn s_sig_deserialize<'de, D>(deserializer: D) -> Result<Vec<Signature>, D::Error>
where
    D: Deserializer<'de>,
{
    let str: Vec<String> = Deserialize::deserialize(deserializer)?;
    if str.len() == 0 {
        return Ok(Vec::new());
    } else {
        let n = str.len();
        let mut v = Vec::new();
        for i in 0..n {
            if str[i].len() != 128 {
                return Err(D::Error::custom(
                    "not enough bytes deserializing to transparent sig",
                ));
            }
            let mut bytes = [0u8; 64];
            hex::decode_to_slice(&str[i], &mut bytes);
            let s = Signature::read(&bytes[..]);
            if s.is_ok() {
                v.push(s.unwrap());
            } else {
                return Err(D::Error::custom("error deserializing to spend sig"));
            }
        }
        return Ok(v);
    }
}
