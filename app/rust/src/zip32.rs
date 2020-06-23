use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};

use aes::{
    block_cipher_trait::{
        generic_array::typenum::{U16, U32, U8},
        generic_array::GenericArray,
        BlockCipher,
    },
    Aes256,
};
use binary_ff1::BinaryFF1;
use core::convert::TryInto;
use itertools::zip;

use byteorder::{ByteOrder, LittleEndian};

use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};

use crate::{bolos, constants};

#[inline(always)]
pub fn prf_expand(sk: &[u8], t: &[u8]) -> [u8; 64] {
    bolos::blake2b_expand_seed(sk, t)
}

pub fn sapling_derive_dummy_ask(sk_in: &[u8]) -> [u8; 32] {
    let t = prf_expand(&sk_in, &[0x00]);
    let ask = Fr::from_bytes_wide(&t);
    ask.to_bytes()
}

pub fn sapling_derive_dummy_nsk(sk_in: &[u8]) -> [u8; 32] {
    let t = prf_expand(&sk_in, &[0x01]);
    let nsk = Fr::from_bytes_wide(&t);
    nsk.to_bytes()
}

pub fn sapling_ask_to_ak(ask: &[u8; 32]) -> [u8; 32] {
    let ak = constants::SPENDING_KEY_BASE.multiply_bits(&ask);
    AffinePoint::from(ak).to_bytes()
}

pub fn sapling_nsk_to_nk(nsk: &[u8; 32]) -> [u8; 32] {
    let nk = constants::PROVING_KEY_BASE.multiply_bits(&nsk);
    AffinePoint::from(nk).to_bytes()
}

pub fn aknk_to_ivk(ak: &[u8; 32], nk: &[u8; 32]) -> [u8; 32] {
    pub const CRH_IVK_PERSONALIZATION: &[u8; 8] = b"Zcashivk"; //move to constants

    // blake2s CRH_IVK_PERSONALIZATION || ak || nk
    let h = Blake2sParams::new()
        .hash_length(32)
        .personal(CRH_IVK_PERSONALIZATION)
        .to_state()
        .update(ak)
        .update(nk)
        .finalize();

    let mut x: [u8; 32] = *h.as_array();
    x[31] &= 0b0000_0111; //check this
    x
}

#[inline(never)]
fn diversifier_group_hash_check(hash: &[u8; 32]) -> bool {
    let u = AffinePoint::from_bytes(*hash);
    if u.is_some().unwrap_u8() == 1 {
        let v = u.unwrap();
        let q = v.mul_by_cofactor();
        let i = ExtendedPoint::identity();
        return q != i;
    }

    false
}

#[inline(never)]
fn diversifier_group_hash_light(tag: &[u8]) -> bool {
    let x = bolos::blake2s_diversification(tag);

    //    diversifier_group_hash_check(&x)

    let u = AffinePoint::from_bytes(x);
    if u.is_some().unwrap_u8() == 1 {
        let v = u.unwrap();
        let q = v.mul_by_cofactor();
        let i = ExtendedPoint::identity();
        return q != i;
    }

    false
}

pub fn default_diversifier_fromlist(list: &[u8; 44]) -> [u8; 11] {
    let mut result = [0u8; 11];
    for c in 0..4 {
        result.copy_from_slice(&list[c * 11..(c + 1) * 11]);
        //c[1] += 1;
        if diversifier_group_hash_light(&result) {
            //if diversifier_group_hash_light(&x[0..11]) {
            return result;
        }
    }
    //return a value that indicates that diversifier not found
    result
}

struct AesSDK {
    key: [u8; 32],
}

impl BlockCipher for AesSDK {
    type KeySize = U32;
    type BlockSize = U16;
    type ParBlocks = U8;

    fn new(k: &GenericArray<u8, Self::KeySize>) -> AesSDK {
        let v: [u8; 32] = k.as_slice().try_into().expect("Wrong length");
        AesSDK { key: v }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        let x: [u8; 16] = block.as_slice().try_into().expect("err");
        let y = bolos::aes256_encryptblock(&self.key, &x);

        block.copy_from_slice(&y);
    }

    fn decrypt_block(&self, _block: &mut GenericArray<u8, Self::BlockSize>) {
        //not used but has to be defined
    }
}

//list of 4 diversifiers
pub fn ff1aes_list(sk: &[u8; 32]) -> [u8; 44] {
    let cipher: AesSDK = BlockCipher::new(GenericArray::from_slice(sk));
    let mut scratch = [0u8; 12];
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();
    let mut d: [u8; 11];
    let mut counter: [u8; 11] = [0u8; 11];

    let mut result = [0u8; 44];
    let size = 4;

    for c in 0..size {
        d = counter.clone();
        ff1.encrypt(&mut d).unwrap();
        result[c * 11..(c + 1) * 11].copy_from_slice(&d);
        for k in 0..11 {
            counter[k] = counter[k].wrapping_add(1);
            if counter[k] != 0 {
                // No overflow
                break;
            }
        }
    }
    result
}

#[inline(never)]
pub fn pkd_group_hash(d: &[u8; 11]) -> [u8; 32] {
    let h = bolos::blake2s_diversification(d);

    let v = AffinePoint::from_bytes(h).unwrap();
    let q = v.mul_by_cofactor();
    let t = AffinePoint::from(q);
    t.to_bytes()
}

#[inline(never)]
pub fn default_pkd(ivk: &[u8; 32], d: &[u8; 11]) -> [u8; 32] {
    let h = bolos::blake2s_diversification(d);

    let v = AffinePoint::from_bytes(h).unwrap();
    let y = v.mul_by_cofactor();

    let v = y.to_niels().multiply_bits(ivk);
    let t = AffinePoint::from(v);
    t.to_bytes()
}

pub fn master_spending_key_zip32(seed: &[u8; 32]) -> [u8; 64] {
    bolos::blake2b_zip32master(seed)
}

pub fn diversifier_key_zip32(in_key: &[u8; 32]) -> [u8; 32] {
    let mut dk_m = [0u8; 32];
    dk_m.copy_from_slice(&prf_expand(in_key, &[0x10])[..32]);
    dk_m
}

pub fn outgoingviewingkey(key: &[u8; 32]) -> [u8; 32] {
    let mut ovk = [0u8; 32];
    ovk.copy_from_slice(&prf_expand(key, &[0x02])[..32]);
    ovk
}

pub fn full_viewingkey(key: &[u8; 32]) -> [u8; 96] {
    let ask = sapling_derive_dummy_ask(key);
    let ak = sapling_ask_to_ak(&ask);

    let nsk = sapling_derive_dummy_nsk(key);
    let nk = sapling_nsk_to_nk(&nsk);

    let ovk = outgoingviewingkey(key);
    let mut result = [0u8; 96];
    result[0..32].copy_from_slice(&ak);
    result[32..64].copy_from_slice(&nk);
    result[64..96].copy_from_slice(&ovk);
    result
}

pub fn expandedspendingkey_zip32(key: &[u8; 32]) -> [u8; 96] {
    let ask = sapling_derive_dummy_ask(key);
    let nsk = sapling_derive_dummy_nsk(key);
    let ovk = outgoingviewingkey(key);
    let mut result = [0u8; 96];
    result[0..32].copy_from_slice(&ask);
    result[32..64].copy_from_slice(&nsk);
    result[64..96].copy_from_slice(&ovk);
    result
}

pub fn update_dk_zip32(key: &[u8; 32], dk: &mut [u8; 32]) {
    let mut dkcopy = [0u8; 32];
    dkcopy.copy_from_slice(dk);
    dk.copy_from_slice(&bolos::blake2b_expand_vec_two(key, &[0x16], &dkcopy)[0..32]);
}

pub fn update_exk_zip32(key: &[u8; 32], exk: &mut [u8; 96]) {
    exk[0..32].copy_from_slice(&sapling_derive_dummy_ask(key));
    exk[32..64].copy_from_slice(&sapling_derive_dummy_nsk(key));
    let mut ovkcopy = [0u8; 32];
    ovkcopy.copy_from_slice(&exk[64..96]);
    exk[64..96].copy_from_slice(&bolos::blake2b_expand_vec_two(key, &[0x15], &ovkcopy)[..32]);
}

pub fn derive_zip32_master(seed: &[u8; 32]) -> [u8; 96] {
    let tmp = master_spending_key_zip32(seed); //64
    let mut key = [0u8; 32]; //32
    let mut chain = [0u8; 32]; //32

    key.copy_from_slice(&tmp[..32]);
    chain.copy_from_slice(&tmp[32..]);

    let ask = Fr::from_bytes_wide(&prf_expand(&key, &[0x00]));

    let nsk = Fr::from_bytes_wide(&prf_expand(&key, &[0x01]));

    let divkey = diversifier_key_zip32(&key); //32
    let mut result = [0u8; 96];
    result[0..32].copy_from_slice(&divkey);
    result[32..64].copy_from_slice(&ask.to_bytes());
    result[64..96].copy_from_slice(&nsk.to_bytes());
    result
}

pub fn derive_zip32_child_fromseedandpath(seed: &[u8; 32], path: &[u32]) -> [u8; 96] {
    //ASSERT: len(path) == len(harden)

    let mut tmp = master_spending_key_zip32(seed); //64
    let mut key = [0u8; 32]; //32
    let mut chain = [0u8; 32]; //32

    key.copy_from_slice(&tmp[..32]);
    chain.copy_from_slice(&tmp[32..]);

    let mut ask = Fr::from_bytes_wide(&prf_expand(&key, &[0x00]));

    let mut nsk = Fr::from_bytes_wide(&prf_expand(&key, &[0x01]));

    let mut expkey: [u8; 96];
    expkey = expandedspendingkey_zip32(&key); //96
                                              //master divkey
    let mut divkey = [0u8; 32];
    divkey.copy_from_slice(&diversifier_key_zip32(&key)); //32
    for &p in path {
        //compute expkey needed for zip32 child derivation
        //non-hardened child
        let hardened = (p & 0x80000000) != 0;
        let c = p & 0x7FFFFFFF;
        if hardened {
            let mut le_i = [0; 4];
            LittleEndian::write_u32(&mut le_i, c + (1 << 31));
            //make index LE
            //zip32 child derivation
            tmp = bolos::blake2b_expand_vec_four(&chain, &[0x11], &expkey, &divkey, &le_i);
        //64
        } else {
            let fvk = full_viewingkey(&key);
            let mut le_i = [0; 4];
            LittleEndian::write_u32(&mut le_i, c);
            tmp = bolos::blake2b_expand_vec_four(&chain, &[0x12], &fvk, &divkey, &le_i);
        }
        //extract key and chainkey
        key.copy_from_slice(&tmp[..32]);
        chain.copy_from_slice(&tmp[32..]);

        let ask_cur = Fr::from_bytes_wide(&prf_expand(&key, &[0x13]));
        let nsk_cur = Fr::from_bytes_wide(&prf_expand(&key, &[0x14]));

        ask += ask_cur;
        nsk += nsk_cur;

        //new divkey from old divkey and key
        update_dk_zip32(&key, &mut divkey);
        update_exk_zip32(&key, &mut expkey);
    }
    let mut result = [0u8; 96];
    result[0..32].copy_from_slice(&divkey);
    result[32..64].copy_from_slice(&ask.to_bytes());
    result[64..96].copy_from_slice(&nsk.to_bytes());
    result
}
