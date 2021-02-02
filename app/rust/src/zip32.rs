use aes::{
    block_cipher_trait::{
        generic_array::typenum::{U16, U32, U8},
        generic_array::GenericArray,
        BlockCipher,
    },
    Aes256,
};
use binary_ff1::BinaryFF1;
use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};
use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryInto;
use core::mem;
use itertools::zip;
use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};

use crate::commitments::bytes_to_extended;
use crate::pedersen::extended_to_bytes;
use crate::{bolos, constants};

#[inline(always)]
pub fn prf_expand(sk: &[u8], t: &[u8]) -> [u8; 64] {
    bolos::blake2b_expand_seed(sk, t)
}

#[inline(never)]
pub fn sapling_derive_dummy_ask(sk_in: &[u8]) -> [u8; 32] {
    let t = prf_expand(&sk_in, &[0x00]);
    let ask = Fr::from_bytes_wide(&t);
    ask.to_bytes()
}

#[inline(never)]
pub fn sapling_derive_dummy_nsk(sk_in: &[u8]) -> [u8; 32] {
    let t = prf_expand(&sk_in, &[0x01]);
    let nsk = Fr::from_bytes_wide(&t);
    nsk.to_bytes()
}

#[inline(never)]
pub fn sapling_ask_to_ak(ask: &[u8; 32]) -> [u8; 32] {
    let mut point = [0u8; 32];
    bolos::sdk_jubjub_scalarmult_spending_base(&mut point, &ask[..]);
    point
}

#[inline(never)]
pub fn sapling_nsk_to_nk(nsk: &[u8; 32]) -> [u8; 32] {
    let nk = constants::PROVING_KEY_BASE.multiply_bits(&nsk);
    AffinePoint::from(nk).to_bytes()
}

#[inline(never)]
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
    let hash_tag = bolos::blake2s_diversification(tag);

    //    diversifier_group_hash_check(&x)

    let u = AffinePoint::from_bytes(hash_tag);
    if u.is_some().unwrap_u8() == 1 {
        let q = u.unwrap().mul_by_cofactor();
        return q != ExtendedPoint::identity();
    }

    false
}

#[inline(never)]
pub fn default_diversifier_fromlist(list: &[u8; 110]) -> [u8; 11] {
    let mut result = [0u8; 11];
    for c in 0..10 {
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

    #[inline(never)]
    fn new(k: &GenericArray<u8, Self::KeySize>) -> AesSDK {
        let v: [u8; 32] = k.as_slice().try_into().expect("Wrong length");
        AesSDK { key: v }
    }
    #[inline(never)]
    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        let x: [u8; 16] = block.as_slice().try_into().expect("err");
        let y = bolos::aes256_encryptblock(&self.key, &x);

        block.copy_from_slice(&y);
    }

    fn decrypt_block(&self, _block: &mut GenericArray<u8, Self::BlockSize>) {
        //not used but has to be defined
    }
}

//list of 10 diversifiers
#[inline(never)]
pub fn ff1aes_list(sk: &[u8; 32], result: &mut [u8; 110]) {
    let cipher: AesSDK = BlockCipher::new(GenericArray::from_slice(sk));
    let mut scratch = [0u8; 12];
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();
    let mut d: [u8; 11];
    let mut counter: [u8; 11] = [0u8; 11];

    let size = 10;

    for c in 0..size {
        d = counter;
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
}

//list of 4 diversifiers
#[inline(never)]
pub fn ff1aes_list_with_startingindex(
    sk: &[u8; 32],
    startindex: &[u8; 11],
    result: &mut [u8; 220],
) {
    let cipher: AesSDK = BlockCipher::new(GenericArray::from_slice(sk));
    let mut scratch = [0u8; 12];
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();
    let mut d: [u8; 11];
    let mut counter: [u8; 11] = [0u8; 11];
    counter.copy_from_slice(startindex);

    let size = 20;

    for c in 0..size {
        d = counter;
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
pub fn multwithgd(scalar: &[u8; 32], d: &[u8; 11]) -> [u8; 32] {
    let h = bolos::blake2s_diversification(d);

    let v = AffinePoint::from_bytes(h)
        .unwrap()
        .mul_by_cofactor()
        .to_niels();
    let t = v.multiply_bits(scalar);
    extended_to_bytes(&t)
}

#[inline(never)]
pub fn mul_by_cof(p: &mut ExtendedPoint) {
    *p = p.mul_by_cofactor();
}

#[inline(never)]
pub fn niels_multbits(p: &mut ExtendedPoint, b: &[u8; 32]) {
    *p = p.to_niels().multiply_bits(b);
}

#[inline(never)]
pub fn default_pkd(ivk: &[u8; 32], d: &[u8; 11]) -> [u8; 32] {
    let h = bolos::blake2s_diversification(d);

    let mut y = bytes_to_extended(h);
    mul_by_cof(&mut y);

    niels_multbits(&mut y, ivk);
    extended_to_bytes(&y)
}

#[inline(never)]
pub fn master_spending_key_zip32(seed: &[u8; 32]) -> [u8; 64] {
    pub const ZIP32_SAPLING_MASTER_PERSONALIZATION: &[u8; 16] = b"ZcashIP32Sapling";
    bolos::blake2b64_with_personalization(ZIP32_SAPLING_MASTER_PERSONALIZATION, seed)
}

#[inline(never)]
pub fn diversifier_key_zip32(in_key: &[u8; 32]) -> [u8; 32] {
    let mut dk_m = [0u8; 32];
    dk_m.copy_from_slice(&prf_expand(in_key, &[0x10])[..32]);
    dk_m
}

#[inline(never)]
pub fn outgoingviewingkey(key: &[u8; 32]) -> [u8; 32] {
    let mut ovk = [0u8; 32];
    ovk.copy_from_slice(&prf_expand(key, &[0x02])[..32]);
    ovk
}

#[inline(never)]
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

#[inline(never)]
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

#[inline(never)]
pub fn update_dk_zip32(key: &[u8; 32], dk: &mut [u8; 32]) {
    let mut dkcopy = [0u8; 32];
    dkcopy.copy_from_slice(dk);
    dk.copy_from_slice(&bolos::blake2b_expand_vec_two(key, &[0x16], &dkcopy)[0..32]);
}

#[inline(never)]
pub fn update_exk_zip32(key: &[u8; 32], exk: &mut [u8; 96]) {
    exk[0..32].copy_from_slice(&sapling_derive_dummy_ask(key));
    exk[32..64].copy_from_slice(&sapling_derive_dummy_nsk(key));
    let mut ovkcopy = [0u8; 32];
    ovkcopy.copy_from_slice(&exk[64..96]);
    exk[64..96].copy_from_slice(&bolos::blake2b_expand_vec_two(key, &[0x15], &ovkcopy)[..32]);
}

#[inline(never)]
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
/*
ChildIndex::Hardened(32),
ChildIndex::Hardened(config.get_coin_type()),
ChildIndex::Hardened(pos)
*/

#[inline(never)]
pub fn derive_zip32_ovk_fromseedandpath(seed: &[u8; 32], path: &[u32]) -> [u8; 32] {
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
        let hardened = (p & 0x8000_0000) != 0;
        let c = p & 0x7FFF_FFFF;
        if hardened {
            let mut le_i = [0; 4];
            LittleEndian::write_u32(&mut le_i, c + (1 << 31));
            //make index LE
            //zip32 child derivation
            tmp = bolos::blake2b_expand_vec_four(&chain, &[0x11], &expkey, &divkey, &le_i);
        //64
        } else {
            //WARNING: CURRENTLY COMPUTING NON-HARDENED PATHS DO NOT FIT IN MEMORY
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
    let mut result = [0u8; 32];
    result[0..32].copy_from_slice(&key);
    result
}

#[inline(never)]
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
        let hardened = (p & 0x8000_0000) != 0;
        let c = p & 0x7FFF_FFFF;
        if hardened {
            let mut le_i = [0; 4];
            LittleEndian::write_u32(&mut le_i, c + (1 << 31));
            //make index LE
            //zip32 child derivation
            tmp = bolos::blake2b_expand_vec_four(&chain, &[0x11], &expkey, &divkey, &le_i);
        //64
        } else {
            //WARNING: CURRENTLY COMPUTING NON-HARDENED PATHS DO NOT FIT IN MEMORY
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

#[no_mangle]
pub extern "C" fn ask_to_ak(ask_ptr: *const [u8; 32], ak_ptr: *mut [u8; 32]) {
    let ask = unsafe { &*ask_ptr };
    let ak = unsafe { &mut *ak_ptr };
    let tmp_ak = sapling_ask_to_ak(&ask);
    ak.copy_from_slice(&tmp_ak)
}

#[no_mangle]
pub extern "C" fn nsk_to_nk(nsk_ptr: *const [u8; 32], nk_ptr: *mut [u8; 32]) {
    let nsk = unsafe { &*nsk_ptr };
    let nk = unsafe { &mut *nk_ptr };
    let tmp_nk = sapling_nsk_to_nk(&nsk);
    nk.copy_from_slice(&tmp_nk)
}

#[no_mangle]
pub extern "C" fn get_ivk(
    ak_ptr: *const [u8; 32],
    nk_ptr: *const [u8; 32],
    ivk_ptr: *mut [u8; 32],
) {
    let ak = unsafe { &*ak_ptr };
    let nk = unsafe { &*nk_ptr };
    let ivk = unsafe { &mut *ivk_ptr };

    let tmp_ivk = aknk_to_ivk(&ak, &nk);
    ivk.copy_from_slice(&tmp_ivk)
}

#[no_mangle]
pub extern "C" fn zip32_master(
    seed_ptr: *const [u8; 32],
    sk_ptr: *mut [u8; 32],
    dk_ptr: *mut [u8; 32],
) {
    let seed = unsafe { &*seed_ptr };
    let sk = unsafe { &mut *sk_ptr };
    let dk = unsafe { &mut *dk_ptr };

    let k = derive_zip32_master(seed);
    sk.copy_from_slice(&k[0..32]);
    dk.copy_from_slice(&k[32..64])
}

//this function is consistent with zecwallet code
#[no_mangle]
pub extern "C" fn zip32_ovk(seed_ptr: *const [u8; 32], ovk_ptr: *mut [u8; 32], pos: u32) {
    let seed = unsafe { &*seed_ptr };
    let ovk = unsafe { &mut *ovk_ptr };

    const FIRSTVALUE: u32 = 32 ^ 0x8000_0000;
    const COIN_TYPE: u32 = 133 ^ 0x8000_0000; //hardened, fixed value from https://github.com/adityapk00/librustzcash/blob/master/zcash_client_backend/src/constants/mainnet.rs
    let k = derive_zip32_ovk_fromseedandpath(seed, &[FIRSTVALUE, COIN_TYPE, pos]); //consistent with zecwallet
    ovk.copy_from_slice(&k[0..32]);
}

//this function is consistent with zecwallet code
#[no_mangle]
pub extern "C" fn zip32_child(
    seed_ptr: *const [u8; 32],
    dk_ptr: *mut [u8; 32],
    ask_ptr: *mut [u8; 32],
    nsk_ptr: *mut [u8; 32],
    pos: u32,
) {
    let seed = unsafe { &*seed_ptr };
    let dk = unsafe { &mut *dk_ptr };
    let ask = unsafe { &mut *ask_ptr };
    let nsk = unsafe { &mut *nsk_ptr };

    const FIRSTVALUE: u32 = 32 ^ 0x8000_0000;
    const COIN_TYPE: u32 = 133 ^ 0x8000_0000; //hardened, fixed value from https://github.com/adityapk00/librustzcash/blob/master/zcash_client_backend/src/constants/mainnet.rs
    let k = derive_zip32_child_fromseedandpath(seed, &[FIRSTVALUE, COIN_TYPE, pos]); //consistent with zecwallet
    dk.copy_from_slice(&k[0..32]);
    ask.copy_from_slice(&k[32..64]);
    nsk.copy_from_slice(&k[64..96]);
}

#[no_mangle]
pub extern "C" fn zip32_child_ask_nsk(
    seed_ptr: *const [u8; 32],
    ask_ptr: *mut [u8; 32],
    nsk_ptr: *mut [u8; 32],
    pos: u32,
) {
    let seed = unsafe { &*seed_ptr };
    let ask = unsafe { &mut *ask_ptr };
    let nsk = unsafe { &mut *nsk_ptr };

    const FIRSTVALUE: u32 = 32 ^ 0x8000_0000;
    const COIN_TYPE: u32 = 133 ^ 0x8000_0000; //hardened, fixed value from https://github.com/adityapk00/librustzcash/blob/master/zcash_client_backend/src/constants/mainnet.rs
    let k = derive_zip32_child_fromseedandpath(seed, &[FIRSTVALUE, COIN_TYPE, pos]); //consistent with zecwallet;
    ask.copy_from_slice(&k[32..64]);
    nsk.copy_from_slice(&k[64..96]);
}

#[no_mangle]
pub extern "C" fn get_diversifier_list(
    sk_ptr: *const [u8; 32],
    diversifier_list_ptr: *mut [u8; 110],
) {
    let sk = unsafe { &*sk_ptr };
    let diversifier = unsafe { &mut *diversifier_list_ptr };
    ff1aes_list(sk, diversifier);
}

#[no_mangle]
pub extern "C" fn get_diversifier_list_withstartindex(
    sk_ptr: *const [u8; 32],
    start_index: *const [u8; 11],
    diversifier_list_ptr: *mut [u8; 220],
) {
    let sk = unsafe { &*sk_ptr };
    let start = unsafe { &*start_index };
    let diversifier = unsafe { &mut *diversifier_list_ptr };
    ff1aes_list_with_startingindex(sk, start, diversifier);
}

#[no_mangle]
pub extern "C" fn is_valid_diversifier(div_ptr: *const [u8; 11]) -> bool {
    let div = unsafe { &*div_ptr };
    diversifier_group_hash_light(div)
}

#[no_mangle]
pub extern "C" fn get_diversifier_fromlist(
    div_ptr: *mut [u8; 11],
    diversifier_list_ptr: *const [u8; 110],
) {
    let diversifier_list = unsafe { &*diversifier_list_ptr };
    let div = unsafe { &mut *div_ptr };

    let d = default_diversifier_fromlist(diversifier_list);
    div.copy_from_slice(&d)
}

#[no_mangle]
pub extern "C" fn get_pkd(
    ivk_ptr: *const [u8; 32],
    diversifier_ptr: *const [u8; 11],
    pkd_ptr: *mut [u8; 32],
) {
    let ivk = unsafe { &*ivk_ptr };
    let diversifier = unsafe { &*diversifier_ptr };
    let pkd = unsafe { &mut *pkd_ptr };

    let tmp_pkd = default_pkd(&ivk, &diversifier);
    pkd.copy_from_slice(&tmp_pkd)
}

#[no_mangle]
pub extern "C" fn group_hash_from_div(diversifier_ptr: *const [u8; 11], gd_ptr: *mut [u8; 32]) {
    let diversifier = unsafe { &*diversifier_ptr };
    let gd = unsafe { &mut *gd_ptr };
    let gd_tmp = pkd_group_hash(diversifier);
    gd.copy_from_slice(&gd_tmp);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip32_master() {
        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        let dk: [u8; 32] = [
            0x77, 0xc1, 0x7c, 0xb7, 0x5b, 0x77, 0x96, 0xaf, 0xb3, 0x9f, 0x0f, 0x3e, 0x91, 0xc9,
            0x24, 0x60, 0x7d, 0xa5, 0x6f, 0xa9, 0xa2, 0x0e, 0x28, 0x35, 0x09, 0xbc, 0x8a, 0x3e,
            0xf9, 0x96, 0xa1, 0x72,
        ];
        let keys = derive_zip32_master(&seed);
        assert_eq!(keys[0..32], dk);
    }

    #[test]
    fn test_zip32_path() {
        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        let dk: [u8; 32] = [
            0x77, 0xc1, 0x7c, 0xb7, 0x5b, 0x77, 0x96, 0xaf, 0xb3, 0x9f, 0x0f, 0x3e, 0x91, 0xc9,
            0x24, 0x60, 0x7d, 0xa5, 0x6f, 0xa9, 0xa2, 0x0e, 0x28, 0x35, 0x09, 0xbc, 0x8a, 0x3e,
            0xf9, 0x96, 0xa1, 0x72,
        ];
        let keys = derive_zip32_master(&seed);
        assert_eq!(keys[0..32], dk);
    }

    #[test]
    fn test_zip32_childaddress() {
        let seed = [0u8; 32];

        let p: u32 = 0x8000_0001;
        let keys = derive_zip32_child_fromseedandpath(&seed, &[p]);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&keys[64..96]);

        let ask_test: [u8; 32] = [
            0x66, 0x5e, 0xd6, 0xf7, 0xb7, 0x93, 0xaf, 0xa1, 0x82, 0x21, 0xe1, 0x57, 0xba, 0xd5,
            0x43, 0x3c, 0x54, 0x23, 0xf4, 0xfe, 0xc9, 0x46, 0xe0, 0x8e, 0xd6, 0x30, 0xa0, 0xc6,
            0x0a, 0x1f, 0xac, 0x02,
        ];

        assert_eq!(ask, ask_test);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk_test: [u8; 32] = [
            0x2c, 0x57, 0xfb, 0x12, 0x8c, 0x35, 0xa4, 0x4d, 0x2d, 0x5b, 0xf2, 0xfd, 0x21, 0xdc,
            0x3b, 0x44, 0x11, 0x4c, 0x36, 0x6c, 0x9c, 0x49, 0x60, 0xc4, 0x91, 0x66, 0x17, 0x38,
            0x3e, 0x89, 0xfd, 0x00,
        ];
        let ivk = aknk_to_ivk(&ak, &nk);

        assert_eq!(ivk, ivk_test);

        let mut listbytes = [0u8; 110];
        ff1aes_list(&dk, &mut listbytes);
        let default_d = default_diversifier_fromlist(&listbytes);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(
            default_d,
            [0x10, 0xaa, 0x8e, 0xe1, 0xe1, 0x91, 0x48, 0xe7, 0x49, 0x7d, 0x3c]
        );
        assert_eq!(
            pk_d,
            [
                0xb3, 0xbe, 0x9e, 0xb3, 0xe7, 0xa9, 0x61, 0x17, 0x95, 0x17, 0xae, 0x28, 0xab, 0x19,
                0xb4, 0x84, 0xae, 0x17, 0x2f, 0x1f, 0x33, 0xd1, 0x16, 0x33, 0xe9, 0xec, 0x05, 0xee,
                0xa1, 0xe8, 0xa9, 0xd6
            ]
        );
    }

    #[test]
    fn test_zip32_childaddress_ledgerkey() {
        //e91db3f6c120a86ece0de8d21d452dcdcb708d563494e60a6cee676f5047ded7
        let s = hex::decode("b08e3d98da431cef4566a13c1bb348b982f7d8e743b43bb62557ba51994b1257")
            .expect("error");
        let seed: [u8; 32] = s.as_slice().try_into().expect("er");

        const FIRSTVALUE: u32 = 32 ^ 0x8000_0000;
        const COIN_TYPE: u32 = 133 ^ 0x8000_0000;

        let p: u32 = 1000 | 0x8000_0000;
        let keys = derive_zip32_child_fromseedandpath(&seed, &[FIRSTVALUE, COIN_TYPE, p]);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&keys[64..96]);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);

        let mut ivk_ledger = [0u8; 32];
        hex::decode_to_slice(
            "6dfadf175921e6fbfa093c8f7c704a0bdb07328474f56c833dfcfa5301082d03",
            &mut ivk_ledger,
        )
        .expect("dec");
        assert_eq!(ivk, ivk_ledger);

        let mut list = [0u8; 110];
        ff1aes_list(&dk, &mut list);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(
            default_d,
            [198, 158, 151, 156, 103, 99, 193, 176, 146, 56, 220]
        );
        assert_eq!(
            pk_d,
            [
                107, 213, 220, 191, 53, 54, 13, 249, 93, 202, 223, 140, 15, 162, 93, 203, 237, 170,
                246, 5, 117, 56, 184, 18, 208, 102, 86, 114, 110, 162, 118, 103
            ]
        );
    }

    #[test]
    fn test_zip32_master_address_ledgerkey() {
        let s = hex::decode("b08e3d98da431cef4566a13c1bb348b982f7d8e743b43bb62557ba51994b1257")
            .expect("error");
        let seed: [u8; 32] = s.as_slice().try_into().expect("er");

        let keys = derive_zip32_master(&seed);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&keys[64..96]);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);

        let mut list = [0u8; 110];
        ff1aes_list(&dk, &mut list);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(
            default_d,
            [249, 61, 207, 226, 4, 114, 83, 238, 188, 23, 212]
        );
        assert_eq!(
            pk_d,
            [
                220, 53, 23, 146, 73, 107, 157, 1, 78, 98, 108, 59, 201, 41, 230, 211, 47, 80, 127,
                184, 11, 102, 79, 92, 174, 151, 211, 123, 247, 66, 219, 169
            ]
        );
    }

    #[test]
    fn test_zip32_master_address_allzero() {
        let seed = [0u8; 32];

        let keys = derive_zip32_master(&seed);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&keys[64..96]);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);
        let mut list = [0u8; 110];
        ff1aes_list(&dk, &mut list);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(
            default_d,
            [0x3b, 0xf6, 0xfa, 0x1f, 0x83, 0xbf, 0x45, 0x63, 0xc8, 0xa7, 0x13]
        );
        assert_eq!(
            pk_d,
            [
                0x04, 0x54, 0xc0, 0x14, 0x13, 0x5e, 0xc6, 0x95, 0xa1, 0x86, 0x0f, 0x8d, 0x65, 0xb3,
                0x73, 0x54, 0x6b, 0x62, 0x3f, 0x38, 0x8a, 0xbb, 0xec, 0xd0, 0xc8, 0xb2, 0x11, 0x1a,
                0xbd, 0xec, 0x30, 0x1d
            ]
        );
    }

    #[test]
    fn test_div() {
        let nk = [
            0xf7, 0xcf, 0x9e, 0x77, 0xf2, 0xe5, 0x86, 0x83, 0x38, 0x3c, 0x15, 0x19, 0xac, 0x7b,
            0x06, 0x2d, 0x30, 0x04, 0x0e, 0x27, 0xa7, 0x25, 0xfb, 0x88, 0xfb, 0x19, 0xa9, 0x78,
            0xbd, 0x3f, 0xd6, 0xba,
        ];
        let ak = [
            0xf3, 0x44, 0xec, 0x38, 0x0f, 0xe1, 0x27, 0x3e, 0x30, 0x98, 0xc2, 0x58, 0x8c, 0x5d,
            0x3a, 0x79, 0x1f, 0xd7, 0xba, 0x95, 0x80, 0x32, 0x76, 0x07, 0x77, 0xfd, 0x0e, 0xfa,
            0x8e, 0xf1, 0x16, 0x20,
        ];

        let ivk: [u8; 32] = aknk_to_ivk(&ak, &nk);
        let default_d = [
            0xf1, 0x9d, 0x9b, 0x79, 0x7e, 0x39, 0xf3, 0x37, 0x44, 0x58, 0x39,
        ];

        let result = pkd_group_hash(&default_d);
        let x = super::AffinePoint::from_bytes(result);
        if x.is_some().unwrap_u8() == 1 {
            let y = super::ExtendedPoint::from(x.unwrap());
            let v = y.to_niels().multiply_bits(&ivk);
            let t = super::AffinePoint::from(v);
            let pk_d = t.to_bytes();
            assert_eq!(
                pk_d,
                [
                    0xdb, 0x4c, 0xd2, 0xb0, 0xaa, 0xc4, 0xf7, 0xeb, 0x8c, 0xa1, 0x31, 0xf1, 0x65,
                    0x67, 0xc4, 0x45, 0xa9, 0x55, 0x51, 0x26, 0xd3, 0xc2, 0x9f, 0x14, 0xe3, 0xd7,
                    0x76, 0xe8, 0x41, 0xae, 0x74, 0x15
                ]
            );
        }
    }

    #[test]
    fn test_default_diversifier_fromlist() {
        let seed = [0u8; 32];
        let mut list = [0u8; 110];
        ff1aes_list(&seed, &mut list);
        let default_d = default_diversifier_fromlist(&list);
        assert_eq!(
            default_d,
            [0xdc, 0xe7, 0x7e, 0xbc, 0xec, 0x0a, 0x26, 0xaf, 0xd6, 0x99, 0x8c]
        );
    }

    #[test]
    fn test_grouphash_default() {
        let default_d = [
            0xf1, 0x9d, 0x9b, 0x79, 0x7e, 0x39, 0xf3, 0x37, 0x44, 0x58, 0x39,
        ];

        let result = pkd_group_hash(&default_d);
        let x = super::AffinePoint::from_bytes(result);
        assert_eq!(x.is_some().unwrap_u8(), 1);
        assert_eq!(
            result,
            [
                0x3a, 0x71, 0xe3, 0x48, 0x16, 0x9e, 0x0c, 0xed, 0xbc, 0x4f, 0x36, 0x33, 0xa2, 0x60,
                0xd0, 0xe7, 0x85, 0xea, 0x8f, 0x89, 0x27, 0xce, 0x45, 0x01, 0xce, 0xf3, 0x21, 0x6e,
                0xd0, 0x75, 0xce, 0xa2
            ]
        );
    }

    #[test]
    fn test_ak() {
        let seed = [0u8; 32];
        let ask: [u8; 32] = sapling_derive_dummy_ask(&seed);
        assert_eq!(
            ask,
            [
                0x85, 0x48, 0xa1, 0x4a, 0x47, 0x3e, 0xa5, 0x47, 0xaa, 0x23, 0x78, 0x40, 0x20, 0x44,
                0xf8, 0x18, 0xcf, 0x19, 0x11, 0xcf, 0x5d, 0xd2, 0x05, 0x4f, 0x67, 0x83, 0x45, 0xf0,
                0x0d, 0x0e, 0x88, 0x06
            ]
        );
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);
        assert_eq!(
            ak,
            [
                0xf3, 0x44, 0xec, 0x38, 0x0f, 0xe1, 0x27, 0x3e, 0x30, 0x98, 0xc2, 0x58, 0x8c, 0x5d,
                0x3a, 0x79, 0x1f, 0xd7, 0xba, 0x95, 0x80, 0x32, 0x76, 0x07, 0x77, 0xfd, 0x0e, 0xfa,
                0x8e, 0xf1, 0x16, 0x20
            ]
        );
    }

    #[test]
    fn test_nk() {
        let seed = [0u8; 32];

        let nsk: [u8; 32] = sapling_derive_dummy_nsk(&seed);
        assert_eq!(
            nsk,
            [
                0x30, 0x11, 0x4e, 0xa0, 0xdd, 0x0b, 0xb6, 0x1c, 0xf0, 0xea, 0xea, 0xb6, 0xec, 0x33,
                0x31, 0xf5, 0x81, 0xb0, 0x42, 0x5e, 0x27, 0x33, 0x85, 0x01, 0x26, 0x2d, 0x7e, 0xac,
                0x74, 0x5e, 0x6e, 0x05
            ]
        );

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        assert_eq!(
            nk,
            [
                0xf7, 0xcf, 0x9e, 0x77, 0xf2, 0xe5, 0x86, 0x83, 0x38, 0x3c, 0x15, 0x19, 0xac, 0x7b,
                0x06, 0x2d, 0x30, 0x04, 0x0e, 0x27, 0xa7, 0x25, 0xfb, 0x88, 0xfb, 0x19, 0xa9, 0x78,
                0xbd, 0x3f, 0xd6, 0xba
            ]
        );
    }

    #[test]
    fn test_ivk() {
        let nk = [
            0xf7, 0xcf, 0x9e, 0x77, 0xf2, 0xe5, 0x86, 0x83, 0x38, 0x3c, 0x15, 0x19, 0xac, 0x7b,
            0x06, 0x2d, 0x30, 0x04, 0x0e, 0x27, 0xa7, 0x25, 0xfb, 0x88, 0xfb, 0x19, 0xa9, 0x78,
            0xbd, 0x3f, 0xd6, 0xba,
        ];
        let ak = [
            0xf3, 0x44, 0xec, 0x38, 0x0f, 0xe1, 0x27, 0x3e, 0x30, 0x98, 0xc2, 0x58, 0x8c, 0x5d,
            0x3a, 0x79, 0x1f, 0xd7, 0xba, 0x95, 0x80, 0x32, 0x76, 0x07, 0x77, 0xfd, 0x0e, 0xfa,
            0x8e, 0xf1, 0x16, 0x20,
        ];

        let ivk: [u8; 32] = aknk_to_ivk(&ak, &nk);
        assert_eq!(
            ivk,
            [
                0xb7, 0x0b, 0x7c, 0xd0, 0xed, 0x03, 0xcb, 0xdf, 0xd7, 0xad, 0xa9, 0x50, 0x2e, 0xe2,
                0x45, 0xb1, 0x3e, 0x56, 0x9d, 0x54, 0xa5, 0x71, 0x9d, 0x2d, 0xaa, 0x0f, 0x5f, 0x14,
                0x51, 0x47, 0x92, 0x04
            ]
        );
    }
}
