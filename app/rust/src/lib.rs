#![no_std]
#![no_builtins]
#![allow(dead_code, unused_imports)]

mod bolos;
mod constants;

extern crate core;

use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};

use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};

use aes::{
    block_cipher_trait::{generic_array::GenericArray, BlockCipher,generic_array::typenum::{U8, U16,U32}},
    Aes256,
};
use binary_ff1::BinaryFF1;

use byteorder::{ByteOrder, LittleEndian};

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};

fn debug(_msg: &str) {}

use core::convert::TryInto;
use core::mem;
#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[inline(always)]
pub fn prf_expand(sk: &[u8], t: &[u8]) -> [u8; 64] {
    bolos::blake2b_expand_seed(sk, t)
}

fn sapling_derive_dummy_ask(sk_in: &[u8]) -> [u8; 32] {
    let t = prf_expand(&sk_in, &[0x00]);
    let ask = Fr::from_bytes_wide(&t);
    ask.to_bytes()
}

fn sapling_derive_dummy_nsk(sk_in: &[u8]) -> [u8; 32] {
    let t = prf_expand(&sk_in, &[0x01]);
    let nsk = Fr::from_bytes_wide(&t);
    nsk.to_bytes()
}

fn sapling_ask_to_ak(ask: &[u8; 32]) -> [u8; 32] {
    let ak = constants::SPENDING_KEY_BASE.multiply_bits(&ask);
    AffinePoint::from(ak).to_bytes()
}

fn sapling_nsk_to_nk(nsk: &[u8; 32]) -> [u8; 32] {
    let nk = constants::PROVING_KEY_BASE.multiply_bits(&nsk);
    AffinePoint::from(nk).to_bytes()
}

fn aknk_to_ivk(ak: &[u8; 32], nk: &[u8; 32]) -> [u8; 32] {
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

fn default_diversifier_fromlist(list: &[u8; 44]) -> [u8; 11] {
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

struct AesSDK{
    key: [u8;32]
}

impl BlockCipher for AesSDK {
    type KeySize = U32;
    type BlockSize = U16;
    type ParBlocks = U8;

    fn new(k: &GenericArray<u8, Self::KeySize>) -> AesSDK{
        let v: [u8; 32] = k.as_slice().try_into().expect("Wrong length");
        AesSDK{key:v}
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>){
        let x: [u8;16] = block.as_slice().try_into().expect("err");
        let y = bolos::aes256_encryptblock(&self.key,&x);

        /*let mut y : [u8;16] = [0u8;16];
        for i in 0..16{
            y[i] = 0xFF;
        }*/

        /*let cipher: Aes256 = Aes256::new(GenericArray::from_slice(&self.key));
        //cipher.encrypt_block(block);

        let y: [u8;16] = block.as_slice().try_into().expect("err");

        let mut b = GenericArray::clone_from_slice(&y);
        cipher.encrypt_block(&mut b);
        */
        //let x: &[u8;16] = b.as_slice().try_into().expect("err");
        block.copy_from_slice(&y);
    }


    fn decrypt_block(&self, _block: &mut GenericArray<u8, Self::BlockSize>){
        /*let cipher: Aes256 = Aes256::new(GenericArray::from_slice(&self.key));
        cipher.decrypt_block(block);*/
    }

}

//list of 4 diversifiers
fn ff1aes_list(sk: &[u8; 32]) -> [u8; 44] {
    let cipher: AesSDK = BlockCipher::new(GenericArray::from_slice(sk));
    //let cipher = Aes256::new(GenericArray::from_slice(sk)); //make this a trait that uses SDK
    //let mut scratch = [0u8;12];
    //let mut ff1 = BinaryFF1::new(&c, 11, &[], &mut scratch).unwrap();

    //let cipher = Aes256::new(GenericArray::from_slice(sk));
    let mut scratch = [0u8; 12];
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();
    let mut d = [0u8; 11];
    let mut counter: [u8; 11] = [0u8; 11];

    let mut result = [0u8; 44];
    let size = 4;

    for c in 0..size {
        //let x = prf_expand(sk, &c);
        d = counter.clone();
        ff1.encrypt(&mut d).unwrap();
        result[c * 11..(c + 1) * 11].copy_from_slice(&d);
        //c[1] += 1;
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

fn default_diversifier(sk: &[u8; 32]) -> [u8; 11] {
    //fixme: replace blake2b with aes
    //let mut c: [u8; 2] = [0x03, 0x0];
    // blake2b sk || 0x03 || c
    let mut c: [u8; 2] = [0x03, 0x0];
    loop {
        //let x = prf_expand(sk, &c);
        let x = prf_expand(sk, &c);
        if diversifier_group_hash_light(&x[0..11]) {
            let mut result = [0u8; 11];
            result.copy_from_slice(&x[..11]);
            return result;
        }
        c[1] += 1;
    }
}

#[inline(never)]
fn pkd_group_hash(d: &[u8; 11]) -> [u8; 32] {
    let h = bolos::blake2s_diversification(d);

    let v = AffinePoint::from_bytes(h).unwrap();
    let q = v.mul_by_cofactor();
    let t = AffinePoint::from(q);
    t.to_bytes()
}

#[inline(never)]
fn default_pkd(ivk: &[u8; 32], d: &[u8; 11]) -> [u8; 32] {
    let h = bolos::blake2s_diversification(d);

    let v = AffinePoint::from_bytes(h).unwrap();
    let y = v.mul_by_cofactor();

    // FIXME: We should avoid asserts in ledger code
    //assert_eq!(x.is_some().unwrap_u8(), 1);

    let v = y.to_niels().multiply_bits(ivk);
    let t = AffinePoint::from(v);
    t.to_bytes()
}

pub fn master_spending_key_zip32(seed: &[u8; 32]) -> [u8; 64] {
    let h = Blake2bParams::new() //fixme: SDK call
        .hash_length(64)
        .personal(ZIP32_SAPLING_MASTER_PERSONALIZATION)
        .hash(seed);
    let mut output = [0u8; 64];
    output.copy_from_slice(&h.as_bytes());
    output
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

pub fn expandedspendingkey_zip32(key: [u8; 32]) -> [u8; 96] {
    let ask = sapling_derive_dummy_ask(&key);
    let nsk = sapling_derive_dummy_nsk(&key);
    let ovk = outgoingviewingkey(&key);
    let mut result = [0u8; 96];
    result[0..32].copy_from_slice(&ask);
    result[32..64].copy_from_slice(&nsk);
    result[64..96].copy_from_slice(&ovk);
    result
}

pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

pub fn prf_expand_vec(sk: &[u8], ts: &[&[u8]]) -> [u8; 64] {
    let mut h = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    h.update(sk);
    for t in ts {
        h.update(t);
    }
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&h.finalize().as_bytes());
    hash
}

pub fn update_dk_zip32(key: &[u8; 32], dk: &[u8; 32]) -> [u8; 32] {
    let mut new_divkey = [0u8; 32];
    new_divkey.copy_from_slice(&prf_expand_vec(key, &[&[0x16], dk])[0..32]);
    new_divkey
}

pub fn update_exk_zip32(key: &[u8; 32], ovk: &[u8]) -> [u8; 96] {
    let mut new_exk = [0u8; 96];
    new_exk[0..32].copy_from_slice(&sapling_derive_dummy_ask(key));
    new_exk[32..64].copy_from_slice(&sapling_derive_dummy_nsk(key));
    new_exk[64..96].copy_from_slice(&prf_expand_vec(key, &[&[0x15], ovk])[..32]);
    new_exk
}

pub fn derive_zip32_master(seed: &[u8; 32]) -> [u8; 64] {
    let tmp = master_spending_key_zip32(seed); //64
    let mut key = [0u8; 32]; //32
    let mut chain = [0u8; 32]; //32

    key.copy_from_slice(&tmp[..32]);
    chain.copy_from_slice(&tmp[32..]);

    let divkey = diversifier_key_zip32(&key); //32
    let mut result = [0u8; 64];
    result[0..32].copy_from_slice(&key);
    result[32..64].copy_from_slice(&divkey);
    result
}

pub const ZIP32_SAPLING_MASTER_PERSONALIZATION: &[u8; 16] = b"ZcashIP32Sapling";

//input seed and path = [u32's], output secret key and diversifier key
pub fn derive_child_zip32(seed: &[u8; 32], p: u32) -> [u8; 64] {
    let mut tmp = master_spending_key_zip32(seed); //64
    let mut key = [0u8; 32]; //32
    let mut chain = [0u8; 32]; //32

    key.copy_from_slice(&tmp[..32]);
    chain.copy_from_slice(&tmp[32..]);

    let mut expkey = [0u8; 96];
    expkey = expandedspendingkey_zip32(key); //96
    //master divkey
    let mut divkey = diversifier_key_zip32(&key); //32

    //compute expkey needed for zip32 child derivation

    //make index LE
    let mut le_i = [0; 4];
    LittleEndian::write_u32(&mut le_i, p + (1 << 31));

    //zip32 child derivation
    tmp = prf_expand_vec(&chain, &[&[0x11], &expkey, &divkey, &le_i]); //64

    //extract key and chainkey
    key.copy_from_slice(&tmp[..32]);
    chain.copy_from_slice(&tmp[32..]);

    //new divkey from old divkey and key
    divkey = update_dk_zip32(&key, &divkey);
    expkey = update_exk_zip32(&key, &expkey[64..96]);

    let mut result = [0u8; 64];
    result[0..32].copy_from_slice(&key);
    result[32..64].copy_from_slice(&divkey);
    result
}

#[no_mangle]
pub extern "C" fn get_ak(sk_ptr: *const u8, ak_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute(sk_ptr) };
    let ak: &mut [u8; 32] = unsafe { mem::transmute(ak_ptr) };
    let ask = sapling_derive_dummy_ask(sk);
    let tmp_ak = sapling_ask_to_ak(&ask);
    ak.copy_from_slice(&tmp_ak)
}

#[no_mangle]
pub extern "C" fn get_nk(sk_ptr: *const u8, nk_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute(sk_ptr) };
    let nk: &mut [u8; 32] = unsafe { mem::transmute(nk_ptr) };
    let nsk = sapling_derive_dummy_nsk(sk);
    let tmp_nk = sapling_nsk_to_nk(&nsk);
    nk.copy_from_slice(&tmp_nk)
}

#[no_mangle]
pub extern "C" fn get_ivk(ak_ptr: *const u8, nk_ptr: *mut u8, ivk_ptr: *mut u8) {
    let ak: &[u8; 32] = unsafe { mem::transmute(ak_ptr) };
    let nk: &[u8; 32] = unsafe { mem::transmute(nk_ptr) };
    let ivk: &mut [u8; 32] = unsafe { mem::transmute(ivk_ptr) };

    let tmp_ivk = aknk_to_ivk(&ak, &nk);
    ivk.copy_from_slice(&tmp_ivk)
}

#[no_mangle]
pub extern "C" fn zip32_master(seed_ptr: *const u8, sk_ptr: *mut u8, dk_ptr: *mut u8) {
    let seed: &[u8; 32] = unsafe { mem::transmute(seed_ptr) };
    let sk: &mut [u8; 32] = unsafe { mem::transmute(sk_ptr) };
    let dk: &mut [u8; 32] = unsafe { mem::transmute(dk_ptr) };

    let k = derive_zip32_master(seed);
    sk.copy_from_slice(&k[0..32]);
    dk.copy_from_slice(&k[32..64])
}

#[no_mangle]
pub extern "C" fn zip32_from_path(seed_ptr: *const u8, path: u32, keys_ptr: *mut u8) {
    let seed: &[u8; 32] = unsafe { mem::transmute(seed_ptr) };
    let keys: &mut [u8; 64] = unsafe { mem::transmute(keys_ptr) };

    let k = derive_child_zip32(seed, path);
    keys.copy_from_slice(&k)
}

#[no_mangle]
pub extern "C" fn get_diversifier(sk_ptr: *const u8, diversifier_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute(sk_ptr) };
    let diversifier: &mut [u8; 11] = unsafe { mem::transmute(diversifier_ptr) };
    let d = default_diversifier(sk);
    diversifier.copy_from_slice(&d)
}

#[no_mangle]
pub extern "C" fn get_diversifier_list(sk_ptr: *const u8, diversifier_list_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute(sk_ptr) };
    let diversifier: &mut [u8; 44] = unsafe { mem::transmute(diversifier_list_ptr) };
    let d = ff1aes_list(sk);
    diversifier.copy_from_slice(&d)
}

#[no_mangle]
pub extern "C" fn get_diversifier_fromlist(div_ptr: *mut u8,diversifier_list_ptr: *const u8) {
    let diversifier_list: &mut [u8; 44] = unsafe { mem::transmute(diversifier_list_ptr) };
    let div: &mut [u8; 11] = unsafe { mem::transmute(div_ptr) };

    let d = default_diversifier_fromlist(diversifier_list);
    div.copy_from_slice(&d)
}

#[no_mangle]
pub extern "C" fn get_pkd(ivk_ptr: *mut u8, diversifier_ptr: *mut u8, pkd_ptr: *mut u8) {
    let ivk: &[u8; 32] = unsafe { mem::transmute(ivk_ptr) };
    let diversifier: &[u8; 11] = unsafe { mem::transmute(diversifier_ptr) };
    let pkd: &mut [u8; 32] = unsafe { mem::transmute(pkd_ptr) };

    let tmp_pkd = default_pkd(&ivk, &diversifier);
    pkd.copy_from_slice(&tmp_pkd)
}

//fixme
//fixme: we need to add a prefix to exported functions.. as there are no namespaces in C :(
//get seed from the ledger
#[no_mangle]
pub extern "C" fn get_address(sk_ptr: *mut u8, ivk_ptr: *mut u8, address_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute(sk_ptr) };
    let ivk: &[u8; 32] = unsafe { mem::transmute(ivk_ptr) };
    let address: &mut [u8; 43] = unsafe { mem::transmute(address_ptr) };

    let div = default_diversifier(sk);
    let pkd = default_pkd(&ivk, &div);

    address[..11].copy_from_slice(&div);
    address[11..].copy_from_slice(&pkd);
}

#[cfg(test)]
mod tests {
    use crate::*;

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
        assert_eq!(keys[32..64], dk);
    }

    #[test]
    fn test_zip32_master_address_ledgerkey() {
        let seed = [0xaa; 32];


        let keys = derive_zip32_master(&seed);

        let mut sk = [0u8; 32];
        sk.copy_from_slice(&keys[0..32]);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[32..]);

        let ask = sapling_derive_dummy_ask(&sk);
        let nsk = sapling_derive_dummy_nsk(&sk);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);

        let list = ff1aes_list(&dk);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(default_d, [248, 213, 30, 83, 89, 99, 14, 96, 108, 140, 105]);
        assert_eq!(pk_d, [147, 35, 255, 156, 123, 74, 93, 5, 146, 85, 241, 157, 253, 108, 250, 198, 57, 23, 82, 24, 220, 28, 164, 3, 42, 86, 11, 204, 162, 90, 36, 88]);

    }

    #[test]
    fn test_zip32_master_address_allzero() {
        let seed = [0u8; 32];


        let keys = derive_zip32_master(&seed);

        let mut sk = [0u8; 32];
        sk.copy_from_slice(&keys[0..32]);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[32..]);

        let ask = sapling_derive_dummy_ask(&sk);
        let nsk = sapling_derive_dummy_nsk(&sk);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);

        let list = ff1aes_list(&dk);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(default_d, [0x3b, 0xf6, 0xfa, 0x1f, 0x83, 0xbf, 0x45, 0x63, 0xc8, 0xa7,
            0x13]);
        assert_eq!(pk_d, [0x04, 0x54, 0xc0, 0x14, 0x13, 0x5e, 0xc6, 0x95, 0xa1, 0x86,
            0x0f, 0x8d, 0x65, 0xb3, 0x73, 0x54, 0x6b, 0x62, 0x3f, 0x38, 0x8a, 0xbb, 0xec, 0xd0, 0xc8, 0xb2, 0x11, 0x1a, 0xbd, 0xec, 0x30, 0x1d]);

    }

    #[test]
    fn test_zip32_child() {
        let seed = [0u8; 32];

        let dk: [u8; 32] = [
            0xcb, 0xf6, 0xca, 0x4d, 0x57, 0x0f, 0xaf, 0x7e, 0xb0, 0xad, 0xcd, 0xab, 0xbf, 0xef,
            0x36, 0x1b, 0x62, 0x95, 0x4b, 0x08, 0x10, 0x25, 0x18, 0x2f, 0x50, 0x16, 0x1d, 0x40,
            0x4f, 0x21, 0x45, 0x47
        ];
        let keys = derive_child_zip32(&seed, 1);
        assert_eq!(keys[32..64], dk);
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
    fn test_default_diversifier() {
        let seed = [0u8; 32];
        let default_d = default_diversifier(&seed);
        assert_eq!(
            default_d,
            [241, 157, 155, 121, 126, 57, 243, 55, 68, 88, 57]
        );
    }

    #[test]
    fn test_default_diversifier_fromlist() {
        let seed = [0u8; 32];
        let list = ff1aes_list(&seed);
        let default_d = default_diversifier_fromlist(&list);
        assert_eq!(
            default_d,
            [0xdc, 0xe7, 0x7e, 0xbc, 0xec, 0x0a, 0x26, 0xaf, 0xd6, 0x99, 0x8c]
        );
    }

    #[test]
    fn test_defaultpkd() {
        let seed = [0u8; 32];
        let default_d = default_diversifier(&seed);

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

        let pkd = default_pkd(&ivk, &default_d);
        assert_eq!(
            pkd,
            [
                219, 76, 210, 176, 170, 196, 247, 235, 140, 161, 49, 241, 101, 103, 196, 69, 169, 85, 81, 38, 211, 194, 159, 20, 227, 215, 118, 232, 65, 174, 116, 21
            ]
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
