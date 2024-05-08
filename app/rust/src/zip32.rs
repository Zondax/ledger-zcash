use core::convert::TryInto;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use binary_ff1::BinaryFF1;
use byteorder::{ByteOrder, LittleEndian};
use jubjub::{AffinePoint, ExtendedPoint, Fr};

use crate::bolos::aes::AesSDK;
use crate::bolos::blake2b::{
    blake2b64_with_personalization, blake2b_expand_vec_four, blake2b_expand_vec_two,
};
use crate::bolos::c_check_app_canary;
use crate::bolos::{blake2b, c_zemu_log_stack};
use crate::constants::{
    Zip32ChildComponents, DIV_DEFAULT_LIST_LEN, DIV_SIZE, ZIP32_COIN_TYPE, ZIP32_PURPOSE,
};
use crate::cryptoops::bytes_to_extended;
use crate::cryptoops::extended_to_bytes;
use crate::personalization::ZIP32_SAPLING_MASTER_PERSONALIZATION;
use crate::types::{
    diversifier_zero, AskBytes, Diversifier, DiversifierList10, DiversifierList20,
    DiversifierList4, DkBytes, FullViewingKey, NskBytes, OvkBytes, SaplingExpandedSpendingKey,
    Zip32MasterKey, Zip32MasterSpendingKey, Zip32Seed,
};
use crate::{cryptoops, sapling};

#[inline(never)]
// Calculates I based on https://zips.z.cash/zip-0032#sapling-master-key-generation
pub fn zip32_master_key_i(seed: &Zip32Seed) -> Zip32MasterKey {
    Zip32MasterKey::from_bytes(&blake2b64_with_personalization(
        ZIP32_SAPLING_MASTER_PERSONALIZATION,
        seed,
    ))
}

#[inline(never)]
// As per ask_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
pub fn zip32_sapling_ask_m(sk_m: &[u8]) -> AskBytes {
    let t = cryptoops::prf_expand(&sk_m, &[0x00]);
    let ask = Fr::from_bytes_wide(&t);
    ask.to_bytes()
}

#[inline(never)]
// As per nsk_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
pub fn zip32_sapling_nsk_m(sk_m: &[u8]) -> NskBytes {
    let t = cryptoops::prf_expand(&sk_m, &[0x01]);
    let nsk = Fr::from_bytes_wide(&t);
    nsk.to_bytes()
}

#[inline(never)]
// As per ovk_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
pub fn zip32_sapling_ovk_m(key: &[u8; 32]) -> OvkBytes {
    let prf_output = cryptoops::prf_expand(key, &[0x02]);

    // truncate
    let mut ovk = [0u8; 32];
    ovk.copy_from_slice(&prf_output[..32]);
    ovk
}

#[inline(never)]
// As per dk_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
pub fn zip32_sapling_dk_m(sk_m: &[u8; 32]) -> DkBytes {
    let prf_output = cryptoops::prf_expand(sk_m, &[0x10]);

    // truncate
    let mut dk_m = [0u8; 32];
    dk_m.copy_from_slice(&prf_output[..32]);
    dk_m
}

#[inline(never)]
pub fn zip32_sapling_i_ask(sk_m: &[u8]) -> AskBytes {
    let t = cryptoops::prf_expand(&sk_m, &[0x13]);
    let ask = Fr::from_bytes_wide(&t);
    ask.to_bytes()
}

#[inline(never)]
pub fn zip32_sapling_i_nsk(sk_m: &[u8]) -> NskBytes {
    let t = cryptoops::prf_expand(&sk_m, &[0x14]);
    let nsk = Fr::from_bytes_wide(&t);
    nsk.to_bytes()
}

////////////

#[inline(never)]
pub fn zip32_sapling_ask_i_update(sk_m: &[u8], ask_i: &mut AskBytes) {
    let i_ask = zip32_sapling_i_ask(&sk_m);
    *ask_i = (Fr::from_bytes(&ask_i).unwrap() + Fr::from_bytes(&i_ask).unwrap()).to_bytes();
}

#[inline(never)]
pub fn zip32_sapling_nsk_i_update(sk_m: &[u8], nsk_i: &mut NskBytes) {
    let i_nsk = zip32_sapling_i_nsk(&sk_m);
    *nsk_i = (Fr::from_bytes(&nsk_i).unwrap() + Fr::from_bytes(&i_nsk).unwrap()).to_bytes();
}

#[inline(never)]
pub fn zip32_sapling_ovk_i_update(sk_m: &[u8], ovk_i: &mut DkBytes) {
    let mut ovk_copy = [0u8; 32];
    ovk_copy.copy_from_slice(ovk_i);

    let t = &blake2b_expand_vec_two(sk_m, &[0x15], &ovk_copy);

    ovk_i.copy_from_slice(&t[0..32]);
}

#[inline(never)]
pub fn zip32_sapling_dk_i_update(sk_m: &[u8], dk_i: &mut DkBytes) {
    let mut dk_copy = [0u8; 32];
    dk_copy.copy_from_slice(dk_i);

    let t = &blake2b_expand_vec_two(sk_m, &[0x16], &dk_copy);

    dk_i.copy_from_slice(&t[0..32]);
}

// #[inline(never)]
// fn diversifier_group_hash_check(hash: &[u8; 32]) -> bool {
//     let u = AffinePoint::from_bytes(*hash);
//     if u.is_some().unwrap_u8() == 1 {
//         let v = u.unwrap();
//         let q = v.mul_by_cofactor();
//         let i = ExtendedPoint::identity();
//         return q != i;
//     }
//
//     false
// }

//list of 10 diversifiers
#[inline(never)]
pub fn ff1aes_list_10(sk: &[u8; 32], result: &mut DiversifierList10) {
    let DIVERSIFIER_LIST_SIZE = 10;

    let cipher: AesSDK = BlockCipher::new(GenericArray::from_slice(sk));

    let mut scratch = [0u8; 12];
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();

    let mut d: Diversifier;
    let mut counter: Diversifier = diversifier_zero();

    for c in 0..DIVERSIFIER_LIST_SIZE {
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
pub fn ff1aes_list_with_startingindex_4(
    sk: &[u8; 32],
    counter: &mut Diversifier,
    result: &mut DiversifierList4,
) {
    let DIVERSIFIER_LIST_SIZE = 4;

    let cipher: AesSDK = BlockCipher::new(GenericArray::from_slice(sk));

    let mut scratch = [0u8; 12];
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();

    let mut d: Diversifier;

    for c in 0..DIVERSIFIER_LIST_SIZE {
        d = *counter;
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

//list of 20 diversifiers
#[inline(never)]
pub fn ff1aes_list_with_startingindex_20(
    sk: &[u8; 32],
    start_diversifier: &Diversifier,
    result: &mut DiversifierList20,
) {
    let DIVERSIFIER_LIST_SIZE = 20;

    let cipher: AesSDK = BlockCipher::new(GenericArray::from_slice(sk));

    let mut scratch = [0u8; 12];
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();

    let mut d: Diversifier;
    let mut counter: Diversifier = diversifier_zero();
    counter.copy_from_slice(start_diversifier);

    for c in 0..DIVERSIFIER_LIST_SIZE {
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
pub fn pkd_group_hash(d: &Diversifier) -> [u8; 32] {
    let h = blake2b::blake2s_diversification(d);

    let v = AffinePoint::from_bytes(h).unwrap();
    let q = v.mul_by_cofactor();
    let t = AffinePoint::from(q);
    t.to_bytes()
}

#[inline(never)]
pub fn niels_multbits(p: &mut ExtendedPoint, b: &[u8; 32]) {
    *p = p.to_niels().multiply_bits(b);
}

#[inline(never)]
pub fn default_pkd(ivk: &[u8; 32], d: &Diversifier) -> [u8; 32] {
    let h = blake2b::blake2s_diversification(d);
    c_zemu_log_stack(b"default_pkd\x00\n".as_ref());
    let mut y = bytes_to_extended(h);
    cryptoops::mul_by_cofactor(&mut y);

    niels_multbits(&mut y, ivk);
    let tmp = extended_to_bytes(&y);
    tmp
}

#[inline(never)]
pub fn full_viewing_key(s_k: &[u8; 32]) -> FullViewingKey {
    let ask = zip32_sapling_ask_m(s_k);
    crate::bolos::heartbeat();

    let nsk = zip32_sapling_nsk_m(s_k);
    crate::bolos::heartbeat();

    let ovk = zip32_sapling_ovk_m(s_k);
    crate::bolos::heartbeat();

    ////

    let ak = sapling::sapling_ask_to_ak(&ask);
    crate::bolos::heartbeat();

    let nk = sapling::sapling_nsk_to_nk(&nsk);
    crate::bolos::heartbeat();

    FullViewingKey::new(ak, nk, ovk)
}

#[inline(never)]
pub fn zip32_expanded_spending_key(key: &[u8; 32]) -> SaplingExpandedSpendingKey {
    SaplingExpandedSpendingKey::new(
        zip32_sapling_ask_m(key),
        zip32_sapling_nsk_m(key),
        zip32_sapling_ovk_m(key),
    )
}

#[inline(never)]
pub fn zip32_update_exk(key: &[u8; 32], exk: &mut SaplingExpandedSpendingKey) {
    exk.ask_mut().copy_from_slice(&zip32_sapling_ask_m(key));
    exk.nsk_mut().copy_from_slice(&zip32_sapling_nsk_m(key));

    let mut ovkcopy = [0u8; 32];
    ovkcopy.copy_from_slice(&exk.ovk());
    exk.ovk_mut()
        .copy_from_slice(&blake2b_expand_vec_two(key, &[0x15], &ovkcopy)[..32]);
}

#[inline(never)]
pub fn zip32_derive_master(seed: &Zip32Seed) -> [u8; 96] {
    let master_key = zip32_master_key_i(seed); //64

    let dk = zip32_sapling_dk_m(&master_key.spending_key());
    let ask = zip32_sapling_ask_m(&master_key.spending_key());
    let nsk = zip32_sapling_nsk_m(&master_key.spending_key());

    let mut result = [0u8; 96];
    result[0..32].copy_from_slice(&dk);
    result[32..64].copy_from_slice(&ask);
    result[64..96].copy_from_slice(&nsk);
    result
}
/*
ChildIndex::Hardened(32),
ChildIndex::Hardened(config.get_coin_type()),
ChildIndex::Hardened(pos)
*/

#[inline(never)]
pub fn zip32_derive_ovk_fromseedandpath(seed: &Zip32Seed, path: &[u32]) -> OvkBytes {
    let mut master_key = zip32_master_key_i(seed);
    crate::bolos::heartbeat();

    let mut ask = Fr::from_bytes_wide(&cryptoops::prf_expand(&master_key.spending_key(), &[0x00]));
    let mut nsk = Fr::from_bytes_wide(&cryptoops::prf_expand(&master_key.spending_key(), &[0x01]));
    crate::bolos::heartbeat();

    let mut expkey = zip32_expanded_spending_key(&master_key.spending_key());
    crate::bolos::heartbeat();

    let mut divkey = [0u8; 32];
    divkey.copy_from_slice(&zip32_sapling_dk_m(&master_key.spending_key())); //32

    for p in path.iter().copied() {
        //compute expkey needed for zip32 child derivation
        //non-hardened child
        let hardened = (p & 0x8000_0000) != 0;
        let c = p & 0x7FFF_FFFF;

        if hardened {
            let mut le_i = [0; 4];
            LittleEndian::write_u32(&mut le_i, c + (1 << 31));

            //make index LE
            //zip32 child derivation
            let r = blake2b_expand_vec_four(
                &master_key.chain_code(),
                &[0x11],
                &expkey.to_bytes(),
                &divkey,
                &le_i,
            );

            master_key.to_bytes_mut().copy_from_slice(&r);
        } else {
            //WARNING: CURRENTLY COMPUTING NON-HARDENED PATHS DO NOT FIT IN MEMORY
            let mut le_i = [0; 4];
            LittleEndian::write_u32(&mut le_i, c);

            let fvk = full_viewing_key(&master_key.spending_key());

            let r = blake2b_expand_vec_four(
                &master_key.chain_code(),
                &[0x12],
                &fvk.to_bytes(),
                &divkey,
                &le_i,
            );

            master_key.to_bytes_mut().copy_from_slice(&r);
        }
        crate::bolos::heartbeat();

        //extract key and chainkey
        let ask_cur =
            Fr::from_bytes_wide(&cryptoops::prf_expand(&master_key.spending_key(), &[0x13]));
        let nsk_cur =
            Fr::from_bytes_wide(&cryptoops::prf_expand(&master_key.spending_key(), &[0x14]));

        ask += ask_cur;
        nsk += nsk_cur;

        //new divkey from old divkey and key
        crate::bolos::heartbeat();
        zip32_sapling_dk_i_update(&master_key.spending_key(), &mut divkey);
        zip32_update_exk(&master_key.spending_key(), &mut expkey);
    }

    let mut result: OvkBytes = [0u8; 32];
    result[0..32].copy_from_slice(&master_key.spending_key());
    result
}

#[inline(never)]
pub fn zip32_derive_fvk_fromseedandpath(seed: &[u8; 32], path: &[u32]) -> FullViewingKey {
    let mut master_key = zip32_master_key_i(seed);
    crate::bolos::heartbeat();

    let mut ask = Fr::from_bytes_wide(&cryptoops::prf_expand(&master_key.spending_key(), &[0x00]));
    let mut nsk = Fr::from_bytes_wide(&cryptoops::prf_expand(&master_key.spending_key(), &[0x01]));
    crate::bolos::heartbeat();

    let mut expkey = zip32_expanded_spending_key(&master_key.spending_key());
    crate::bolos::heartbeat();

    let mut divkey = [0u8; 32];
    divkey.copy_from_slice(&zip32_sapling_dk_m(&master_key.spending_key())); //32

    for p in path.iter().copied() {
        //compute expkey needed for zip32 child derivation
        //non-hardened child
        let hardened = (p & 0x8000_0000) != 0;
        let c = p & 0x7FFF_FFFF;

        if hardened {
            let mut le_i = [0; 4];
            LittleEndian::write_u32(&mut le_i, c + (1 << 31));

            //make index LE
            //zip32 child derivation
            let r = blake2b_expand_vec_four(
                &master_key.chain_code(),
                &[0x11],
                &expkey.to_bytes(),
                &divkey,
                &le_i,
            );

            master_key.to_bytes_mut().copy_from_slice(&r);
        } else {
            //WARNING: CURRENTLY COMPUTING NON-HARDENED PATHS DO NOT FIT IN MEMORY
            let mut le_i = [0; 4];
            LittleEndian::write_u32(&mut le_i, c);

            let fvk = full_viewing_key(&master_key.spending_key());
            let r = blake2b_expand_vec_four(
                &master_key.chain_code(),
                &[0x12],
                &fvk.to_bytes(),
                &divkey,
                &le_i,
            );

            master_key.to_bytes_mut().copy_from_slice(&r);
        }
        crate::bolos::heartbeat();

        //extract key and chainkey
        let ask_cur =
            Fr::from_bytes_wide(&cryptoops::prf_expand(&master_key.spending_key(), &[0x13]));
        let nsk_cur =
            Fr::from_bytes_wide(&cryptoops::prf_expand(&master_key.spending_key(), &[0x14]));

        ask += ask_cur;
        nsk += nsk_cur;

        //new divkey from old divkey and key
        crate::bolos::heartbeat();
        zip32_sapling_dk_i_update(&master_key.spending_key(), &mut divkey);
        zip32_update_exk(&master_key.spending_key(), &mut expkey);
    }

    let ak = sapling::sapling_ask_to_ak(&ask.to_bytes());
    let nk = sapling::sapling_nsk_to_nk(&nsk.to_bytes());
    let ovk = zip32_sapling_ovk_m(&master_key.spending_key());

    FullViewingKey::new(ak, nk, ovk)
}

fn zip32_sapling_derive_child(
    ik: &mut Zip32MasterKey,
    path_i: u32,
    mut esk_i: &mut SaplingExpandedSpendingKey,
    mut dk_i: &mut DkBytes,
    mut ask_i: &mut AskBytes,
    mut nsk_i: &mut NskBytes,
    mut ovk_i: &mut OvkBytes,
) {
    let hardened = (path_i & 0x8000_0000) != 0;
    let c = path_i & 0x7FFF_FFFF;

    let mut le_i = [0; 4];
    if hardened {
        LittleEndian::write_u32(&mut le_i, c + (1 << 31));

        //make index LE
        //zip32 child derivation
        let r =
            blake2b_expand_vec_four(&ik.chain_code(), &[0x11], &esk_i.to_bytes(), &*dk_i, &le_i);

        ik.to_bytes_mut().copy_from_slice(&r);
    } else {
        //non-hardened child
        // NOTE: WARNING: CURRENTLY COMPUTING NON-HARDENED PATHS DO NOT FIT IN MEMORY
        LittleEndian::write_u32(&mut le_i, c);

        // FIXME: Duplicated work?
        let fvk = full_viewing_key(&ik.spending_key());

        let r = blake2b_expand_vec_four(&ik.chain_code(), &[0x12], &fvk.to_bytes(), &*dk_i, &le_i);

        ik.to_bytes_mut().copy_from_slice(&r);
    }
    crate::bolos::heartbeat();

    // https://zips.z.cash/zip-0032#deriving-a-child-extended-spending-key

    zip32_sapling_ask_i_update(&ik.spending_key(), &mut *ask_i);
    zip32_sapling_nsk_i_update(&ik.spending_key(), &mut *nsk_i);
    zip32_sapling_dk_i_update(&ik.spending_key(), &mut dk_i);
    zip32_sapling_ovk_i_update(&ik.spending_key(), &mut ovk_i);

    zip32_update_exk(&ik.spending_key(), &mut esk_i);
}

#[inline(never)]
pub fn zip32_sapling_derive(
    seed: &[u8; 32],
    account: u32,
    child_components: Zip32ChildComponents,
) -> [u8; 96] {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];

    // ik as in capital I (https://zips.z.cash/zip-0032#sapling-child-key-derivation)
    let mut ik = zip32_master_key_i(seed);
    crate::bolos::heartbeat();

    let mut ask_i = zip32_sapling_ask_m(&ik.spending_key());
    let mut nsk_i = zip32_sapling_nsk_m(&ik.spending_key());
    let mut ovk_i = zip32_sapling_ovk_m(&ik.spending_key());

    let mut dk_i = zip32_sapling_dk_m(&ik.spending_key());

    // FIXME: Duplicated work?
    let mut esk_i = zip32_expanded_spending_key(&ik.spending_key());
    crate::bolos::heartbeat();

    for p in path.iter().copied() {
        zip32_sapling_derive_child(
            &mut ik, p, &mut esk_i, &mut dk_i, &mut ask_i, &mut nsk_i, &mut ovk_i,
        );
    }

    let mut result = [0u8; 96];
    match child_components {
        /// Group These Two
        Zip32ChildComponents::DkAkNk => {
            let ak = sapling::sapling_ask_to_ak(&ask_i);
            let nk = sapling::sapling_nsk_to_nk(&nsk_i);
            result[0..32].copy_from_slice(&dk_i);
            result[32..64].copy_from_slice(&ak);
            result[64..96].copy_from_slice(&nk);
        }
        Zip32ChildComponents::AkNk => {
            let ak = sapling::sapling_ask_to_ak(&ask_i);
            let nk = sapling::sapling_nsk_to_nk(&nsk_i);
            result[0..32].copy_from_slice(&ak);
            result[32..64].copy_from_slice(&nk);
        }
        Zip32ChildComponents::Dk => {
            result[0..32].copy_from_slice(&dk_i);
        }
        Zip32ChildComponents::AkNsk => {
            let ak = sapling::sapling_ask_to_ak(&ask_i);
            result[0..32].copy_from_slice(&ak);
            result[32..64].copy_from_slice(&nsk_i);
        }
        /////////////////////////
        Zip32ChildComponents::AskNsk => {
            result[0..32].copy_from_slice(&ask_i);
            result[32..64].copy_from_slice(&nsk_i);
        }
    }
    c_check_app_canary();
    result
}

#[inline(never)]
#[deprecated(note = "This function is deprecated and will be removed in future releases.")]
pub fn deprecated_master_nsk_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let master_key = zip32_master_key_i(seed); //64

    crate::bolos::heartbeat();
    let nsk = Fr::from_bytes_wide(&cryptoops::prf_expand(&master_key.spending_key(), &[0x01]));

    let mut result = [0u8; 32];
    result.copy_from_slice(&nsk.to_bytes());
    result
}

#[no_mangle]
pub fn get_dk(seed_ptr: *const [u8; 32], dk_ptr: *mut [u8; 32], pos: u32) {
    let seed = unsafe { &*seed_ptr };
    let dk = unsafe { &mut *dk_ptr };

    let k = zip32_sapling_derive(seed, pos, Zip32ChildComponents::Dk); //consistent with zecwallet

    // k = dk || ...
    dk.copy_from_slice(&k[0..32]);
}

////////////////////////////////
////////////////////////////////

#[no_mangle]
pub extern "C" fn zip32_ivk(seed_ptr: *const [u8; 32], ivk_ptr: *mut [u8; 32], pos: u32) {
    c_zemu_log_stack(b"zip32_ivk\x00\n".as_ref());

    let seed = unsafe { &*seed_ptr };
    let ivk = unsafe { &mut *ivk_ptr };

    crate::bolos::heartbeat();
    let k = zip32_sapling_derive(seed, pos, Zip32ChildComponents::AkNk); //consistent with zecwallet

    // k =  ak || nk
    // ak = k[0..32]
    // nk = k[32..64]

    let tmp_ivk = sapling::sapling_aknk_to_ivk(
        &k[0..32].try_into().unwrap(),
        &k[32..64].try_into().unwrap(),
    );

    ivk.copy_from_slice(&tmp_ivk)
}

////////////////////////////////
////////////////////////////////

#[no_mangle]
pub extern "C" fn get_default_diversifier_without_start_index(
    seed_ptr: *const [u8; 32],
    pos: u32,
    diversifier_ptr: *mut Diversifier,
) {
    c_zemu_log_stack(b"get_pkd_from_seed\x00\n".as_ref());
    let seed = unsafe { &*seed_ptr };
    let mut start = diversifier_zero();
    let div = unsafe { &mut *diversifier_ptr };

    let mut div_list = [0u8; DIV_SIZE * DIV_DEFAULT_LIST_LEN];

    let dk = zip32_sapling_derive(&seed, pos, Zip32ChildComponents::DkAkNk);

    let mut found = false;

    while !found {
        let sk = &dk[0..32].try_into().unwrap();
        ff1aes_list_with_startingindex_4(sk, &mut start, &mut div_list);

        for i in 0..DIV_DEFAULT_LIST_LEN {
            if !found
                && is_valid_diversifier(
                    &div_list[i * DIV_SIZE..(i + 1) * DIV_SIZE]
                        .try_into()
                        .unwrap(),
                )
            {
                found = true;
                div.copy_from_slice(&div_list[i * DIV_SIZE..(i + 1) * DIV_SIZE]);
            }
        }
        crate::bolos::heartbeat();
    }
}

// #[no_mangle]
// pub extern "C" fn zip32_master(
//     seed_ptr: *const [u8; 32],
//     sk_ptr: *mut [u8; 32],
//     dk_ptr: *mut [u8; 32],
// ) {
//     let seed = unsafe { &*seed_ptr };
//     let sk = unsafe { &mut *sk_ptr };
//     let dk = unsafe { &mut *dk_ptr };
//
//     let k = derive_zip32_master(seed);
//     sk.copy_from_slice(&k[0..32]);
//     dk.copy_from_slice(&k[32..64])
// }

//this function is consistent with zecwallet code
#[no_mangle]
pub extern "C" fn zip32_ovk(seed_ptr: *const [u8; 32], ovk_ptr: *mut [u8; 32], account: u32) {
    let seed = unsafe { &*seed_ptr };
    let ovk = unsafe { &mut *ovk_ptr };

    crate::bolos::heartbeat();

    // FIXME: no need to pass the complete path
    let k = zip32_derive_ovk_fromseedandpath(seed, &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account]); //consistent with zecwallet
    ovk.copy_from_slice(&k[0..32]);
}

//this function is consistent with zecwallet code
#[no_mangle]
pub extern "C" fn zip32_fvk(seed_ptr: *const [u8; 32], fvk_ptr: *mut [u8; 96], account: u32) {
    c_zemu_log_stack(b"zip32_fvk\x00\n".as_ref());
    let seed = unsafe { &*seed_ptr };

    let fvk = unsafe { &mut *fvk_ptr };

    // FIXME: no need to pass the complete path
    let k = zip32_derive_fvk_fromseedandpath(seed, &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account]); //consistent with zecwallet
    fvk.copy_from_slice(k.to_bytes());
}

////////////////////////////////
////////////////////////////////

#[no_mangle]
pub extern "C" fn zip32_child_proof_key(
    seed_ptr: *const [u8; 32],
    ak_ptr: *mut [u8; 32],
    nsk_ptr: *mut [u8; 32],
    account: u32,
) {
    let seed = unsafe { &*seed_ptr };

    let k = zip32_sapling_derive(seed, account, Zip32ChildComponents::AkNsk); //consistent with zecwallet

    let ak = unsafe { &mut *ak_ptr };
    let nsk = unsafe { &mut *nsk_ptr };
    // k = ak || nsk
    ak.copy_from_slice(&k[0..32]);
    nsk.copy_from_slice(&k[32..64]);
}

////////////////////////////////
////////////////////////////////

#[no_mangle]
pub extern "C" fn zip32_child_ask_nsk(
    seed_ptr: *const [u8; 32],
    ask_ptr: *mut [u8; 32],
    nsk_ptr: *mut [u8; 32],
    pos: u32,
) {
    let seed = unsafe { &*seed_ptr };

    let k = zip32_sapling_derive(seed, pos, Zip32ChildComponents::AskNsk); //consistent with zecwallet;

    let ask = unsafe { &mut *ask_ptr };
    let nsk = unsafe { &mut *nsk_ptr };
    ask.copy_from_slice(&k[0..32]);
    nsk.copy_from_slice(&k[32..64]);
}

////////////////////////////////
////////////////////////////////

#[no_mangle]
#[deprecated(note = "This function is deprecated and will be removed in future releases.")]
pub extern "C" fn zip32_nsk_from_seed(seed_ptr: *const [u8; 32], nsk_ptr: *mut [u8; 32]) {
    let seed = unsafe { &*seed_ptr };
    let nsk = unsafe { &mut *nsk_ptr };

    let k = deprecated_master_nsk_from_seed(seed);

    nsk.copy_from_slice(&k);
}

////////////////////////////////
////////////////////////////////

#[no_mangle]
pub extern "C" fn get_diversifier_list(
    sk_ptr: *const [u8; 32],
    diversifier_list_ptr: *mut DiversifierList10,
) {
    let sk = unsafe { &*sk_ptr };
    let diversifier = unsafe { &mut *diversifier_list_ptr };
    ff1aes_list_10(sk, diversifier);
}

////////////////////////////////
////////////////////////////////

#[no_mangle]
pub extern "C" fn get_diversifier_list_withstartindex(
    seed_ptr: *const [u8; 32],
    pos: u32,
    start_index: *const Diversifier,
    diversifier_list_ptr: *mut DiversifierList20,
) {
    let mut dk = [0u8; 32];
    let seed = unsafe { &*seed_ptr };
    let start = unsafe { &*start_index };
    let diversifier = unsafe { &mut *diversifier_list_ptr };
    get_dk(seed, &mut dk, pos);
    ff1aes_list_with_startingindex_20(&mut dk, start, diversifier);
}

////////////////////////////////
////////////////////////////////

#[no_mangle]
pub extern "C" fn get_default_diversifier_list_withstartindex(
    seed_ptr: *const [u8; 32],
    pos: u32,
    start_ptr: *mut Diversifier,
    diversifier_list_ptr: *mut DiversifierList4,
) {
    let mut dk = [0u8; 32];
    let seed = unsafe { &*seed_ptr };
    let start = unsafe { &mut *start_ptr };
    let diversifier = unsafe { &mut *diversifier_list_ptr };
    get_dk(seed, &mut dk, pos);
    ff1aes_list_with_startingindex_4(&mut dk, start, diversifier);
}

////////////////////////////////
////////////////////////////////

#[no_mangle]
pub extern "C" fn get_pkd_from_seed(
    seed_ptr: *const [u8; 32],
    pos: u32,
    start_index: *mut Diversifier,
    diversifier_ptr: *mut Diversifier,
    pkd_ptr: *mut [u8; 32],
) {
    c_zemu_log_stack(b"get_pkd_from_seed\x00\n".as_ref());
    let seed = unsafe { &*seed_ptr };
    let start = unsafe { &mut *start_index };
    let div = unsafe { &mut *diversifier_ptr };

    let mut div_list = [0u8; DIV_SIZE * DIV_DEFAULT_LIST_LEN];
    crate::bolos::heartbeat();
    let dk_ak_nk = zip32_sapling_derive(&seed, pos, Zip32ChildComponents::DkAkNk);

    let mut found = false;

    while !found {
        let sk = &mut dk_ak_nk[0..32].try_into().unwrap();
        ff1aes_list_with_startingindex_4(sk, start, &mut div_list);
        for i in 0..DIV_DEFAULT_LIST_LEN {
            if !found
                && is_valid_diversifier(
                    &div_list[i * DIV_SIZE..(i + 1) * DIV_SIZE]
                        .try_into()
                        .unwrap(),
                )
            {
                found = true;
                div.copy_from_slice(&div_list[i * DIV_SIZE..(i + 1) * DIV_SIZE]);
            }
        }
        crate::bolos::heartbeat();
    }
    let ivk = sapling::sapling_aknk_to_ivk(
        &dk_ak_nk[32..64].try_into().unwrap(),
        &dk_ak_nk[64..96].try_into().unwrap(),
    );

    let pkd = unsafe { &mut *pkd_ptr };
    let tmp_pkd = default_pkd(&ivk, div);
    pkd.copy_from_slice(&tmp_pkd);
}

////////////////////////////////
////////////////////////////////

#[inline(never)]
fn diversifier_group_hash_light(tag: &[u8]) -> bool {
    if tag == diversifier_zero() {
        return false;
    }
    let hash_tag = blake2b::blake2s_diversification(tag);

    //    diversifier_group_hash_check(&x)

    let u = AffinePoint::from_bytes(hash_tag);
    if u.is_some().unwrap_u8() == 1 {
        let q = u.unwrap().mul_by_cofactor();
        return q != ExtendedPoint::identity();
    }

    false
}

#[no_mangle]
pub extern "C" fn is_valid_diversifier(div_ptr: *const Diversifier) -> bool {
    let div = unsafe { &*div_ptr };
    diversifier_group_hash_light(div)
}

#[inline(never)]
pub fn default_diversifier_fromlist(list: &DiversifierList10) -> Diversifier {
    let mut result = diversifier_zero();

    for c in 0..10 {
        result.copy_from_slice(&list[c * 11..(c + 1) * 11]);
        //c[1] += 1;
        if diversifier_group_hash_light(&result) {
            //if diversifier_group_hash_light(&x[0..11]) {
            return result;
        }
    }
    //return a value that indicates that diversifier not found
    // FIXME: this seems a problem
    result
}

//////////////////////
//////////////////////

#[no_mangle]
pub extern "C" fn get_diversifier_fromlist(
    div_ptr: *mut Diversifier,
    diversifier_list_ptr: *const DiversifierList10,
) {
    let diversifier_list = unsafe { &*diversifier_list_ptr };
    let div = unsafe { &mut *div_ptr };

    let d = default_diversifier_fromlist(diversifier_list);
    div.copy_from_slice(&d)
}

//////////////////////
//////////////////////

#[no_mangle]
pub extern "C" fn get_pkd(
    seed_ptr: *const [u8; 32],
    pos: u32,
    diversifier_ptr: *const Diversifier,
    pkd_ptr: *mut [u8; 32],
) {
    c_zemu_log_stack(b"get_pkd\x00\n".as_ref());
    let ivk_ptr = &mut [0u8; 32];
    let diversifier = unsafe { &*diversifier_ptr };
    let pkd = unsafe { &mut *pkd_ptr };
    zip32_ivk(seed_ptr, ivk_ptr, pos);

    let tmp_pkd = default_pkd(ivk_ptr, &diversifier);
    pkd.copy_from_slice(&tmp_pkd)
}

#[cfg(test)]
mod tests {
    use crate::sapling::{sapling_aknk_to_ivk, sapling_ask_to_ak, sapling_nsk_to_nk};
    use crate::types::diversifier_list10_zero;

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
        let keys = zip32_derive_master(&seed);
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
        let keys = zip32_derive_master(&seed);
        assert_eq!(keys[0..32], dk);
    }

    #[test]
    fn test_zip32_childaddress() {
        let seed = [0u8; 32];

        let p: u32 = 0x8000_0001;
        let dk_ak_nk = zip32_sapling_derive(&seed, p, Zip32ChildComponents::DkAkNk);
        let ask_nsk = zip32_sapling_derive(&seed, p, Zip32ChildComponents::AskNsk);
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&dk_ak_nk[0..32]);

        let mut ak_derived = [0u8; 32];
        ak_derived.copy_from_slice(&dk_ak_nk[32..64]);

        let mut nk_derived = [0u8; 32];
        nk_derived.copy_from_slice(&dk_ak_nk[64..96]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&ask_nsk[0..32]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&ask_nsk[32..64]);

        let ask_expected = "3c2f45f9da64e1dd28cd51b9a967fefbd398f9a94373c13f64e4bfae9187f406";

        assert_eq!(hex::encode(ask), ask_expected);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        assert_eq!(ak, ak_derived);
        assert_eq!(nk, nk_derived);

        let ivk = sapling_aknk_to_ivk(&ak, &nk);
        assert_eq!(
            hex::encode(ivk),
            "7f2882eaefcd85e72661304c58f0e2c8bfbd8120caead9f2911e40baf3375401"
        );

        let mut listbytes = diversifier_list10_zero();
        ff1aes_list_10(&dk, &mut listbytes);
        let default_d = default_diversifier_fromlist(&listbytes);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(hex::encode(default_d), "0d60b722145a1df956f591");
        assert_eq!(
            hex::encode(pk_d),
            "484627ced466ef481867c477dc93d5d942947288df3673b3c294c09edafa0e32"
        );
    }

    #[test]
    fn test_zip32_childaddress_ledgerkey() {
        //e91db3f6c120a86ece0de8d21d452dcdcb708d563494e60a6cee676f5047ded7
        let s = hex::decode("b08e3d98da431cef4566a13c1bb348b982f7d8e743b43bb62557ba51994b1257")
            .expect("error");
        let seed: [u8; 32] = s.as_slice().try_into().expect("er");

        let p: u32 = 0x8000_1000;

        let dk_ak_nk = zip32_sapling_derive(&seed, p, Zip32ChildComponents::DkAkNk);
        let ask_nsk = zip32_sapling_derive(&seed, p, Zip32ChildComponents::AskNsk);
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&dk_ak_nk[0..32]);

        let mut ak_derived = [0u8; 32];
        ak_derived.copy_from_slice(&dk_ak_nk[32..64]);

        let mut nk_derived = [0u8; 32];
        nk_derived.copy_from_slice(&dk_ak_nk[64..96]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&ask_nsk[0..32]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&ask_nsk[32..64]);

        let ivk = sapling_aknk_to_ivk(&ak_derived, &nk_derived);

        assert_eq!(
            hex::encode(ivk),
            "d87d13325bbccca7abd9c404149ef8c4bebf9b6b0fc70f426d00df254c825406"
        );

        let mut list = diversifier_list10_zero();
        ff1aes_list_10(&dk, &mut list);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(hex::encode(default_d), "162fbb707ab875dfc04b74");
        assert_eq!(
            hex::encode(pk_d),
            "c20926d1af7acbd07d2a27c9f26ad11921d68ee517398cba10c878dd8be3f9e7"
        );
    }

    #[test]
    fn test_zip32_master_address_ledgerkey() {
        let s = hex::decode("b08e3d98da431cef4566a13c1bb348b982f7d8e743b43bb62557ba51994b1257")
            .expect("error");
        let seed: [u8; 32] = s.as_slice().try_into().expect("er");

        let keys = zip32_derive_master(&seed);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&keys[64..96]);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = sapling_aknk_to_ivk(&ak, &nk);

        let mut list = diversifier_list10_zero();
        ff1aes_list_10(&dk, &mut list);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(hex::encode(default_d), "f93dcfe2047253eebc17d4");
        assert_eq!(
            hex::encode(pk_d),
            "dc351792496b9d014e626c3bc929e6d32f507fb80b664f5cae97d37bf742dba9"
        );
    }

    #[test]
    fn test_zip32_master_address_allzero() {
        let seed = [0u8; 32];

        let keys = zip32_derive_master(&seed);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&keys[64..96]);

        let nk = sapling_nsk_to_nk(&nsk);
        let ak = sapling_ask_to_ak(&ask);

        let ivk = sapling_aknk_to_ivk(&ak, &nk);
        let mut list = diversifier_list10_zero();
        ff1aes_list_10(&dk, &mut list);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(hex::encode(default_d), "3bf6fa1f83bf4563c8a713");
        assert_eq!(
            hex::encode(pk_d),
            "0454c014135ec695a1860f8d65b373546b623f388abbecd0c8b2111abdec301d"
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

        let ivk: [u8; 32] = sapling_aknk_to_ivk(&ak, &nk);
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
        let mut list = diversifier_list10_zero();
        ff1aes_list_10(&seed, &mut list);
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
        let ask: [u8; 32] = zip32_sapling_ask_m(&seed);
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

        let nsk: [u8; 32] = zip32_sapling_nsk_m(&seed);
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

        let ivk: [u8; 32] = sapling_aknk_to_ivk(&ak, &nk);
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

#[no_mangle]
pub extern "C" fn randomized_secret_from_seed(
    seed_ptr: *const [u8; 32],
    pos: u32,
    alpha_ptr: *const [u8; 32],
    output_ptr: *mut [u8; 32],
) {
    let mut ask = [0u8; 32];
    let mut nsk = [0u8; 32];
    let alpha = unsafe { &*alpha_ptr };
    let output = unsafe { &mut *output_ptr };

    zip32_child_ask_nsk(seed_ptr, &mut ask, &mut nsk, pos);

    let mut skfr = Fr::from_bytes(&ask).unwrap();
    let alphafr = Fr::from_bytes(&alpha).unwrap();
    skfr += alphafr;
    output.copy_from_slice(&skfr.to_bytes());
}
