use core::convert::TryInto;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use binary_ff1::BinaryFF1;
use byteorder::{ByteOrder, LittleEndian};
use jubjub::{AffinePoint, ExtendedPoint, Fr};
use log::debug;

use crate::bolos::aes::AesSDK;
use crate::bolos::blake2b;
use crate::bolos::blake2b::{
    blake2b64_with_personalization, blake2b_expand_v4, blake2b_expand_vec_two,
};
use crate::bolos::c_check_app_canary;
use crate::constants::{Zip32ChildComponents, ZIP32_COIN_TYPE, ZIP32_PURPOSE};
use crate::cryptoops;
use crate::cryptoops::bytes_to_extended;
use crate::cryptoops::extended_to_bytes;
use crate::personalization::ZIP32_SAPLING_MASTER_PERSONALIZATION;
use crate::sapling::{sapling_aknk_to_ivk, sapling_ask_to_ak, sapling_nsk_to_nk};
use crate::types::{
    diversifier_zero, AskBytes, Diversifier, DiversifierList10, DiversifierList20,
    DiversifierList4, DkBytes, FullViewingKey, NskBytes, OvkBytes, SaplingAskNskDk,
    SaplingExpandedSpendingKey, Zip32MasterKey, Zip32Seed,
};

#[inline(never)]
// Calculates I based on https://zips.z.cash/zip-0032#sapling-master-key-generation
fn zip32_master_key_i(seed: &Zip32Seed) -> Zip32MasterKey {
    Zip32MasterKey::from_bytes(&blake2b64_with_personalization(
        ZIP32_SAPLING_MASTER_PERSONALIZATION,
        seed,
    ))
}

#[inline(never)]
// As per ask_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
fn zip32_sapling_ask_m(sk_m: &[u8]) -> AskBytes {
    let t = cryptoops::prf_expand(&sk_m, &[0x00]);
    let ask = Fr::from_bytes_wide(&t);
    ask.to_bytes()
}

#[inline(never)]
// As per nsk_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
fn zip32_sapling_nsk_m(sk_m: &[u8]) -> NskBytes {
    let t = cryptoops::prf_expand(&sk_m, &[0x01]);
    let nsk = Fr::from_bytes_wide(&t);
    nsk.to_bytes()
}

#[inline(never)]
// As per ovk_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
fn zip32_sapling_ovk_m(key: &[u8; 32]) -> OvkBytes {
    let prf_output = cryptoops::prf_expand(key, &[0x02]);

    // truncate
    let mut ovk = [0u8; 32];
    ovk.copy_from_slice(&prf_output[..32]);
    ovk
}

#[inline(never)]
// As per dk_m formula at https://zips.z.cash/zip-0032#sapling-master-key-generation
fn zip32_sapling_dk_m(sk_m: &[u8; 32]) -> DkBytes {
    let prf_output = cryptoops::prf_expand(sk_m, &[0x10]);

    // truncate
    let mut dk_m = [0u8; 32];
    dk_m.copy_from_slice(&prf_output[..32]);
    dk_m
}

#[inline(never)]
fn zip32_sapling_i_ask(sk_m: &[u8]) -> AskBytes {
    let t = cryptoops::prf_expand(&sk_m, &[0x13]);
    let ask = Fr::from_bytes_wide(&t);
    ask.to_bytes()
}

#[inline(never)]
fn zip32_sapling_i_nsk(sk_m: &[u8]) -> NskBytes {
    let t = cryptoops::prf_expand(&sk_m, &[0x14]);
    let nsk = Fr::from_bytes_wide(&t);
    nsk.to_bytes()
}

////////////

#[inline(never)]
fn zip32_sapling_ask_i_update(sk_m: &[u8], ask_i: &mut AskBytes) {
    let i_ask = zip32_sapling_i_ask(&sk_m);
    *ask_i = (Fr::from_bytes(&ask_i).unwrap() + Fr::from_bytes(&i_ask).unwrap()).to_bytes();
}

#[inline(never)]
fn zip32_sapling_nsk_i_update(sk_m: &[u8], nsk_i: &mut NskBytes) {
    let i_nsk = zip32_sapling_i_nsk(&sk_m);
    *nsk_i = (Fr::from_bytes(&nsk_i).unwrap() + Fr::from_bytes(&i_nsk).unwrap()).to_bytes();
}

#[inline(never)]
fn zip32_sapling_ovk_i_update(sk_m: &[u8], ovk_i: &mut DkBytes) {
    let mut ovk_copy = [0u8; 32];
    ovk_copy.copy_from_slice(ovk_i);

    let t = &blake2b_expand_vec_two(sk_m, &[0x15], &ovk_copy);

    ovk_i.copy_from_slice(&t[0..32]);
}

#[inline(never)]
fn zip32_sapling_dk_i_update(sk_m: &[u8], dk_i: &mut DkBytes) {
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
    let diversifier_list_size = 10;

    let cipher: AesSDK = BlockCipher::new(GenericArray::from_slice(sk));

    let mut scratch = [0u8; 12];
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();

    let mut d: Diversifier;
    let mut counter: Diversifier = diversifier_zero();

    for c in 0..diversifier_list_size {
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
    let diversifier_list_size = 4;

    let cipher: AesSDK = BlockCipher::new(GenericArray::from_slice(sk));

    let mut scratch = [0u8; 12];
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();

    let mut d: Diversifier;

    for c in 0..diversifier_list_size {
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
    let diversifier_list_size = 20;

    let cipher: AesSDK = BlockCipher::new(GenericArray::from_slice(sk));

    let mut scratch = [0u8; 12];
    let mut ff1 = BinaryFF1::new(&cipher, 11, &[], &mut scratch).unwrap();

    let mut d: Diversifier;
    let mut counter: Diversifier = diversifier_zero();
    counter.copy_from_slice(start_diversifier);

    for c in 0..diversifier_list_size {
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
pub fn default_pkd(ivk: &[u8; 32], d: &Diversifier) -> [u8; 32] {
    let h = blake2b::blake2s_diversification(d);
    let mut y = bytes_to_extended(h);

    cryptoops::mul_by_cofactor(&mut y);
    cryptoops::niels_multbits(&mut y, ivk);

    let tmp = extended_to_bytes(&y);
    tmp
}

#[inline(never)]
fn zip32_sapling_esk(s_k: &[u8; 32]) -> SaplingExpandedSpendingKey {
    SaplingExpandedSpendingKey::new(
        zip32_sapling_ask_m(s_k),
        zip32_sapling_nsk_m(s_k),
        zip32_sapling_ovk_m(s_k),
    )
}

#[inline(never)]
fn zip32_update_esk(s_k: &[u8; 32], esk: &mut SaplingExpandedSpendingKey) {
    esk.ask_mut().copy_from_slice(&zip32_sapling_ask_m(s_k));
    esk.nsk_mut().copy_from_slice(&zip32_sapling_nsk_m(s_k));

    let mut ovkcopy = [0u8; 32];
    ovkcopy.copy_from_slice(&esk.ovk());
    esk.ovk_mut()
        .copy_from_slice(&blake2b_expand_vec_two(s_k, &[0x15], &ovkcopy)[..32]);
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
        if cfg!(test) {
            debug!("---- path_i: {:x} | HARDENED", path_i);
        }

        LittleEndian::write_u32(&mut le_i, c + (1 << 31));

        //make index LE
        //zip32 child derivation
        let c_i = &ik.chain_code();

        let esk_i = SaplingExpandedSpendingKey::new(*ask_i, *nsk_i, *ovk_i);

        let prf_result = blake2b_expand_v4(c_i, &[0x11], &esk_i.to_bytes(), &*dk_i, &le_i);

        ik.to_bytes_mut().copy_from_slice(&prf_result);
    } else {
        if cfg!(test) {
            debug!("---- path_i: {:x} | NORMAL", path_i);
        }

        //non-hardened child
        // NOTE: WARNING: CURRENTLY COMPUTING NON-HARDENED PATHS DO NOT FIT IN MEMORY
        LittleEndian::write_u32(&mut le_i, c);

        // FIXME: Duplicated work?
        let s_k = &ik.spending_key();

        let ask = zip32_sapling_ask_m(s_k);
        let nsk = zip32_sapling_nsk_m(s_k);
        let ovk = zip32_sapling_ovk_m(s_k);
        let ak = sapling_ask_to_ak(&ask);
        let nk = sapling_nsk_to_nk(&nsk);

        let fvk = FullViewingKey::new(ak, nk, ovk);

        let prf_result =
            blake2b_expand_v4(&ik.chain_code(), &[0x12], &fvk.to_bytes(), &*dk_i, &le_i);

        ik.to_bytes_mut().copy_from_slice(&prf_result);
    }
    crate::bolos::heartbeat();

    // https://zips.z.cash/zip-0032#deriving-a-child-extended-spending-key

    zip32_update_esk(&ik.spending_key(), &mut esk_i);

    zip32_sapling_ask_i_update(&ik.spending_key(), &mut *ask_i);
    zip32_sapling_nsk_i_update(&ik.spending_key(), &mut *nsk_i);
    zip32_sapling_ovk_i_update(&ik.spending_key(), &mut ovk_i);

    zip32_sapling_dk_i_update(&ik.spending_key(), &mut dk_i);
}

#[inline(never)]
pub fn zip32_sapling_derive(
    seed: &[u8; 32],
    path: &[u32],
    child_components: Zip32ChildComponents,
) -> [u8; 96] {
    // ik as in capital I (https://zips.z.cash/zip-0032#sapling-child-key-derivation)
    let mut ik = zip32_master_key_i(seed);

    // FIXME: Duplicated work?
    let mut esk_i = zip32_sapling_esk(&ik.spending_key());

    let mut ask_i = zip32_sapling_ask_m(&ik.spending_key());
    let mut nsk_i = zip32_sapling_nsk_m(&ik.spending_key());
    let mut ovk_i = zip32_sapling_ovk_m(&ik.spending_key());

    let mut dk_i = zip32_sapling_dk_m(&ik.spending_key());

    if cfg!(test) {
        debug!("------------------------------ ");
        debug!("---- s_k_i :  {}", hex::encode(ik.spending_key()));
        debug!("---- c_k_i :  {}", hex::encode(ik.chain_code()));
        debug!(
            "---- ask_i :  {} {}",
            hex::encode(ask_i),
            hex::encode(esk_i.ask())
        );
        debug!(
            "---- nsk_i :  {} {}",
            hex::encode(nsk_i),
            hex::encode(esk_i.nsk())
        );
        debug!(
            "---- osk_i :  {} {}",
            hex::encode(ovk_i),
            hex::encode(esk_i.ovk())
        );
    }

    for path_i in path.iter().copied() {
        zip32_sapling_derive_child(
            &mut ik, path_i, &mut esk_i, &mut dk_i, &mut ask_i, &mut nsk_i, &mut ovk_i,
        );

        if cfg!(test) {
            debug!("---- path_i: {:x}", path_i);
            debug!("---- s_k_i :  {}", hex::encode(ik.spending_key()));
            debug!("---- c_k_i :  {}", hex::encode(ik.chain_code()));
            debug!(
                "---- ask_i :  {} {}",
                hex::encode(ask_i),
                hex::encode(esk_i.ask())
            );
            debug!(
                "---- nsk_i :  {} {}",
                hex::encode(nsk_i),
                hex::encode(esk_i.nsk())
            );
            debug!(
                "---- osk_i :  {} {}",
                hex::encode(ovk_i),
                hex::encode(esk_i.ovk())
            );
        }

        c_check_app_canary();
    }

    if cfg!(test) {
        debug!("------------------------------ ");
    }

    match child_components {
        Zip32ChildComponents::AskNskDk => {
            let tmp = SaplingAskNskDk::new(ask_i, nsk_i, dk_i);
            tmp.to_bytes().try_into().unwrap()
        }
        Zip32ChildComponents::FullViewingKey => {
            FullViewingKey::new(sapling_ask_to_ak(&ask_i), sapling_nsk_to_nk(&nsk_i), ovk_i)
                .to_bytes()
                .try_into()
                .unwrap()
        }
    }
}

#[inline(never)]
#[deprecated(note = "This function is deprecated and will be removed in future releases.")]
pub fn deprecated_master_nsk_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let master_key = zip32_master_key_i(seed);

    crate::bolos::heartbeat();
    let nsk = Fr::from_bytes_wide(&cryptoops::prf_expand(&master_key.spending_key(), &[0x01]));

    let mut result = [0u8; 32];
    result.copy_from_slice(&nsk.to_bytes());
    result
}

#[no_mangle]
pub fn zip32_sapling_dk(seed_ptr: *const Zip32Seed, account: u32, dk_ptr: *mut [u8; 32]) {
    let seed = unsafe { &*seed_ptr };
    let dk = unsafe { &mut *dk_ptr };

    let k = SaplingAskNskDk::from_bytes(&zip32_sapling_derive(
        seed,
        &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account],
        Zip32ChildComponents::AskNskDk,
    ));

    dk.copy_from_slice(&k.dk());
}

#[inline(never)]
pub(crate) fn diversifier_group_hash_light(tag: &[u8]) -> bool {
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

#[inline(never)]
pub fn diversifier_default_fromlist(list: &DiversifierList10) -> Diversifier {
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

/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
fn zip32_sapling_derive_master(seed: &Zip32Seed) -> SaplingAskNskDk {
    let master_key = zip32_master_key_i(seed);

    let ask = zip32_sapling_ask_m(&master_key.spending_key());
    let nsk = zip32_sapling_nsk_m(&master_key.spending_key());
    let dk = zip32_sapling_dk_m(&master_key.spending_key());

    SaplingAskNskDk::new(ask, nsk, dk)
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use crate::constants::ZIP32_HARDENED;
    use crate::sapling::{sapling_aknk_to_ivk, sapling_ask_to_ak, sapling_nsk_to_nk};
    use crate::types::diversifier_list10_zero;

    use super::*;

    // Based on test vectors at
    // https://github.com/zcash/zcash-test-vectors/blob/master/zcash_test_vectors/sapling/zip32.py
    // https://github.com/zcash/zcash-test-vectors/blob/master/test-vectors/zcash/sapling_zip32.json

    #[test]
    fn test_zip32_master() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();

        let keys = zip32_sapling_derive_master(&seed);
        assert_eq!(
            hex::encode(keys.ask()),
            "b6c00c93d36032b9a268e99e86a860776560bf0e83c1a10b51f607c954742506"
        );
        assert_eq!(
            hex::encode(keys.nsk()),
            "8204ede83b2f1fbd84f9b45d7f996e2ebd0a030ad243b48ed39f748a8821ea06"
        );
        assert_eq!(
            hex::encode(keys.dk()),
            "77c17cb75b7796afb39f0f3e91c924607da56fa9a20e283509bc8a3ef996a172"
        );

        let ak = sapling_ask_to_ak(&keys.ask());
        let nk = sapling_nsk_to_nk(&keys.nsk());
        assert_eq!(
            hex::encode(ak),
            "93442e5feffbff16e7217202dc7306729ffffe85af5683bce2642e3eeb5d3871"
        );
        assert_eq!(
            hex::encode(nk),
            "dce8e7edece04b8950417f85ba57691b783c45b1a27422db1693dceb67b10106"
        );

        let ivk = sapling_aknk_to_ivk(&ak, &nk);
        assert_eq!(
            hex::encode(ivk),
            "4847a130e799d3dbea36a1c16467d621fb2d80e30b3b1d1a426893415dad6601"
        );
    }

    #[test]
    fn test_zip32_master_empty() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();

        let ask_nsk_df = SaplingAskNskDk::from_bytes(&zip32_sapling_derive(
            &seed,
            &[],
            Zip32ChildComponents::AskNskDk,
        ));
        assert_eq!(
            hex::encode(ask_nsk_df.ask()),
            "b6c00c93d36032b9a268e99e86a860776560bf0e83c1a10b51f607c954742506"
        );
        assert_eq!(
            hex::encode(ask_nsk_df.nsk()),
            "8204ede83b2f1fbd84f9b45d7f996e2ebd0a030ad243b48ed39f748a8821ea06"
        );
        assert_eq!(
            hex::encode(ask_nsk_df.dk()),
            "77c17cb75b7796afb39f0f3e91c924607da56fa9a20e283509bc8a3ef996a172"
        );

        let ak = sapling_ask_to_ak(&ask_nsk_df.ask());
        let nk = sapling_nsk_to_nk(&ask_nsk_df.nsk());
        assert_eq!(
            hex::encode(ak),
            "93442e5feffbff16e7217202dc7306729ffffe85af5683bce2642e3eeb5d3871"
        );
        assert_eq!(
            hex::encode(nk),
            "dce8e7edece04b8950417f85ba57691b783c45b1a27422db1693dceb67b10106"
        );

        let ivk = sapling_aknk_to_ivk(&ak, &nk);
        assert_eq!(
            hex::encode(ivk),
            "4847a130e799d3dbea36a1c16467d621fb2d80e30b3b1d1a426893415dad6601"
        );

        let fvk = FullViewingKey::from_bytes(&zip32_sapling_derive(
            &seed,
            &[],
            Zip32ChildComponents::FullViewingKey,
        ));

        assert_eq!(
            hex::encode(fvk.ak()),
            "93442e5feffbff16e7217202dc7306729ffffe85af5683bce2642e3eeb5d3871"
        );
        assert_eq!(
            hex::encode(fvk.nk()),
            "dce8e7edece04b8950417f85ba57691b783c45b1a27422db1693dceb67b10106"
        );
        assert_eq!(
            hex::encode(fvk.ovk()),
            "395884890323b9d4933c021db89bcf767df21977b2ff0683848321a4df4afb21"
        );
    }

    #[test]
    fn test_zip32_derivation_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();
        let path = [1];

        let ask_nsk_df = SaplingAskNskDk::from_bytes(&zip32_sapling_derive(
            &seed,
            &path,
            Zip32ChildComponents::AskNskDk,
        ));

        assert_eq!(
            hex::encode(ask_nsk_df.ask()),
            "282bc197a516287c8ea8f68c424abad302b45cdf95407961d7b8b455267a350c"
        );
        assert_eq!(
            hex::encode(ask_nsk_df.nsk()),
            "e7a32988fdca1efcd6d1c4c562e629c2e96b2c3f7eda04ac4efd1810ff6bba01"
        );
        assert_eq!(
            hex::encode(ask_nsk_df.dk()),
            "e04de832a2d791ec129ab9002b91c9e9cdeed79241a7c4960e5178d870c1b4dc"
        );

        let ak = sapling_ask_to_ak(&ask_nsk_df.ask());
        let nk = sapling_nsk_to_nk(&ask_nsk_df.nsk());
        assert_eq!(
            hex::encode(ak),
            "dc14b514d3a92594c21925af2f7765a547b30e73fa7b700ea1bff2e5efaaa88b"
        );
        assert_eq!(
            hex::encode(nk),
            "6152eb7fdb252779ddcb95d217ea4b6fd34036e9adadb3b5c9cbeceb41ba452a"
        );

        let ivk = sapling_aknk_to_ivk(&ak, &nk);
        assert_eq!(
            hex::encode(ivk),
            "155a8ee205d3872d12f8a3e639914633c23cde1f30ed5051e52130b1d0104c06"
        );

        let fvk = FullViewingKey::from_bytes(&zip32_sapling_derive(
            &seed,
            &path,
            Zip32ChildComponents::FullViewingKey,
        ));

        assert_eq!(
            hex::encode(fvk.ak()),
            "dc14b514d3a92594c21925af2f7765a547b30e73fa7b700ea1bff2e5efaaa88b"
        );
        assert_eq!(
            hex::encode(fvk.nk()),
            "6152eb7fdb252779ddcb95d217ea4b6fd34036e9adadb3b5c9cbeceb41ba452a"
        );
        assert_eq!(
            hex::encode(fvk.ovk()),
            "5f1381fc8886da6a02dffeefcf503c40fa8f5a36f7a7142fd81b5518c5a47474"
        );
    }

    #[test]
    fn test_zip32_derivation_1_hard() {
        crate::tests::setup_logging();

        let seed = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();
        let path = [1 + ZIP32_HARDENED];

        let ask_nsk_df = SaplingAskNskDk::from_bytes(&zip32_sapling_derive(
            &seed,
            &path,
            Zip32ChildComponents::AskNskDk,
        ));

        assert_eq!(
            hex::encode(ask_nsk_df.ask()),
            "d5f7e92efb7abe04dc8c148b0b3b0fc23e0429f00208ff93b68d21a6e131bd04"
        );
        assert_eq!(
            hex::encode(ask_nsk_df.nsk()),
            "372a7c6822cbe603f3465c4b9b6558f3a3512decd434012e67bffcf657e5750a"
        );
        assert_eq!(
            hex::encode(ask_nsk_df.dk()),
            "f288400fd65f9adfe3a7c3720aceee0dae050d0a819d619f92e9e2cb4434d526"
        );

        let ak = sapling_ask_to_ak(&ask_nsk_df.ask());
        let nk = sapling_nsk_to_nk(&ask_nsk_df.nsk());
        assert_eq!(
            hex::encode(ak),
            "cfca79d337bc689813e409a54e3e72ad8e2f703ae6f8223c9becbde9a8a35f53"
        );
        assert_eq!(
            hex::encode(nk),
            "513de64085d35a3adf23d89d5a21cdee4db4c625bd6a3c3c624bef4344141deb"
        );

        let ivk = sapling_aknk_to_ivk(&ak, &nk);
        assert_eq!(
            hex::encode(ivk),
            "f6e75cd980c30eabc61f49ac68f488573ab3e6afe15376375d34e406702ffd02"
        );

        let fvk = FullViewingKey::from_bytes(&zip32_sapling_derive(
            &seed,
            &path,
            Zip32ChildComponents::FullViewingKey,
        ));

        assert_eq!(
            hex::encode(fvk.ak()),
            "cfca79d337bc689813e409a54e3e72ad8e2f703ae6f8223c9becbde9a8a35f53"
        );
        assert_eq!(
            hex::encode(fvk.nk()),
            "513de64085d35a3adf23d89d5a21cdee4db4c625bd6a3c3c624bef4344141deb"
        );
        assert_eq!(
            hex::encode(fvk.ovk()),
            "2530761933348c1fcf14355433a8d291167fbb37b2ce37ca97160a47ec331c69"
        );
    }

    #[test]
    fn test_zip32_derivation_2() {
        crate::tests::setup_logging();

        let seed = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();
        let path = [1, 2 + ZIP32_HARDENED];

        let ask_nsk_df = SaplingAskNskDk::from_bytes(&zip32_sapling_derive(
            &seed,
            &path,
            Zip32ChildComponents::AskNskDk,
        ));

        assert_eq!(
            hex::encode(ask_nsk_df.ask()),
            "8be8113cee3413a71f82c41fc8da517be134049832e6825c92da6b84fee4c60d"
        );
        assert_eq!(
            hex::encode(ask_nsk_df.nsk()),
            "3778059dc569e7d0d32391573f951bbde92fc6b9cf614773661c5c273aa6990c"
        );
        assert_eq!(
            hex::encode(ask_nsk_df.dk()),
            "a3eda19f9eff46ca12dfa1bf10371b48d1b4a40c4d05a0d8dce0e7dc62b07b37"
        );

        let ak = sapling_ask_to_ak(&ask_nsk_df.ask());
        let nk = sapling_nsk_to_nk(&ask_nsk_df.nsk());
        assert_eq!(
            hex::encode(ak),
            "a6c5925a0f85fa4f1e405e3a4970d0c4a4b4814438f4e9d4520e20f7fdcf3841"
        );
        assert_eq!(
            hex::encode(nk),
            "304e305916216beb7b654d8aae50ecd188fcb384bc36c00c664f307725e2ee11"
        );

        let ivk = sapling_aknk_to_ivk(&ak, &nk);
        assert_eq!(
            hex::encode(ivk),
            "a2a13c1e38b45984445803e430a683c90bb2e14d4c8692ff253a6484dd9bb504"
        );

        let fvk = FullViewingKey::from_bytes(&zip32_sapling_derive(
            &seed,
            &path,
            Zip32ChildComponents::FullViewingKey,
        ));

        assert_eq!(
            hex::encode(fvk.ak()),
            "a6c5925a0f85fa4f1e405e3a4970d0c4a4b4814438f4e9d4520e20f7fdcf3841"
        );
        assert_eq!(
            hex::encode(fvk.nk()),
            "304e305916216beb7b654d8aae50ecd188fcb384bc36c00c664f307725e2ee11"
        );
        assert_eq!(
            hex::encode(fvk.ovk()),
            "cf81182e96223c028ce3d6eb4794d3113b95069d14c57588e193b65efc2813bc"
        );
    }

    #[test]
    fn test_zip32_derivation_2_hard() {
        crate::tests::setup_logging();

        let seed = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();
        let path = [1  + ZIP32_HARDENED, 2 + ZIP32_HARDENED];

        let ask_nsk_df = SaplingAskNskDk::from_bytes(&zip32_sapling_derive(
            &seed,
            &path,
            Zip32ChildComponents::AskNskDk,
        ));

        assert_eq!(
            hex::encode(ask_nsk_df.ask()),
            "7ff35db69e13c36f59ad9c08d32d5227378da0cff971fd424baef9a6332f5106"
        );
        assert_eq!(
            hex::encode(ask_nsk_df.nsk()),
            "779c6ee4a03944eba28bc9bdc1329a391407f48c410d5ae0a364f59959bfde00"
        );
        assert_eq!(
            hex::encode(ask_nsk_df.dk()),
            "e4699e9a86e031c54b21cdd0960ac18ddd61ec9f7ae98d5582a6faf65f3248d1"
        );

        let ak = sapling_ask_to_ak(&ask_nsk_df.ask());
        let nk = sapling_nsk_to_nk(&ask_nsk_df.nsk());
        assert_eq!(
            hex::encode(ak),
            "9a853f9544713797e0851764da392e68534b1d948dae4742ee765c727572ab4e"
        );
        assert_eq!(
            hex::encode(nk),
            "f166a28a4f88cec12141a82d2120bd6d8caf879c9a1b3ad2118501364f5d4fbe"
        );

        let ivk = sapling_aknk_to_ivk(&ak, &nk);
        assert_eq!(
            hex::encode(ivk),
            "33bd46015a2cad17d6e015eb88861b0c917796246570521c9e1ae4b1c8311d06"
        );

        let fvk = FullViewingKey::from_bytes(&zip32_sapling_derive(
            &seed,
            &path,
            Zip32ChildComponents::FullViewingKey,
        ));

        assert_eq!(
            hex::encode(fvk.ak()),
            "9a853f9544713797e0851764da392e68534b1d948dae4742ee765c727572ab4e"
        );
        assert_eq!(
            hex::encode(fvk.nk()),
            "f166a28a4f88cec12141a82d2120bd6d8caf879c9a1b3ad2118501364f5d4fbe"
        );
        assert_eq!(
            hex::encode(fvk.ovk()),
            "d9fc7101bf907f41886a7330a5d6a7bd23535e305eb7679bc23d7605936185ac"
        );
    }

    #[test]
    fn test_zip32_childaddress() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();

        let account: u32 = 0x8000_0001;
        let ask_nsk_df = SaplingAskNskDk::from_bytes(&zip32_sapling_derive(
            &seed,
            &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account],
            Zip32ChildComponents::AskNskDk,
        ));

        let dk = ask_nsk_df.dk();
        let ask = ask_nsk_df.ask();
        let nsk = ask_nsk_df.nsk();
        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ask_expected = "3c2f45f9da64e1dd28cd51b9a967fefbd398f9a94373c13f64e4bfae9187f406";

        assert_eq!(hex::encode(ask), ask_expected);

        let ivk = sapling_aknk_to_ivk(&ak, &nk);
        assert_eq!(
            hex::encode(ivk),
            "7f2882eaefcd85e72661304c58f0e2c8bfbd8120caead9f2911e40baf3375401"
        );

        let mut listbytes = diversifier_list10_zero();
        ff1aes_list_10(&dk, &mut listbytes);
        let default_d = diversifier_default_fromlist(&listbytes);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(hex::encode(default_d), "0d60b722145a1df956f591");
        assert_eq!(
            hex::encode(pk_d),
            "484627ced466ef481867c477dc93d5d942947288df3673b3c294c09edafa0e32"
        );
    }

    #[test]
    fn test_zip32_childaddress_ledgerkey() {
        let s = hex::decode("b08e3d98da431cef4566a13c1bb348b982f7d8e743b43bb62557ba51994b1257")
            .expect("error");
        let seed: [u8; 32] = s.as_slice().try_into().expect("error decoding seed");

        let ask_nsk_dk = SaplingAskNskDk::from_bytes(&zip32_sapling_derive(
            &seed,
            &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, 0x8000_1000],
            Zip32ChildComponents::AskNskDk,
        ));
        let dk = ask_nsk_dk.dk();
        let ask = ask_nsk_dk.ask();
        let nsk = ask_nsk_dk.nsk();
        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = sapling_aknk_to_ivk(&ak, &nk);

        assert_eq!(
            hex::encode(ivk),
            "d87d13325bbccca7abd9c404149ef8c4bebf9b6b0fc70f426d00df254c825406"
        );

        let mut list = diversifier_list10_zero();
        ff1aes_list_10(&dk, &mut list);
        let default_d = diversifier_default_fromlist(&list);

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

        let keys = zip32_sapling_derive_master(&seed);

        let dk = keys.dk();
        let ask = keys.ask();
        let nsk = keys.nsk();
        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = sapling_aknk_to_ivk(&ak, &nk);

        let mut list = diversifier_list10_zero();
        ff1aes_list_10(&dk, &mut list);
        let default_d = diversifier_default_fromlist(&list);

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

        let keys = zip32_sapling_derive_master(&seed);

        let dk = keys.dk();
        let ask = keys.ask();
        let nsk = keys.nsk();
        let nk = sapling_nsk_to_nk(&nsk);
        let ak = sapling_ask_to_ak(&ask);

        let ivk = sapling_aknk_to_ivk(&ak, &nk);
        let mut list = diversifier_list10_zero();
        ff1aes_list_10(&dk, &mut list);
        let default_d = diversifier_default_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(hex::encode(default_d), "3bf6fa1f83bf4563c8a713");
        assert_eq!(
            hex::encode(pk_d),
            "0454c014135ec695a1860f8d65b373546b623f388abbecd0c8b2111abdec301d"
        );
    }

    #[test]
    fn test_div() {
        let nk = hex::decode("f7cf9e77f2e58683383c1519ac7b062d30040e27a725fb88fb19a978bd3fd6ba")
            .expect("error decoding hex")
            .try_into()
            .unwrap();
        let ak = hex::decode("f344ec380fe1273e3098c2588c5d3a791fd7ba958032760777fd0efa8ef11620")
            .expect("error decoding hex")
            .try_into()
            .unwrap();

        let ivk: [u8; 32] = sapling_aknk_to_ivk(&ak, &nk);
        let default_d = [
            0xf1, 0x9d, 0x9b, 0x79, 0x7e, 0x39, 0xf3, 0x37, 0x44, 0x58, 0x39,
        ];

        let result = pkd_group_hash(&default_d);
        let x = AffinePoint::from_bytes(result);
        if x.is_some().unwrap_u8() == 1 {
            let y = super::ExtendedPoint::from(x.unwrap());
            let v = y.to_niels().multiply_bits(&ivk);
            let t = super::AffinePoint::from(v);
            let pk_d = t.to_bytes();
            assert_eq!(
                hex::encode(pk_d),
                "db4cd2b0aac4f7eb8ca131f16567c445a9555126d3c29f14e3d776e841ae7415"
            );
        }
    }

    #[test]
    fn test_default_diversifier_fromlist() {
        let seed = [0u8; 32];
        let mut list = diversifier_list10_zero();
        ff1aes_list_10(&seed, &mut list);
        let default_d = diversifier_default_fromlist(&list);
        let expected_d = "dce77ebcec0a26afd6998c";
        assert_eq!(hex::encode(default_d), expected_d);
    }

    #[test]
    fn test_grouphash_default() {
        let default_d = hex::decode("f19d9b797e39f337445839")
            .expect("error decoding hex")
            .try_into()
            .unwrap();

        let result = pkd_group_hash(&default_d);

        let x = AffinePoint::from_bytes(result);
        assert_eq!(x.is_some().unwrap_u8(), 1);

        let expected_result = "3a71e348169e0cedbc4f3633a260d0e785ea8f8927ce4501cef3216ed075cea2";
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn test_ak() {
        let seed = [0u8; 32];
        let ask: [u8; 32] = zip32_sapling_ask_m(&seed);
        assert_eq!(
            hex::encode(ask),
            "8548a14a473ea547aa2378402044f818cf1911cf5dd2054f678345f00d0e8806"
        );
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);
        assert_eq!(
            hex::encode(ak),
            "f344ec380fe1273e3098c2588c5d3a791fd7ba958032760777fd0efa8ef11620"
        );
    }

    #[test]
    fn test_nk() {
        let seed = [0u8; 32];

        let nsk = zip32_sapling_nsk_m(&seed);
        let nk = sapling_nsk_to_nk(&nsk);

        assert_eq!(
            hex::encode(nsk),
            "30114ea0dd0bb61cf0eaeab6ec3331f581b0425e27338501262d7eac745e6e05"
        );
        assert_eq!(
            hex::encode(nk),
            "f7cf9e77f2e58683383c1519ac7b062d30040e27a725fb88fb19a978bd3fd6ba"
        );
    }

    #[test]
    fn test_ivk() {
        let nk = hex::decode("f7cf9e77f2e58683383c1519ac7b062d30040e27a725fb88fb19a978bd3fd6ba")
            .expect("error decoding hex")
            .try_into()
            .unwrap();
        let ak = hex::decode("f344ec380fe1273e3098c2588c5d3a791fd7ba958032760777fd0efa8ef11620")
            .expect("error decoding hex")
            .try_into()
            .unwrap();

        let ivk: [u8; 32] = sapling_aknk_to_ivk(&ak, &nk);
        assert_eq!(
            hex::encode(ivk),
            "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204"
        );
    }
}
