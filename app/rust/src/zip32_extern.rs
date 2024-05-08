use crate::bolos::c_zemu_log_stack;
use crate::constants::{
    Zip32ChildComponents, DIV_DEFAULT_LIST_LEN, DIV_SIZE, ZIP32_COIN_TYPE, ZIP32_PURPOSE,
};
use crate::sapling::{sapling_aknk_to_ivk, sapling_ask_to_ak};
use crate::types::{
    diversifier_zero, Diversifier, DiversifierList10, DiversifierList20, DiversifierList4,
    FullViewingKey, SaplingAskNskDk, Zip32Seed,
};
use crate::zip32::diversifier_group_hash_light;
use crate::{sapling, zip32};
use jubjub::Fr;

#[no_mangle]
pub extern "C" fn zip32_ivk(seed_ptr: *const [u8; 32], ivk_ptr: *mut [u8; 32], account: u32) {
    c_zemu_log_stack(b"zip32_ivk\x00\n".as_ref());

    let seed = unsafe { &*seed_ptr };
    let ivk = unsafe { &mut *ivk_ptr };

    crate::bolos::heartbeat();
    let k = FullViewingKey::from_bytes(&zip32::zip32_sapling_derive(
        seed,
        &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account],
        Zip32ChildComponents::FullViewingKey,
    ));

    let tmp_ivk = sapling_aknk_to_ivk(&k.ak(), &k.nk());

    ivk.copy_from_slice(&tmp_ivk)
}

#[no_mangle]
pub extern "C" fn get_default_diversifier_without_start_index(
    seed_ptr: *const [u8; 32],
    account: u32,
    diversifier_ptr: *mut Diversifier,
) {
    c_zemu_log_stack(b"get_pkd_from_seed\x00\n".as_ref());
    let seed = unsafe { &*seed_ptr };
    let mut start = diversifier_zero();
    let div = unsafe { &mut *diversifier_ptr };

    let mut div_list = [0u8; DIV_SIZE * DIV_DEFAULT_LIST_LEN];

    let ask_nsk_dk = SaplingAskNskDk::from_bytes(&zip32::zip32_sapling_derive(
        &seed,
        &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account],
        Zip32ChildComponents::AskNskDk,
    ));

    let mut found = false;

    while !found {
        let sk = &ask_nsk_dk.dk().try_into().unwrap();
        zip32::ff1aes_list_with_startingindex_4(sk, &mut start, &mut div_list);

        for i in 0..DIV_DEFAULT_LIST_LEN {
            if !found
                && diversifier_is_valid(
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

//this function is consistent with zecwallet code
#[no_mangle]
pub extern "C" fn zip32_ovk(seed_ptr: *const Zip32Seed, ovk_ptr: *mut [u8; 32], account: u32) {
    let seed = unsafe { &*seed_ptr };
    let ovk = unsafe { &mut *ovk_ptr };

    crate::bolos::heartbeat();

    // FIXME: duplicating space, risky
    let k = FullViewingKey::from_bytes(&zip32::zip32_sapling_derive(
        seed,
        &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account],
        Zip32ChildComponents::FullViewingKey,
    ));

    ovk.copy_from_slice(&k.ovk());
}

//this function is consistent with zecwallet code
#[no_mangle]
pub extern "C" fn zip32_fvk(seed_ptr: *const Zip32Seed, fvk_ptr: *mut [u8; 96], account: u32) {
    let seed = unsafe { &*seed_ptr };
    let fvk = unsafe { &mut *fvk_ptr };

    // FIXME: we are duplicating the space
    let k = FullViewingKey::from_bytes(&zip32::zip32_sapling_derive(
        seed,
        &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account],
        Zip32ChildComponents::FullViewingKey,
    ));

    fvk.copy_from_slice(&k.to_bytes());
}

#[no_mangle]
pub extern "C" fn zip32_child_proof_key(
    seed_ptr: *const [u8; 32],
    ak_ptr: *mut [u8; 32],
    nsk_ptr: *mut [u8; 32],
    account: u32,
) {
    let seed = unsafe { &*seed_ptr };

    let k = SaplingAskNskDk::from_bytes(&zip32::zip32_sapling_derive(
        seed,
        &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account],
        Zip32ChildComponents::AskNskDk,
    ));

    let ak = unsafe { &mut *ak_ptr };
    let nsk = unsafe { &mut *nsk_ptr };

    ak.copy_from_slice(&sapling_ask_to_ak(&k.ask()));
    nsk.copy_from_slice(&k.nsk());
}

#[no_mangle]
pub extern "C" fn zip32_child_ask_nsk(
    seed_ptr: *const [u8; 32],
    ask_ptr: *mut [u8; 32],
    nsk_ptr: *mut [u8; 32],
    account: u32,
) {
    let seed = unsafe { &*seed_ptr };

    let k = SaplingAskNskDk::from_bytes(&zip32::zip32_sapling_derive(
        seed,
        &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account],
        Zip32ChildComponents::AskNskDk,
    ));

    let ask = unsafe { &mut *ask_ptr };
    let nsk = unsafe { &mut *nsk_ptr };
    ask.copy_from_slice(&k.ask());
    nsk.copy_from_slice(&k.nsk());
}

#[no_mangle]
#[deprecated(note = "This function is deprecated and will be removed in future releases.")]
pub extern "C" fn zip32_nsk_from_seed(seed_ptr: *const [u8; 32], nsk_ptr: *mut [u8; 32]) {
    let seed = unsafe { &*seed_ptr };
    let nsk = unsafe { &mut *nsk_ptr };

    let k = zip32::deprecated_master_nsk_from_seed(seed);

    nsk.copy_from_slice(&k);
}

#[no_mangle]
pub extern "C" fn get_diversifier_list(
    sk_ptr: *const [u8; 32],
    diversifier_list_ptr: *mut DiversifierList10,
) {
    let sk = unsafe { &*sk_ptr };
    let diversifier = unsafe { &mut *diversifier_list_ptr };
    zip32::ff1aes_list_10(sk, diversifier);
}

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
    zip32::zip32_sapling_dk(seed, pos, &mut dk);
    zip32::ff1aes_list_with_startingindex_20(&mut dk, start, diversifier);
}

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
    zip32::zip32_sapling_dk(seed, pos, &mut dk);
    zip32::ff1aes_list_with_startingindex_4(&mut dk, start, diversifier);
}

#[no_mangle]
pub extern "C" fn get_pkd_from_seed(
    seed_ptr: *const [u8; 32],
    account: u32,
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

    let ask_nsk_df = SaplingAskNskDk::from_bytes(&zip32::zip32_sapling_derive(
        &seed,
        &[ZIP32_PURPOSE, ZIP32_COIN_TYPE, account],
        Zip32ChildComponents::AskNskDk,
    ));

    let mut found = false;

    while !found {
        let sk = &mut ask_nsk_df.dk().try_into().unwrap();
        zip32::ff1aes_list_with_startingindex_4(sk, start, &mut div_list);
        for i in 0..DIV_DEFAULT_LIST_LEN {
            if !found
                && diversifier_is_valid(
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

    let ivk = sapling::sapling_asknsk_to_ivk(
        &ask_nsk_df.ask().try_into().unwrap(),
        &ask_nsk_df.nsk().try_into().unwrap(),
    );

    let pkd = unsafe { &mut *pkd_ptr };
    let tmp_pkd = zip32::default_pkd(&ivk, div);
    pkd.copy_from_slice(&tmp_pkd);
}

#[no_mangle]
pub extern "C" fn get_diversifier_fromlist(
    div_ptr: *mut Diversifier,
    diversifier_list_ptr: *const DiversifierList10,
) {
    let diversifier_list = unsafe { &*diversifier_list_ptr };
    let div = unsafe { &mut *div_ptr };

    let d = zip32::diversifier_default_fromlist(diversifier_list);
    div.copy_from_slice(&d)
}

#[no_mangle]
pub extern "C" fn get_pkd(
    seed_ptr: *const [u8; 32],
    account: u32,
    diversifier_ptr: *const Diversifier,
    pkd_ptr: *mut [u8; 32],
) {
    c_zemu_log_stack(b"get_pkd\x00\n".as_ref());
    let ivk_ptr = &mut [0u8; 32];
    let diversifier = unsafe { &*diversifier_ptr };
    let pkd = unsafe { &mut *pkd_ptr };
    zip32_ivk(seed_ptr, ivk_ptr, account);

    let tmp_pkd = zip32::default_pkd(ivk_ptr, &diversifier);
    pkd.copy_from_slice(&tmp_pkd)
}

#[no_mangle]
pub extern "C" fn randomized_secret_from_seed(
    seed_ptr: *const [u8; 32],
    account: u32,
    alpha_ptr: *const [u8; 32],
    output_ptr: *mut [u8; 32],
) {
    let mut ask = [0u8; 32];
    let mut nsk = [0u8; 32];
    let alpha = unsafe { &*alpha_ptr };
    let output = unsafe { &mut *output_ptr };

    zip32_child_ask_nsk(seed_ptr, &mut ask, &mut nsk, account);

    let mut skfr = Fr::from_bytes(&ask).unwrap();
    let alphafr = Fr::from_bytes(&alpha).unwrap();
    skfr += alphafr;
    output.copy_from_slice(&skfr.to_bytes());
}

#[no_mangle]
pub extern "C" fn diversifier_is_valid(div_ptr: *const Diversifier) -> bool {
    let div = unsafe { &*div_ptr };
    diversifier_group_hash_light(div)
}
