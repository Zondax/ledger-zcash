use jubjub::Fr;

use crate::bolos::{c_device_seed, c_zemu_log_stack};
use crate::constants::{DIV_DEFAULT_LIST_LEN, DIV_SIZE, ZIP32_COIN_TYPE, ZIP32_PURPOSE};
use crate::sapling::{
    sapling_aknk_to_ivk, sapling_ask_to_ak, sapling_asknsk_to_ivk, sapling_nsk_to_nk,
};
use crate::types::{
    diversifier_zero, Diversifier, DiversifierList10, DiversifierList20, DiversifierList4,
    FullViewingKey, IvkBytes, NskBytes, Zip32Seed,
};
use crate::zip32::{diversifier_group_hash_light, zip32_sapling_derive, zip32_sapling_fvk};
use crate::{sapling, zip32};

#[no_mangle]
pub extern "C" fn zip32_ivk(account: u32, ivk_ptr: *mut IvkBytes) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];
    let ivk = unsafe { &mut *ivk_ptr };

    crate::bolos::heartbeat();

    let k = zip32_sapling_derive(&path);
    let ak = sapling_ask_to_ak(&k.ask());
    let nk = sapling_nsk_to_nk(&k.nsk());

    let tmp_ivk = sapling_aknk_to_ivk(&ak, &nk);

    ivk.copy_from_slice(&tmp_ivk)
}

// This only tries to find ONE diversifier!!!
// Related to handleGetKeyIVK
#[no_mangle]
pub extern "C" fn diversifier_find_valid(zip32_account: u32, div_ptr: *mut Diversifier) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, zip32_account];
    let div_out = unsafe { &mut *div_ptr };

    let key_bundle = zip32_sapling_derive(&path);
    let dk = key_bundle.dk();

    let start = diversifier_zero();
    div_out.copy_from_slice(&zip32::diversifier_find_valid(&dk, &start));
}

//this function is consistent with zecwallet code
#[no_mangle]
pub extern "C" fn zip32_ovk(account: u32, ovk_ptr: *mut [u8; 32]) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];
    let ovk = unsafe { &mut *ovk_ptr };

    crate::bolos::heartbeat();

    let key_bundle = zip32_sapling_derive(&path);

    ovk.copy_from_slice(&key_bundle.ovk());
}

//this function is consistent with zecwallet code
#[no_mangle]
pub extern "C" fn zip32_fvk(account: u32, fvk_ptr: *mut FullViewingKey) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];
    let fvk_out = unsafe { &mut *fvk_ptr };

    let key_bundle = zip32_sapling_derive(&path);

    let fvk = zip32_sapling_fvk(&key_bundle);

    fvk_out.to_bytes_mut().copy_from_slice(fvk.to_bytes());
}

#[no_mangle]
pub extern "C" fn zip32_child_proof_key(
    account: u32,
    ak_ptr: *mut [u8; 32],
    nsk_ptr: *mut [u8; 32],
) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];
    let ak = unsafe { &mut *ak_ptr };
    let nsk = unsafe { &mut *nsk_ptr };

    let k = zip32_sapling_derive(&path);

    ak.copy_from_slice(&sapling_ask_to_ak(&k.ask()));
    nsk.copy_from_slice(&k.nsk());
}

#[no_mangle]
pub extern "C" fn zip32_child_ask_nsk(
    account: u32,
    ask_ptr: *mut [u8; 32],
    nsk_ptr: *mut [u8; 32],
) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];
    let ask = unsafe { &mut *ask_ptr };
    let nsk = unsafe { &mut *nsk_ptr };

    let key_bundle = zip32_sapling_derive(&path);

    ask.copy_from_slice(&key_bundle.ask());
    nsk.copy_from_slice(&key_bundle.nsk());
}

#[no_mangle]
pub extern "C" fn zip32_nsk(account: u32, nsk_ptr: *mut NskBytes) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];
    let nsk = unsafe { &mut *nsk_ptr };

    let key_bundle = zip32_sapling_derive(&path);

    nsk.copy_from_slice(&key_bundle.nsk());
}

// This will generate a list of 20 diversifiers starting from the given diversifier
// related to handleGetDiversifierList
#[no_mangle]
pub extern "C" fn diversifier_get_list(
    zip32_account: u32,
    start_index: *const Diversifier,
    diversifier_list_ptr: *mut DiversifierList20,
) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, zip32_account];
    let start = unsafe { &*start_index };
    let diversifier = unsafe { &mut *diversifier_list_ptr };

    let key_bundle = zip32_sapling_derive(&path);

    zip32::diversifier_get_list_large(&key_bundle.dk(), start, diversifier);
}

#[no_mangle]
pub extern "C" fn get_pkd(
    account: u32,
    diversifier_ptr: *const Diversifier,
    pkd_ptr: *mut [u8; 32],
) {
    let ivk_ptr = &mut [0u8; 32];
    let diversifier = unsafe { &*diversifier_ptr };
    let pkd = unsafe { &mut *pkd_ptr };

    zip32_ivk(account, ivk_ptr);

    let tmp_pkd = zip32::pkd_default(ivk_ptr, diversifier);
    pkd.copy_from_slice(&tmp_pkd)
}

#[no_mangle]
pub extern "C" fn get_pkd_from_seed(
    account: u32,
    start_diversifier: *mut Diversifier,
    div_ptr: *mut Diversifier,
    pkd_ptr: *mut [u8; 32],
) {
    let path = [ZIP32_PURPOSE, ZIP32_COIN_TYPE, account];
    let start = unsafe { &mut *start_diversifier };
    let div_out = unsafe { &mut *div_ptr };

    let key_bundle = zip32_sapling_derive(&path);
    let dk = key_bundle.dk();

    div_out.copy_from_slice(&zip32::diversifier_find_valid(&dk, start));

    let ivk = sapling_asknsk_to_ivk(&key_bundle.ask(), &key_bundle.nsk());
    let tmp_pkd = zip32::pkd_default(&ivk, div_out);

    let pkd_out = unsafe { &mut *pkd_ptr };
    pkd_out.copy_from_slice(&tmp_pkd);
}

#[no_mangle]
pub extern "C" fn randomized_secret_from_seed(
    account: u32,
    alpha_ptr: *const [u8; 32],
    output_ptr: *mut [u8; 32],
) {
    let mut ask = [0u8; 32];
    let mut nsk = [0u8; 32];
    let alpha = unsafe { &*alpha_ptr };
    let output = unsafe { &mut *output_ptr };

    zip32_child_ask_nsk(account, &mut ask, &mut nsk);

    let mut skfr = Fr::from_bytes(&ask).unwrap();
    let alphafr = Fr::from_bytes(alpha).unwrap();
    skfr += alphafr;
    output.copy_from_slice(&skfr.to_bytes());
}

#[no_mangle]
pub extern "C" fn diversifier_is_valid(div_ptr: *const Diversifier) -> bool {
    let div = unsafe { &*div_ptr };
    diversifier_group_hash_light(div)
}
