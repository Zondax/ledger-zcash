use crate::bolos::blake2b::blake2b32_with_personalization;
use crate::bolos::jubjub::scalarmult_spending_base;
use crate::constants::PROVING_KEY_BASE;
use crate::cryptoops::niels_multbits;
use crate::cryptoops::{bytes_to_extended, extended_to_bytes, mul_by_cofactor};
use crate::personalization::{CRH_IVK_PERSONALIZATION, KDF_SAPLING_PERSONALIZATION};
use crate::types::{AkBytes, AskBytes, IvkBytes, NkBytes, NskBytes};
use blake2s_simd::Params as Blake2sParams;
use jubjub::AffinePoint;

#[inline(never)]
pub fn sapling_ask_to_ak(ask: &AskBytes) -> AkBytes {
    let mut point = [0u8; 32];
    scalarmult_spending_base(&mut point, &ask[..]);
    point
}

#[inline(never)]
pub fn sapling_nsk_to_nk(nsk: &NskBytes) -> NkBytes {
    let nk = PROVING_KEY_BASE.multiply_bits(&nsk);
    AffinePoint::from(nk).to_bytes()
}

#[inline(never)]
pub fn sapling_asknsk_to_ivk(ask: &AskBytes, nsk: &NskBytes) -> IvkBytes {
    let ak = sapling_ask_to_ak(ask);
    let nk = sapling_nsk_to_nk(nsk);

    // FIXME: not using bolos blake!?
    let h = Blake2sParams::new()
        .hash_length(32)
        .personal(CRH_IVK_PERSONALIZATION)
        .to_state()
        .update(&ak)
        .update(&nk)
        .finalize();

    let mut x: [u8; 32] = *h.as_array();
    x[31] &= 0b0000_0111; //check this
    x
}

#[inline(never)]
pub fn sapling_aknk_to_ivk(ak: &AkBytes, nk: &NkBytes) -> IvkBytes {
    // FIXME: not using bolos blake!?
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
