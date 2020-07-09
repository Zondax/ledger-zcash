use core::convert::TryInto;
use core::mem;

use crate::constants;
use crate::{bolos, zip32};

use crate::bolos::c_zemu_log_stack;
use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};
use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};

const COMPACT_NOTE_SIZE: usize = 1 /* version */ + 11 /*diversifier*/ + 8 /*value*/ + 32 /*rcv*/;

const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + 512;
const OUT_PLAINTEXT_SIZE: usize = 32 /*pk_d*/ + 32 /* esk */;

const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;
const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + 16;

pub fn generate_esk(buffer: [u8; 64]) -> [u8; 32] {
    //Rng.fill_bytes(&mut buffer); fill with random bytes
    let esk = Fr::from_bytes_wide(&buffer);
    esk.to_bytes()
}

pub fn derive_public(esk: [u8; 32], g_d: [u8; 32]) -> [u8; 32] {
    let p = AffinePoint::from_bytes(g_d).unwrap();
    let q = p.to_niels().multiply_bits(&esk);
    let t = AffinePoint::from(q);
    t.to_bytes()
}

pub fn sapling_ka_agree(esk: [u8; 32], pk_d: [u8; 32]) -> [u8; 32] {
    let p = AffinePoint::from_bytes(pk_d).unwrap();
    let q = p.mul_by_cofactor();
    let v = q.to_niels().multiply_bits(&esk);
    let t = AffinePoint::from(v);
    t.to_bytes()
}

fn kdf_sapling(dhsecret: [u8; 32], epk: [u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    (&mut input[..32]).copy_from_slice(&dhsecret);
    (&mut input[32..]).copy_from_slice(&epk);
    bolos::blake2b_kdf_sapling(&input)
}

fn prf_ock(ovk: [u8; 32], cv: [u8; 32], cmu: [u8; 32], epk: [u8; 32]) -> [u8; 32] {
    let mut ock_input = [0u8; 128];
    ock_input[0..32].copy_from_slice(&ovk); //Todo: compute this from secret key
    ock_input[32..64].copy_from_slice(&cv);
    ock_input[64..96].copy_from_slice(&cmu);
    ock_input[96..128].copy_from_slice(&epk);

    bolos::blake2b_prf_ock(&ock_input)
}
