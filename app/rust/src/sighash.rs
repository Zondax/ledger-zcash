#[cfg(test)]
extern crate hex;

use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{BigEndian, ByteOrder, LittleEndian};

use crate::bolos::*;

const ZCASH_SIGHASH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashSigHash";
const ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashPrevoutHash";
const ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSequencHash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashOutputsHash";
const ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashJSplitsHash";
const ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSSpendsHash";
const ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZcashSOutputHash";

pub fn hash_with_personalization(person: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = Blake2bParams::new()
        .hash_length(32)
        .personal(person)
        .hash(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&h.as_bytes());
    hash
}

pub fn signature_hash(data: &[u8]) -> [u8; 32] {
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZCASH_SIGHASH_PERSONALIZATION_PREFIX);
    LittleEndian::write_u32(&mut personal[12..], 0x76b8_09bb);
    let h = Blake2bParams::new()
        .hash_length(32)
        .personal(&personal)
        .hash(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&h.as_bytes());
    hash
}

#[no_mangle]
pub extern "C" fn sighash(input_ptr: *const &[u8], output_ptr: *mut [u8; 32]) {
    c_zemu_log_stack(b"inside_sighash\x00".as_ref());
    let input = unsafe { *input_ptr };
    let output = unsafe { &mut *output_ptr };
    let hash = blake2b32_with_personalization(
        &[
            90, 99, 97, 115, 104, 83, 105, 103, 72, 97, 115, 104, 187, 9, 184, 118,
        ],
        input,
    );
    output.copy_from_slice(&hash);
}

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;

    #[test]
    fn test_shieldedoutputshash() {
        let str_preimage = "4999c538f7a758bb5b1d28fd218fba1938744bdb77b4a4dfa7a5fae96e8cd49b26907dfc6685c5c99b7141ac626ab4761fd3f41e728e1a28f89db89ffdeca364e4b22d81d9968d0119e4c7a189adf22ad96830a54e40dc73eaba6b2aaf14f7ca942e7370b247c046f8e75ef8e3f8bd821cf577491864e20e6d08fd2e32b555c92c661f19588b72a89599710a88061253ca285b6304b37da2b5294f5cb354a894322848ccbdc7c2545b7da568afac87ffa005c312241c2d57f4b45d6419f0d2e2c5af33ae243785b325cdab95404fc7aed70525cddb41872cfcc214b13232edc78609753dbff930eb0dc156612b9cb434bc4b693392deb87c530435312edcedc6a961133338d786c4a3e103f60110a16b1337129704bf4754ff6ba9fbe65951e610620f71cda8fc877625f2c5bb04cbe1228b1e886f4050afd8fe94e97d2e9e85c6bb748c0042d3249abb1342bb0eebf62058bf3de080d94611a3750915b5dc6c0b3899d41222bace760ee9c8818ded599e34c56d7372af1eb86852f2a732104bdb750739de6c2c6e0f9eb7cb17f1942bfc9f4fd6ebb6b4cdd4da2bca26fac4578e9f543405acc7d86ff59158bd0cba3aef6f4a8472d144d99f8b8d1dedaa9077d4f01d4bb27bbe31d88fbefac3dcd4797563a26b1d61fcd9a464ab21ed550fe6fa09695ba0b2f10eea6468cc6e20a66f826e3d14c5006f0563887f5e1289be1b2004caca8d3f34d6e84bf59c1e04619a7c23a996941d889e4622a9b9b1d59d5e319094318cd405ba27b7e2c084762d31453ec4549a4d97729d033460fcf89d6494f2ffd789e98082ea5ce9534b3acd60fe49e37e4f666931677319ed89f85588741b3128901a93bd78e4be0225a9e2692c77c969ed0176bdf9555948cbd5a332d045de6ba6bf4490adfe7444cd467a09075417fcc0062e49f008c51ad4227439c1b4476ccd8e97862dab7be1e8d399c05ef27c6e22ee273e15786e394c8f1be31682a30147963ac8da8d41d804258426a3f70289b8ad19d8de13be4eebe3bd4c8a6f55d6e0c373d456851879f5fbc282db9e134806bff71e11bc33ab75dd6ca067fb73a043b646a7cf39cab4928386786d2f24141ee120fdc34d6764eafc66880ee0204f53cc1167ed20b43a52dea3ca7cff8ef35cd8e6d7c111a68ef44bcd0c1513ad47ca61c659cc5d325b440f6b9f59aff66879bb6688fd2859362b182f207b3175961f6411a493bffd048e7d0d87d82fe6f990a2b0a25f5aa0111a6e68f37bf6f3ac2d26b84686e569d58d99c1383597fad81193c4c1b16e6a90e2d507cdfe6fbdaa86163e9cf5de3100fbca7e8da047b09079362d7792deb3ca9dc1561b87c82e3cb99eb5837319582216a3226774efa90efb7bfc79f425644e4e98c2d7d8642b9db82aa739bf2d71cc4117227db227cf0a05ad9a95832e23c94f271ca0e4694fac6322282ebac6986b8fdc8ad863084ff10fd11e6a13311fb799c79c641d9da43b33e7ad012e28255398789262275f1175be8462c01491c4d842406d0ec4282c9526174a09878fe8fdde33a29604e5e5e7b2a025d6650b97dbb52befb59b1d30a57433b0a351474444099daa371046613260cf3354cfcdada663ece824ffd7e44393886a86165ddddf2b4c41773554c86995269408b11e6737a4c447586f69173446d8e48bf84cbc000a807899973eb93c5e819aad669413f8387933ad1584aa35e43f4ecd1e2d0407c0b1b89920ffdfdb9bea51ac95b557af71b89f903f5d9848f14fcbeb1837570f544d6359eb23faf38a0822da36ce426c4a2fbeffeb0a8a2e297a9d19ba15024590e3329d9fa9261f9938a4032dd34606c9cf9f3dd33e576f05cd1dd6811c6298757d77d9e810abdb226afcaa4346a6560f8932b3181fd355d5d391976183f8d99388839632d6354f666d09d3e5629ea19737388613d38a34fd0f6e50ee5a0cc9677177f50028c141378187bd2819403fc534f80076e9380cb4964d3b6b45819d3b8e9caf54f051852d671bf8c1ffde2d1510756418cb4810936aa57e6965d6fb656a760b7f19adf96c173488552193b147ee58858033dac7cd0eb204c06490bbdedf5f7571acb2ebe76acef3f2a01ee987486dfe6c3f0a5e234c127258f97a28fb5d164a8176be946b8097d0e317287f33bf9c16f9a545409ce29b1f4273725fc0df02a04ebae178b3414fb0a82d50deb09fcf4e6ee9d180ff4f56ff3bc1d3601fc2dc90d814c3256f4967d3a8d64c83fea339c51f5a8e5801fbb97835581b602465dee04b5922c2761b54245bec0c9eef2db97d22b2b3556cc969fbb13d06509765a52b3fac54b93f421bf08e18d52ddd52cc1c8ca8adfaccab7e5cc2f4573fbbf8239bb0b8aedbf8dad16282da5c9125dba1c059d0df8abf621078f02d6c4bc86d40845ac1d59710c45f07d585eb48b32fc0167ba256e73ca3b9311c62d109497957d8dbe10aa3e866b40c0baa2bc492c19ad1e6372d9622bf163fbffeaeee796a3cd9b6fbbfa4d792f34d7fd6e763cd5859dd26833d21d9bc5452bd19515dff9f4995b35bc0c1f876e6ad11f2452dc9ae85aec01fc56f8cbfda75a7727b75ebbd6bbffb43b63a3b1b671e40feb0db002974a3c3b1a788567231bf6399ff89236981149d423802d2341a3bedb9ddcbac1fe7b6435e1479c72e7089b51bfe2ff345857da9b545e88e3221f3f5f72d1e069c9a85dd2236d390989587be005cda16af4408f3ab06a916eeeb9c9594b70424a4c1d171295b6763b22f4712ba7beff0ff27883afaff26034b895735709cf937bd2231891e70eb2771e9927c97f8764eb48e911d428ec8d861b708e8298acb62155145155ae95f0a1d1501034753146e22d05f586d7f6b4fe12dad9a17f5db70b1db96b8d9a83edadc966c8a5466b61fc998c31f1070d9a5c9a6d268d304fe6b8fd3b4010348611abdcbd49fe4f85b623c7828c71382e1034ea67bc8ae97404b0c50b2a04f559e49950afcb0ef462a2ae024b0f0224dfd73684b88c7fbe92d02b68f759c4752663cd7b97a14943649305521326bde085630864629291bae25ff8822a14c4b666a9259ad0dc42a8290ac7bc7f53a16f379f758e5de750f04fd7cad47701c8597f97888bea6fa0bf2999956fbfd0ee68ec36e4688809ae231eb8bc4369f5fe1573f57e099d9c09901bf39caac48dc11956a8ae905ead86954547c448ae43d315e669c4242da565938f417bf43ce7b2b30b1cd4018388e1a910f0fc41fb0877a5925e466819d375b0a912d4fe843b76ef6f223f0f7c894f38f7ab780dfd75f669c8c06cffa43eb47565a50e3b1fa45ad61ce9a1c4727b7aaa53562f523e73952bbf33d8a4104078ade3eaaa49699a69fdf1c5ac7732146ee5e1d6b6ca9b9180f964cc9d0878ae1373524d7d510e58227df6de9d30d271867640177b0f1856e28d5c8afb095ef6184fed651589022eeaea4c0ce1fa6f085092b04979489172b3ef8194a798df5724d6b05f1ae000013a08d612bca8a8c31443c10346dbf61de8475c0bbec5104b47556af3d514458e2321d146071789d2335934a680614e83562f82dfd405b54a45eb32c165448d4d5d61ca2859585369f53f1a137e9e82b67b8fdaf01bda54a317311896ae10280a032440c420a421e944d1e952b70d5826cd3b08b7db9630fe4fd5f22125de840fcc40b98038af11d55be25432597b4b65b9ec1c7a8bbfd052cbf7e1c1785314934b262d5853754f1f17771cfb7503072655753fa3f54ecc587e9f83b581916092df26e63e18994cb0db91a0bbdc7b6119b32222adf5e61d8d8ae89dae4954b54813bb33f08d562ba513fee1b09c0fcd516055419474dd7fda038a89c84ea7b9468287f0eb0c10c4b132520194d3d8d5351fc10d09c15c8cc101aa1663bbf17b84111f38bb439f07353bdea3596d15e713e1e2e7d3f1c383135b47fa7f81f46df7a902a404699ec912f5656c35b85763e4de583aecaa1dfd5d2677d9c8ffee877f63f40a5ca0d67f6e5541247";
        let mut preimage = [0u8; 2844];
        hex::decode_to_slice(str_preimage, &mut preimage).expect("decode failed");

        let str_hash = "dafece799f638ba7268bf8fe43f02a5112f0bb32a84c4a8c2f508c41ff1c78b5";
        let mut hash = [0u8; 32];
        hex::decode_to_slice(str_hash, &mut hash).expect("decode failed");
        assert_eq!(
            blake2b32_with_personalization(ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION, &preimage),
            hash
        );
    }

    #[test]
    fn test_sighash() {
        let str_sighash = "63d18534de5f2d1c9e169b73f9c783718adbef5c8a7d55b5e7a37affa1dd3ff3";
        let mut sighash = [0u8; 32];
        hex::decode_to_slice(str_sighash, &mut sighash).expect("decode failed");

        let str_preimage = "0400008085202f89d53a633bbecf82fe9e9484d8a0e727c73bb9e68c96e72dec30144f6a84afa136a5f25f01959361ee6eb56a7401210ee268226f6ce764a4f10b7f29e54db37272ab6f7f6c5ad6b56357b5f37e16981723db6c32411753e28c175e15589172194a00000000000000000000000000000000000000000000000000000000000000003fd9edb96dccf5b9aeb71e3db3710e74be4f1dfb19234c1217af26181f494a36dafece799f638ba7268bf8fe43f02a5112f0bb32a84c4a8c2f508c41ff1c78b5481cdd86b3cc4318442117623ceb050001000000";
        let mut preimage = [0u8; 220];
        hex::decode_to_slice(str_preimage, &mut preimage).expect("decode failed");

        assert_eq!(
            blake2b32_with_personalization(
                &[90, 99, 97, 115, 104, 83, 105, 103, 72, 97, 115, 104, 187, 9, 184, 118],
                &preimage,
            ),
            sighash
        );

        assert_eq!(signature_hash(&preimage), sighash);
    }
}
