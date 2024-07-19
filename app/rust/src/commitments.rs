use blake2s_simd::Params as Blake2sParams;
use jubjub::{AffinePoint, ExtendedPoint, Fr};

use crate::bolos::c_zemu_log_stack;
use crate::constants::{
    NOTE_POSITION_BASE, PEDERSEN_RANDOMNESS_BASE, VALUE_COMMITMENT_RANDOM_BASE,
    VALUE_COMMITMENT_VALUE_BASE,
};
use crate::cryptoops::{add_to_point, extended_to_bytes};
use crate::pedersen::*;
use crate::personalization::CRH_NF;
use crate::types::Diversifier;
use crate::utils::{into_fixed_array, shiftsixbits};
use crate::{utils, zip32};

#[inline(never)]
pub fn group_hash_from_diversifier(diversifier_ptr: *const Diversifier, gd_ptr: *mut [u8; 32]) {
    let diversifier = unsafe { &*diversifier_ptr };
    let gd = unsafe { &mut *gd_ptr };
    let gd_tmp = zip32::pkd_group_hash(diversifier);

    gd.copy_from_slice(&gd_tmp);
}

#[inline(never)]
pub fn prepare_and_hash_input_commitment(
    value: u64,
    g_d_ptr: *const [u8; 32],
    pkd_ptr: *const [u8; 32],
    output_ptr: *mut [u8; 32],
) {
    // Dereference pointers safely within an unsafe block
    let gd = unsafe { &*g_d_ptr };
    let pkd = unsafe { &*pkd_ptr };
    let output_msg = unsafe { &mut *output_ptr };

    // Initialize buffers for input hash and prepared message
    let mut input_hash = [0u8; 73];

    // Convert the value to bytes and reverse the bits
    let vbytes = utils::write_u64_tobytes(value);
    input_hash[0..8].copy_from_slice(&vbytes);

    // Reverse bits for g_d and pk_d and place them into the input hash
    utils::reverse_bits(gd, &mut input_hash[8..40]);
    utils::reverse_bits(pkd, &mut input_hash[40..72]);

    // Perform a bit shift operation on the entire array
    shiftsixbits(&mut input_hash);

    // Compute the Pedersen hash from the prepared input hash
    let h = pedersen_hash_pointbytes(&input_hash, 582);
    output_msg.copy_from_slice(&h);
}

////////////////////////////////////////////////
////////////////////////////////////////////////

#[inline(never)]
pub fn mixed_pedersen(e: &ExtendedPoint, scalar: Fr) -> [u8; 32] {
    let mut p = NOTE_POSITION_BASE * scalar;
    add_to_point(&mut p, e);
    extended_to_bytes(&p)
}

#[inline(never)]
pub fn prf_nf(nk: &[u8; 32], rho: &[u8; 32]) -> [u8; 32] {
    // BLAKE2s Personalization for PRF^nf = BLAKE2s(nk | rho)

    // FIXME: not using bolos blake!?
    let h = Blake2sParams::new()
        .hash_length(32)
        .personal(CRH_NF)
        .to_state()
        .update(nk)
        .update(rho)
        .finalize();

    let x: [u8; 32] = *h.as_array();
    x
}

//////////////////////////////
//////////////////////////////

#[inline(never)]
pub fn value_commitment_step1(value: u64) -> ExtendedPoint {
    let scalar = into_fixed_array(value);
    VALUE_COMMITMENT_VALUE_BASE.multiply_bits(&scalar)
}

#[inline(never)]
pub fn value_commitment_step2(rcm: &[u8; 32]) -> ExtendedPoint {
    VALUE_COMMITMENT_RANDOM_BASE.multiply_bits(rcm)
}

//////////////////////////////
//////////////////////////////

#[cfg(test)]
mod tests {
    use std::string::{String, ToString};
    use std::vec::Vec;
    use crate::bolos::seed::with_device_seed_context;
    use crate::commitments_extern::{compute_note_commitment, compute_nullifier};
    use crate::types::{diversifier_zero, NskBytes};
    use crate::utils::into_fixed_array;
    use crate::zip32_extern::zip32_nsk;

    use serde::Deserialize;
    use serde_json::Result;
    use crate::sapling::sapling_nsk_to_nk;
    use super::*;

    #[derive(Deserialize, Debug)]
    struct TestCase {
        sk: String,
        ask: String,
        nsk: String,
        ovk: String,
        ak: String,
        nk: String,
        ivk: String,
        default_d: String,
        default_pk_d: String,
        note_v: u64,
        note_r: String,
        note_cmu: String,
        note_pos: u64,
        note_nf: String,
        rho: String,
    }

    #[inline(never)]
    pub fn note_commitment(
        v: u64,
        g_d: &[u8; 32],
        pk_d: &[u8; 32],
        rcm: &[u8; 32],
    ) -> ExtendedPoint {
        c_zemu_log_stack(b"notecommit\x00".as_ref());
        let mut input_hash = [0u8; 73];

        // Convert the value to bytes and reverse the bits as per protocol
        let vbytes = utils::write_u64_tobytes(v);
        input_hash[0..8].copy_from_slice(&vbytes);

        // Reverse bits for g_d and pk_d and place them into the input hash
        utils::reverse_bits(g_d, &mut input_hash[8..40]);
        utils::reverse_bits(pk_d, &mut input_hash[40..72]);

        // Perform a bit shift operation on the entire array
        shiftsixbits(&mut input_hash);

        // Compute the Pedersen hash to point
        let mut p = pedersen_hash_to_point(&input_hash, 582);

        // Multiply the randomness base by rcm and add to the point
        let s = PEDERSEN_RANDOMNESS_BASE.multiply_bits(rcm);
        p += s;

        p
    }

    #[inline(never)]
    pub fn value_commitment(value: u64, rcm: &[u8; 32]) -> [u8; 32] {
        let scalar = into_fixed_array(value);
        let mut x = VALUE_COMMITMENT_VALUE_BASE.multiply_bits(&scalar);
        x += VALUE_COMMITMENT_RANDOM_BASE.multiply_bits(rcm);
        extended_to_bytes(&x)
    }

    #[test]
    fn test_ncm_c() {
        let v = 100000;
        let mut gd = [0u8; 32];
        let div_ptr = diversifier_zero();
        let pkd = [0u8; 32];
        let rcm = [0u8; 32];
        let output = [0u8; 32];

        let div = &div_ptr;

        group_hash_from_diversifier(div, &mut gd);

        prepare_and_hash_input_commitment(
            v,
            gd.as_ptr() as *const [u8; 32],
            pkd.as_ptr() as *const [u8; 32],
            output.as_ptr() as *mut [u8; 32],
        );

        compute_note_commitment(
            rcm.as_ptr() as *const [u8; 32],
            v,
            div.as_ptr() as *const Diversifier,
            pkd.as_ptr() as *const [u8; 32],
            output.as_ptr() as *mut [u8; 32],
        );

        assert_eq!(
            output,
            [
                51, 107, 65, 49, 174, 10, 181, 105, 255, 123, 174, 149, 217, 191, 95, 76, 7, 90,
                151, 132, 85, 143, 180, 30, 26, 35, 160, 160, 197, 140, 21, 95
            ]
        );
    }

    #[test]
    fn test_compute_note_commitment() {
        // Test cases taken from
        // https://github.com/zcash/zcash-test-vectors/blob/master/test-vectors/zcash/sapling_key_components.json
        let data = r#"
    [
        ["From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_key_components.py"],
        ["sk, ask, nsk, ovk, ak, nk, ivk, default_d, default_pk_d, note_v, note_r, note_cmu, note_pos, note_nf, rho"],
        ["0000000000000000000000000000000000000000000000000000000000000000", "8548a14a473ea547aa2378402044f818cf1911cf5dd2054f678345f00d0e8806", "30114ea0dd0bb61cf0eaeab6ec3331f581b0425e27338501262d7eac745e6e05", "98d16913d99b04177caba44f6e4d224e03b5ac031d7ce45e865138e1b996d63b", "f344ec380fe1273e3098c2588c5d3a791fd7ba958032760777fd0efa8ef11620", "f7cf9e77f2e58683383c1519ac7b062d30040e27a725fb88fb19a978bd3fd6ba", "b70b7cd0ed03cbdfd7ada9502ee245b13e569d54a5719d2daa0f5f1451479204", "f19d9b797e39f337445839", "db4cd2b0aac4f7eb8ca131f16567c445a9555126d3c29f14e3d776e841ae7415", 0, "39176dac39ace4980ecc8d778e89860255ec3615060000000000000000000000", "cb3cf9153270d57eb914c6c2bcc01850c9fed44fce0806278f083ef2dd076439", 0, "44fad6564ffdec9fa19c43a28f861d5ebf602346007de76267d9752747ab4063", "a505cb7702d417ff6ed2cb33f1bca2e34a2dbb4be183cbed09513f9188afaeaa"],
        ["0101010101010101010101010101010101010101010101010101010101010101", "c9435629bf8bffe55e7335ec077718ba60ba28d7ac3794b74f512c31af0a5304", "11acc2ead07b5f008c1f0f090cc8ddf335236ff4b253c6495695e9d639dacd08", "3b946210ce6d1b1692d7392ac84a8bc8f03b72723c7d36721b809a79c9d6e45b", "82ff5effc527ae84020bf2d35201c10219131947ff4b96f881a45f2e8ae30518", "c4534d848bb918cf4a7f8b98740ab3ccee586795ff4df64547a8888a6c7415d2", "c518384466b26988b5109067418d192d9d6bd0d9232205d77418c240fc68a406", "aef180f6e34e354b888f81", "a6b13ea336ddb7a67bb09a0e68e9d3cfb39210831ea3a296ba09a922060fd38b", 12227227834928555328, "478ba0ee6e1a75b600036f26f18b7015ab556beddf8b960238869f89dd804e06", "b57893500bfb85df2e8b01ac452f89e10e266bcfa31c31b29a53ae72cad46950", 763714296, "679eb0c3a757e2ae83cdb42a1ab259d78388315419adc71d2e3763174c2e9d93", "1b35ccdd7ff6e97f135b4cb36f9bf9a7815b5f68fe2526977227e8e00e72c7a3"],
        ["0202020202020202020202020202020202020202020202020202020202020202", "ee1c3d7efe0a78063d6af3d9d81212af47b7c1b761f85ccb066fc11a6a421703", "1d3b713755d74875e8ea38fd166e76c62a4250216e6bbfe48a5e2eabad117f0b", "8bf4390e28ddc95b8302c381d5810b84ba8e6096e5a76822774fd49f491e8f49", "ab83574eb5de859a0ab8629dec34c7bee8c3fc74dfa0b19a3a7468d15dca64c6", "95d58053e0592e4a169cc0b7928aaac3de24ef1531aa9eb6f4ab93914da8a06e", "471c24a3dc8730e75036c0a95f3e2f7dd1be6fb93ad29592203def3041954505", "7599f0bf9b57cd2dc299b6", "66141739514b28f05def8a18eeee5eed4d44c6225c3c65d88dd9907708012f5a", 6007711596147559040, "147cf2b51b4c7c63cb77b99e8b783e5b5111db0a7ca04d6c014a1d7da83bae0a", "db85a70a98437f73167fc332d5b7b7408296661770b101b0aa87839f4e55f151", 1527428592, "e98f6a8f34ff498059b3c731b91f451108c4954d919484361cf9b48f59ae1d14", "2ab72bfd45f0a404bb7a9f7b70282af237deb4b8a0a224d14c8ff9c1ae714ba2"],
        ["0303030303030303030303030303030303030303030303030303030303030303", "00c3a1e1ca8f4e0480ee1ee90ca7517879d3fc5c815c0903e5eebc94bb809503", "e66285a5e9b65e157ad2fcd543dad98c67a58abdf287e05506bd1c2e59b0720b", "147678e0553b97829347647c5bc7dab4cc2202b54ec29fd31a3de6be0825fc5e", "3c9cde7e5d0d38a8610faadbcf4c343f5d3cfa3155a5b94661a6753e96e884ea", "b77d36f508941dbd61cfd0f159ee05cfaa78a26c9492903806d83b598d3c1c2a", "636aa964bfc23ce4b1fcf7dfc99179ddc406ff55400c9295acfc14f031c72600", "1b81614f1dadea0f8d0a58", "25eb55fccf761fc64e85a588efe6ead7832fb1f0f7a83165895bdff942925f5c", 18234939431076114368, "34a4b2a9144ff5ea54efee87cf901b5bed5e35d21fbbd788d5bd9d833e112804", "e08ce482b3a8fb3b35ccdbe34337bd105d8839212e0d1644b9d55caa60d19b6c", 2291142888, "5547aa12ff80a6b3304e3b058656472abd2c8183b59d0737b93cee758bec47a1", "929bf1cdc95b9e13dcc034a297438342ea630e6983bb62e53bdbff994cf420a1"],
        ["0404040404040404040404040404040404040404040404040404040404040404", "8236d19d3205d85543a06811343f827b6563770a49aa4d0ca0081805d4c8ea0d", "7ec1ef0bed82718272f0f44f017c484174513d661dd168af02d2092a1d8a0507", "1b6e75ece3ace8dba6a5410d9ad4755668e4b39585d635ec1da7c8dcfd5fc4ed", "55e88389bb7e41de130cfa51a8715fde01ff9c6876647f0175ad34f058dde01a", "725d4ad6a15021cd1c48c5ee19de6c1e768a2cc0a9a730a01bb21c95e3d9e43c", "67fa2bf7c67d4658243c317c0cb41fd32064dfd3709fe0dcb724f14bb01a1d04", "fcfb68a40d4bc6a04b09c4", "8b2a337f03622c24ff381d4c546f6977f90522e92fde44c9d1bb099714b9db2b", 12015423192295118080, "e557851355747c09ac59013cbde85980964ec1844d9c6967ca0c029c8457bb04", "bdc854bf3e7b00821f3b8b85238ccf1e6715bfe70b632d044b26fb2bc71b7f36", 3054857184, "8a9abda3d4ef85caf22bfaf2c48f62382a73a1624eb8eb2bd00d270301bf3d13", "7b130d971687d39e953001685a8e68a4512619ff6b4d2a7a11dc59ac1356519c"],
        ["0505050505050505050505050505050505050505050505050505050505050505", "eae6884d764a054061a8f1c0076c624dcb738789f7ad1e7408e31f24dfc82607", "fbe610f42a41749f9b6e6e4a54b5a32ebfe8f43800881ba6cd13ed0b05294601", "c6bc1f39f0d786314cb20bf9ab228540913555f970696b6d7c77bb332328372a", "e682765914e3864c339e5782b855c0fdf40e0dfcedb9e7b47bc94b90b3a4c988", "82256b95623c67024b4424d91400a370e7ac8e4d15482a3759e00d219749daee", "ea3f1d80e4307ca73b9f37801f91fba810cc41d279fc29f564235654a2178e03", "eb519882ad1e5cc654cd59", "6b27daccb5a8207f532d10ca238f9786648a11b5966e51a2f7d89e15d29b8fdf", 5795906953514121792, "68f06104606b0c5449845ff4c65f73e90f45ef5a43c9d74cb2c85cf56c94c002", "e8267d30ac11c100bc7a0fdf91f71d74c5bcf2e1ef95669044730169de1a5b4c", 3818571480, "332ad99eb9e977eb627a122dbfb2f25fe588e597753ec5580ff2be20b6c9a7e1", "9e7171acc6302269c24f55404edc04c61c24963d0b0c8f41754887f4ef756004"],
        ["0606060606060606060606060606060606060606060606060606060606060606", "e8f816b4bc08a7e566750cc28afe82a4cea9c2bef244fa4b13c4739b28074c0d", "32615b137f2801ed446e48781ab0634572e18cfb0693721b8803c05b8227d107", "f62c05e848a873ef885e12b08c5e7ca2f32424bacc754cb69750444d355f5106", "ff27db0751945d3ee4be9cf15c2ea211b24b164d5f2d7ddff5e4a0708f10b95e", "943885959d4ef8a9cfca07c457f09ec74b96f993d8e0fa32b19c03e3b07a420f", "b5c5894943956933c0e5c12d311fc12cba58354b5c389edc03da55084f74c205", "bebb0fb46b8aaff89040f6", "d11da01f0b43bdd5288d32385b8771d223493c69802544043f77cf1d71c1cb8c", 18023134788442677120, "49f90b47fd52fee7c1c81f0dcb5b74c3fb9b3e03976f8b7524eabad008892107", "572ba20525b0ac4d6dc01ac2ea1090b6e0f2f4bf4ec4a0db5bbccb5b783a1e55", 287318480, "fc74cd0e4be04957b196cf8734ae992396af4cfa8fecbb86f961e6b407d51e11", "18b7bc72cd3a3fa8c90e1146dd9f6bdd1af74536319f4ac854e0000f3d9972cc"],
        ["0707070707070707070707070707070707070707070707070707070707070707", "74b44a37f15023c060427e1daea3f64312dd8feb7b2cedf0dd5544493f872c06", "075c35db8b1b25754223ecee34ab730dddd1f14a6a54f4c6f468453c3c6ed60b", "e9e0dc1ed311daed64bd74da5d94fe88a6ea414b7312de3d2a78f64632bbe373", "283f9aafa9bcb3e6ce17e63212634cb3ee550c476b676bd356a6df8adf51d25e", "dc4c67b10d4b0a218dc6e1487066740a409317866c32e664b50e397aa80389d4", "8716c82880e13683e1bb059dd06c80c90134a96d5afca8aac2bbf68bb05f8402", "ad6e2e185a3100e3a6a8b3", "32cb2806b882f1368b0d4a898f72c4c8f728132cc12456946e7f4cb0fb058da9", 11803618549661680832, "5165aff22dd4ed56b4d81d1f171cc3d6432fed1bebf20a7beab12db142f94a0c", "ab7fc566873ccde671f59827678560a006f82bb7adcd75223fa85936f78c2b23", 1051032776, "d2e887bd854a802bce857053020f5d3e7c8ae5267c5b6583b3d212cc8bb69890", "1e36dfdbaa6dba5926a3f2f3a8983ec1753035c09c517256bd855ac7d952416e"],
        ["0808080808080808080808080808080808080808080808080808080808080808", "039dd93df311ff8fbab3fe230219cd42ac879484f30b903a3c1e67ccca5a7b0d", "049fa14f486c75b9fad7e3b673a443dd074eaa96edcb2a53eaaabdaf70ffbb08", "147dd11d77eba1b1636fd6190c62b9a5d0481bee7e917fab02e21858063ab504", "364048eedbe8ca205eb7e7ba0a9012166c7c7bd9eb228e08481448c488aa21d2", "ed60af1ce7df38070d3851432a96480db0b417c3682a1d68e3e89334235c0bdf", "99c9b4b84f4b4e350f787d1cf7051d50ecc34b1a5b20d2d2139b4af1f160e001", "21c90e1c658b3efe86af58", "9e64174b4ab981405c323b5e12475945a46d4fedf8060828041cd20e62fd2cef", 5584102310880684544, "8c3e56449dc86354d33b025ef2793460bcb169f3324e4a6b64baa60832315704", "7b48a8375d3ebd56bc649bb5b5242336c2a05a0803239b5b88fd92078fea4d04", 1814747072, "a82f1750cc5b2bee649a365c0420ed87075b8871fda4a7f5840d6bbeb17cd620", "1d0f5094ededc913c173a70e72e5a74f210e7f65d9e79dce91f3aab4935c32a5"],
        ["0909090909090909090909090909090909090909090909090909090909090909", "ebbb40a980ba3b8860948d011e1bfb4affe16c652e90e98258302f4464c91e0c", "68431b199104215200b95ee5cb71bf8b883a3e95b7989cad197063141ebbfd00", "573467a7b30ead6ccc504744ca9e1a281a0d1a08738b06a0684feacd1e9d126d", "71c3523eeca35311fbd5d7e7d70b709d6c35a24f262b34bf64059bf2c02e0ba8", "624400103b6569b7358fe80f6f6cad4325defda9d9499c2b8f886a6269a2aa52", "db95ea8bd9f93d41b5ab2bebc91a38edd527083e2a6ef9f3c29702d5ff89ed00", "233c4ab886a55e3ba374c0", "b68e9ee0c0678d7b3036931c831a25255f7ee487385a30316e15f6482b874fda", 17811330145809239872, "6ebbed743619a256f9ad2e85880cfaa9098a5fdb1629990d9a7d3bb93fc90003", "d376a7bee8ce67f4efde56aa77cf64419b0e550abbcb8e2bcbda8b63e41deb37", 2578461368, "653674873b3c670c58858473e7fe721972fb96e215b87377a17ca3710d93c9e9", "f2eee5d57609267b0d5d3dfef401f32657cf0c3e1b83b940c9547a9cc4c52320"]
    ]
    "#;

        let json_data: Vec<Vec<serde_json::Value>> = serde_json::from_str(data).unwrap();

        let mut test_cases: Vec<TestCase> = Vec::new();

        for case in json_data.iter().skip(2) {
            let test_case = TestCase {
                sk: case[0].as_str().unwrap().to_string(),
                ask: case[1].as_str().unwrap().to_string(),
                nsk: case[2].as_str().unwrap().to_string(),
                ovk: case[3].as_str().unwrap().to_string(),
                ak: case[4].as_str().unwrap().to_string(),
                nk: case[5].as_str().unwrap().to_string(),
                ivk: case[6].as_str().unwrap().to_string(),
                default_d: case[7].as_str().unwrap().to_string(),
                default_pk_d: case[8].as_str().unwrap().to_string(),
                note_v: case[9].as_u64().unwrap(),
                note_r: case[10].as_str().unwrap().to_string(),
                note_cmu: case[11].as_str().unwrap().to_string(),
                note_pos: case[12].as_u64().unwrap(),
                note_nf: case[13].as_str().unwrap().to_string(),
                rho: case[14].as_str().unwrap().to_string(),
            };
            test_cases.push(test_case);
        }

        for test_case in test_cases {
            println!("{:?}", test_case);

            let computed_note_commitment = [0u8; 32];
            let expected_note_commitment_vec = hex::decode(test_case.note_cmu).unwrap();
            let mut expected_note_commitment = [0u8; 32];
            expected_note_commitment.copy_from_slice(&expected_note_commitment_vec);

            compute_note_commitment(
                hex::decode(test_case.note_r).unwrap().as_ptr() as *const [u8; 32],
                test_case.note_v,
                hex::decode(test_case.default_d).unwrap().as_ptr() as *const Diversifier,
                hex::decode(test_case.default_pk_d).unwrap().as_ptr() as *const [u8; 32],
                computed_note_commitment.as_ptr() as *mut [u8; 32],
            );

            println!("computed_note_commitment {:?}", computed_note_commitment);
            println!("expected_note_commitment {:?}", expected_note_commitment);

            assert_eq!(
                computed_note_commitment,
                expected_note_commitment
            );



            let expected_nk_vec = hex::decode(test_case.nk).unwrap();
            let mut expected_nk = [0u8; 32];
            expected_nk.copy_from_slice(&expected_nk_vec);

            let nsk:NskBytes = hex::decode(test_case.nsk.clone()).unwrap().as_slice().try_into().unwrap();
            let computed_nk = sapling_nsk_to_nk(&nsk);

            assert_eq!(
                computed_nk,
                expected_nk
            );

            let expected_rho_vec = hex::decode(test_case.rho).unwrap();
            let mut expected_rho = [0u8; 32];
            expected_rho.copy_from_slice(&expected_rho_vec);

            let scalar = Fr::from(test_case.note_pos);
            let e = cryptoops::bytes_to_extended(computed_note_commitment_fullpoint);

            let computed_rho = mixed_pedersen(&e, scalar);

            assert_eq!(
                computed_rho,
                expected_rho
            );

            let computed_nullifier = [0u8; 32];
            let expected_nullifier_vec = hex::decode(test_case.note_nf).unwrap();
            let mut expected_nullifier = [0u8; 32];
            expected_nullifier.copy_from_slice(&expected_nullifier_vec);

            compute_nullifier(
                expected_note_commitment.as_ptr() as *const [u8; 32],
                test_case.note_pos,
                hex::decode(test_case.nsk).unwrap().as_ptr() as *const [u8; 32],
                computed_nullifier.as_ptr() as *mut [u8; 32]
            );

            println!("computed_nullifier {:?}", computed_nullifier);
            println!("expected_nullifier {:?}", expected_nullifier);

            assert_eq!(
                computed_nullifier,
                expected_nullifier
            );
        }
    }

    #[test]
    fn test_valuecommit() {
        let rcm: [u8; 32] = [
            251, 95, 86, 230, 162, 167, 192, 202, 152, 240, 81, 12, 55, 67, 211, 154, 62, 218, 51,
            222, 254, 165, 64, 86, 12, 133, 142, 230, 82, 160, 204, 2,
        ];

        let value: u64 = 1000000;

        let cvtest = [
            239, 131, 3, 60, 201, 185, 181, 197, 195, 143, 58, 116, 0, 164, 87, 230, 88, 49, 234,
            15, 238, 183, 46, 114, 63, 13, 100, 104, 194, 53, 240, 16,
        ];

        let cv = value_commitment(value, &rcm);
        assert_eq!(cvtest, cv);
    }

    #[test]
    fn test_nf() {
        let pos: u32 = 2578461368;
        let pk_d = [
            0x62, 0xef, 0xd5, 0x43, 0x93, 0xb3, 0x20, 0x09, 0xad, 0x95, 0x33, 0xc0, 0xd9, 0x97,
            0x5f, 0xef, 0xce, 0xab, 0x46, 0xd7, 0x20, 0x92, 0xac, 0x3b, 0x56, 0xd1, 0xf3, 0xb7,
            0x3c, 0x8b, 0xf0, 0x27,
        ];

        let g_d: [u8; 32] = [
            0x88, 0x59, 0xed, 0x93, 0x71, 0xcd, 0x59, 0x8a, 0xf4, 0x72, 0x15, 0xc2, 0x70, 0xa2,
            0x59, 0x95, 0xa3, 0xdd, 0xe4, 0x57, 0x88, 0xca, 0xb9, 0xd2, 0x88, 0xca, 0x62, 0xbf,
            0x6e, 0x60, 0xc0, 0x17,
        ];

        let value: u64 = 17811330145809239872;
        let rcm: [u8; 32] = [
            0x6e, 0xbb, 0xed, 0x74, 0x36, 0x19, 0xa2, 0x56, 0xf9, 0xad, 0x2e, 0x85, 0x88, 0x0c,
            0xfa, 0xa9, 0x09, 0x8a, 0x5f, 0xdb, 0x16, 0x29, 0x99, 0x0d, 0x9a, 0x7d, 0x3b, 0xb9,
            0x3f, 0xc9, 0x00, 0x03,
        ];

        let nk = [
            0x62, 0x44, 0x00, 0x10, 0x3b, 0x65, 0x69, 0xb7, 0x35, 0x8f, 0xe8, 0x0f, 0x6f, 0x6c,
            0xad, 0x43, 0x25, 0xde, 0xfd, 0xa9, 0xd9, 0x49, 0x9c, 0x2b, 0x8f, 0x88, 0x6a, 0x62,
            0x69, 0xa2, 0xaa, 0x52,
        ];

        let h = note_commitment(value, &g_d, &pk_d, &rcm);

        let mp = mixed_pedersen(&h, Fr::from_bytes(&into_fixed_array(pos)).unwrap());

        let nf = prf_nf(&nk, &mp);

        let nftest: [u8; 32] = [
            0x4a, 0xb5, 0x57, 0x93, 0x33, 0x81, 0xd9, 0xb0, 0xa2, 0x6a, 0x10, 0xc9, 0x66, 0xdb,
            0x62, 0x4a, 0x18, 0xc5, 0xf4, 0xa5, 0xe5, 0x0c, 0x93, 0x8f, 0x2f, 0x24, 0x11, 0x19,
            0x88, 0x5e, 0x39, 0xb1,
        ];
        assert_eq!(nf, nftest);
    }

    #[test]
    fn test_get_nf() {
        let seed: [u8; 32] = [
            176, 142, 61, 152, 218, 67, 28, 239, 69, 102, 161, 60, 27, 179, 72, 185, 130, 247, 216,
            231, 67, 180, 59, 182, 37, 87, 186, 81, 153, 75, 18, 87,
        ];

        with_device_seed_context(seed, || {
            let account = 0;
            let pos: u64 = 2578461368;
            let cm: [u8; 32] = [
                0x21, 0xc9, 0x46, 0x98, 0xca, 0x32, 0x4b, 0x4c, 0xba, 0xce, 0x29, 0x1d, 0x27, 0xab,
                0xb6, 0x8a, 0xa, 0xaf, 0x27, 0x37, 0xdc, 0x45, 0x56, 0x54, 0x1c, 0x7f, 0xcd, 0xe8,
                0xce, 0x11, 0xdd, 0xe8,
            ];

            let mut nsk: NskBytes = [0u8; 32];
            let mut nf = [0u8; 32];

            zip32_nsk(account, &mut nsk);
            compute_nullifier(&cm, pos, &nsk, &mut nf);

            assert_eq!(
                hex::encode(nf),
                "ce0df155d652565ccab59ae392a569c4f2283df4dc8a26bfd48e178bfceed436"
            );
        })
    }

    #[test]
    fn test_mixed_pedersen() {
        let v = 312354353u32;
        let scalar = into_fixed_array(v);
        let mp = mixed_pedersen(&ExtendedPoint::identity(), Fr::from_bytes(&scalar).unwrap());
        assert_eq!(
            mp,
            [
                229, 21, 27, 49, 9, 57, 15, 12, 130, 17, 72, 150, 250, 83, 173, 10, 32, 188, 132,
                68, 124, 203, 153, 66, 197, 109, 156, 189, 116, 231, 80, 75
            ]
        );
    }

    #[test]
    fn test_note_commitment_null() {
        let rcm: [u8; 32] = [
            0x6e, 0xbb, 0xed, 0x74, 0x36, 0x19, 0xa2, 0x56, 0xf9, 0xad, 0x2e, 0x85, 0x88, 0x0c,
            0xfa, 0xa9, 0x09, 0x8a, 0x5f, 0xdb, 0x16, 0x29, 0x99, 0x0d, 0x9a, 0x7d, 0x3b, 0xb9,
            0x3f, 0xc9, 0x00, 0x03,
        ];
        let g_d = [0u8; 32];
        let pk_d = [0u8; 32];
        let value: u64 = 0;

        let cmnul = [
            0x0d, 0x7d, 0xfe, 0x59, 0x28, 0xee, 0x5d, 0x23, 0xbc, 0x93, 0x85, 0x9b, 0xb9, 0x93,
            0x5a, 0x23, 0xe7, 0xa9, 0x9d, 0xda, 0xf9, 0xd0, 0x97, 0x3d, 0x1d, 0xd1, 0x9e, 0xff,
            0xed, 0x3f, 0x29, 0x13,
        ];

        let t = note_commitment(value, &g_d, &pk_d, &rcm);
        let b = AffinePoint::from(&t).get_u().to_bytes();
        assert_eq!(b, cmnul);
    }

    #[test]
    fn test_note_commitment() {
        let rcm: [u8; 32] = [
            0x6e, 0xbb, 0xed, 0x74, 0x36, 0x19, 0xa2, 0x56, 0xf9, 0xad, 0x2e, 0x85, 0x88, 0x0c,
            0xfa, 0xa9, 0x09, 0x8a, 0x5f, 0xdb, 0x16, 0x29, 0x99, 0x0d, 0x9a, 0x7d, 0x3b, 0xb9,
            0x3f, 0xc9, 0x00, 0x03,
        ];
        let g_d: [u8; 32] = [
            0x88, 0x59, 0xed, 0x93, 0x71, 0xcd, 0x59, 0x8a, 0xf4, 0x72, 0x15, 0xc2, 0x70, 0xa2,
            0x59, 0x95, 0xa3, 0xdd, 0xe4, 0x57, 0x88, 0xca, 0xb9, 0xd2, 0x88, 0xca, 0x62, 0xbf,
            0x6e, 0x60, 0xc0, 0x17,
        ];

        let pk_d: [u8; 32] = [
            0x62, 0xef, 0xd5, 0x43, 0x93, 0xb3, 0x20, 0x09, 0xad, 0x95, 0x33, 0xc0, 0xd9, 0x97,
            0x5f, 0xef, 0xce, 0xab, 0x46, 0xd7, 0x20, 0x92, 0xac, 0x3b, 0x56, 0xd1, 0xf3, 0xb7,
            0x3c, 0x8b, 0xf0, 0x27,
        ];

        let value: u64 = 1000000000;

        let cmnul = [
            0xef, 0xa5, 0xc8, 0x8e, 0xd5, 0x02, 0x9e, 0xae, 0xb2, 0x75, 0x83, 0x55, 0xec, 0xdc,
            0x35, 0x1a, 0x9a, 0x45, 0x01, 0x57, 0x77, 0x83, 0x58, 0x37, 0x3e, 0xaa, 0x19, 0x2a,
            0x5d, 0x7f, 0x9d, 0x68,
        ];

        let t = note_commitment(value, &g_d, &pk_d, &rcm);
        let b = AffinePoint::from(&t).get_u().to_bytes();
        assert_eq!(b, cmnul);
    }
}
