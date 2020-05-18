/*use std::path::PathBuf;
use std::fs;
//use crate::transaction::*;
extern crate rslib;
use rslib::UnshieldedTx;

const RAW_TX: &str = "0200000001c764160b432153d0445828c1cf44d3ead16b76325a0993499bd698b58dc1ab03000000006a473044022019a48ae0df27e3a1e75d64b8ac4ff41c703b54a87117aee1f101f278846bb5c702201587cd1c8980b0f7a34eb7c371b107f9833c128aaddba45574854b2e4e7f11ee012103421c4721b5c27c731b38cb8d0e573fd000a7be5538ade8fe23386f81619ae541ffffffff01d0bf4200000000001976a914d22b1794fe2c2c313abfd06d0c13718bba38382988ac00000000";
const RAW_TX2: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
// coinbase transaction: No input - 1 output
const RAW_TX3: &str = "0100000001416e9b4555180aaa0c417067a46607bc58c96f0131b2f41f7d0fb665eab03a7e000000001976a91499b1ebcfc11a13df5161aba8160460fe1601d54188acffffffff01204e0000000000001976a914e81d742e2c3c7acd4c29de090fc2c4d4120b2bf888ac0000000001000000";
// 1 input - 2 output
const RAW_TX4: &str = "010000000107578c9aff7cfd240c36fa1400ee130d540f4c3397d24e8bea50a7f061116a87010000006a473044022011aecead8f48e3b342856a8da2f30c4e05bec5dc147a5bc7b382d01bf68ae5c302204126fd77522ae311a88688bce967532456b08c94322ba182a18fb7786e696c610121027e563beec6765850071067e4fcc7a46d00cbb0d675ef8df1b8d15aaeef91a21fffffffff021cbb0100000000001976a91461aac8b58ac880a45fb06eeedfcf3017679778a988ac32432400000000001976a9144fc16e1766808c0ab090be4376cea9d3a0bbe12988ac00000000";

#[test]
#[link(name = "rslib" , kind = "static")]
fn simple_1input_2output() {
    let bytes = hex::decode(RAW_TX4).unwrap();
    let transaction = UnshieldedTx::from_bytes(&bytes).unwrap();

    // We know the number of inputs and outputs so:
    assert_eq!(transaction.ilen, 1);
    assert_eq!(transaction.olen, 2);

    let input_path = {
        let mut r = PathBuf::new();
        r.push(env!("CARGO_MANIFEST_DIR"));
        r.push("tests");
        r.push("1i2o_simple");
        r.set_extension("json");
        r
    };
    let str = fs::read_to_string(input_path).expect("Error opening json file");
    let json = serde_json::from_str(&str).unwrap();

    // for now we just verify if the locktime and amount are valids
    let tx_output_values = transaction.get_outputs().iter()
        .map(|out| out.vout).collect::<Vec<u32>>();

    let json_output_values = json["outputs"].iter().map(|v| v["value"]).collect::<Vec<u32>>();
    assert_eq!(&tx_output_values, json_output_values);
}*/
