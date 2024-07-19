use env_logger::Env;
use ledger_zcash::builder::Builder as ZcashBuilder;
use ledger_zcash_builder::{
    data::{OutputBuilderInfo, SpendBuilderInfo},
    txbuilder::Builder,
};
use zcash_primitives::consensus::TestNetwork;
use zcashtool::*;

mod types;

const SPEND_PATH: &str = "tests/params/sapling-spend.params";
const OUTPUT_PATH: &str = "tests/params/sapling-output.params";
const TX_VERSION: usize = 5;

// Values for test_data[0]
const SAPLING_SPEND_1: &str = r#"{
        "proofkey": "0bbb1d4bfe70a4f4fc762e2f980ab7c600a060c28410ccd03972931fe310f2a53022d5db92c9dc180dd12e2d74162396f13513016719e38d2616f7730d09a909",
        "rcv": "a8c2559a94a04143c7b0496ed9fff78ce6ef36dfa100890bc22a26f88e304206",
        "alpha": "12753fff4e914813542a267d89fd7d427d668da1a249f5d744f7416137a2e903",
        "address": "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
        "value": 50000,
        "witness": "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
        "rseed": "0000000000000000000000000000000000000000000000000000000000000000"
      }"#;

const SAPLING_SPEND_2: &str = r#"{
        "proofkey": "0bbb1d4bfe70a4f4fc762e2f980ab7c600a060c28410ccd03972931fe310f2a53022d5db92c9dc180dd12e2d74162396f13513016719e38d2616f7730d09a909",
        "rcv": "102d58b50a3f5994d56fb39bdb32d9b9b15320186b28e64b925ffddbbbe53803",
        "alpha": "7f488788e73b5dc70749b5e851925363ddcb598766fd7b5234e1bb184ced4c00",
        "address": "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
        "value": 50000,
        "witness": "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
        "rseed": "0000000000000000000000000000000000000000000000000000000000000000"
      }"#;

const SAPLING_OUTPUT_1: &str = r#"{
        "rcv": "dbcf9ed1d81bf646903ff4e73abd8d560a9daa5986e2f1b933041bbd55e7ca00",
        "rseed": "9d290fbdd67a766e5e2ad054d91b76325231073edbdb703fe12920a3c9fa4266",
        "ovk": null,
        "address": "15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc",
        "value": 55000,
        "memo": "0000",
        "hash_seed": "1eb697b7dc720c0668768e7d62df99ff1e1baf036dd1c8558492cb3241c48a5f"
      }"#;

const SAPLING_OUTPUT_2: &str = r#"{
    "rcv": "5a585948dc520f254321bc7e8be10e809ca2490758c2a601a32f170a2d132009",
    "rseed": "924ac4fd2b822c45bff8b2ef95c64508bf9c2e0c33e6d72bd5e97d3baa4f6b3c",
    "ovk": "6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca",
    "address": "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
    "value": 35000,
    "memo": "0000",
    "hash_seed": null 
}"#;

fn init_logging() {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .is_test(true)
        .try_init();
}

// Simulate a transaction where Alice sends 55000 ZEC to Bob. Includes:
// - Two spend notes of 50000 ZEC each, associated with Alice's address at path: 1000.
// - Two output notes for transaction distribution.
// - A transaction fee compliant with ZIP-0317.
// Transaction data is collected from the UI and formatted into JSON structures.
fn should_error_empty_tx(data: &types::InitData) {
    let n_tin = data.t_in.len();
    let n_tout = data.t_out.len();
    let n_spend = data.s_spend.len();
    let n_sout = data.s_output.len();

    let fee: u64 = ZcashBuilder::calculate_zip0317_fee(n_tin, n_tout, n_spend, n_sout).into();
    let builder = Builder::new_with_fee(TestNetwork, 0, fee);
    let mut builder = ZcashBuilderBridge::new(builder);

    assert!(builder
        .build(
            &SPEND_PATH.to_string(),
            &OUTPUT_PATH.to_string(),
            TX_VERSION as u8,
        )
        .is_err());
}

fn make_tx_with_two_spend_two_outputs(data: &types::InitData) {
    let n_tin = data.t_in.len();
    let n_tout = data.t_out.len();
    let n_spend = data.s_spend.len();
    let n_sout = data.s_output.len();

    let fee: u64 = ZcashBuilder::calculate_zip0317_fee(n_tin, n_tout, n_spend, n_sout).into();
    let builder = Builder::new_with_fee(TestNetwork, 0, fee);
    let mut builder = ZcashBuilderBridge::new(builder);

    let spend1: SpendBuilderInfo = serde_json::from_str(SAPLING_SPEND_1).unwrap();
    let spend2: SpendBuilderInfo = serde_json::from_str(SAPLING_SPEND_2).unwrap();
    let output1: OutputBuilderInfo = serde_json::from_str(SAPLING_OUTPUT_1).unwrap();
    let output2: OutputBuilderInfo = serde_json::from_str(SAPLING_OUTPUT_2).unwrap();

    builder.add_sapling_spend(spend1).unwrap();
    builder.add_sapling_spend(spend2).unwrap();
    builder.add_sapling_output(output1).unwrap();
    builder.add_sapling_output(output2).unwrap();

    builder
        .build(
            &SPEND_PATH.to_string(),
            &OUTPUT_PATH.to_string(),
            TX_VERSION as u8,
        )
        .unwrap();
}

#[test]
fn test_tx_builder() {
    init_logging();
    let json_data = std::fs::read_to_string("tests/data.json").expect("Failed to read JSON file");
    let test_data: Vec<types::InitData> =
        serde_json::from_str(&json_data).expect("Failed to parse JSON data");

    // Test No. 1
    should_error_empty_tx(&test_data[0]);

    // Test No. 2
    make_tx_with_two_spend_two_outputs(&test_data[0]);
}
