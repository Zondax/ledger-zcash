use env_logger::Env;
use ledger_zcash::builder::Builder as ZcashBuilder;
use ledger_zcash_builder::{
    data::{TransparentInputBuilderInfo, TransparentOutputBuilderInfo},
    txbuilder::Builder,
};
use zcash_primitives::consensus::TestNetwork;
use zcashtool::*;

mod types;

const SPEND_PATH: &str = "tests/params/sapling-spend.params";
const OUTPUT_PATH: &str = "tests/params/sapling-output.params";
const TX_VERSION: usize = 5;

// Values for test_data[4]
const T_IN1: &str = r#"{"outp":"000000000000000000000000000000000000000000000000000000000000000000000000","pk":"031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e","address":"1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac","value":50000}"#;
const T_IN2: &str = r#"{"outp":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pk":"031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e","address":"1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac","value":50000}"#;
const T_OUT1: &str =
    r#"{"address":"1976a914000000000000000000000000000000000000000088ac","value":10000}"#;
const T_OUT2: &str =
    r#"{"address":"1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac","value":80000}"#;

// inputs: 50_000 + 50_000
// output:
// total: 100_000 - 90_000 = 10_000 - fee(10_000) = 0, no change

fn init_logging() {
    let _ = env_logger::Builder::from_env(Env::default().default_filter_or("trace"))
        .is_test(true)
        .try_init();
}

fn build(data: &types::InitData) {
    let n_tin = data.t_in.len();
    let n_tout = data.t_out.len();
    let n_spend = data.s_spend.len();
    let n_sout = data.s_output.len();

    let fee: u64 = ZcashBuilder::calculate_zip0317_fee(n_tin, n_tout, n_spend, n_sout).into();
    let builder = Builder::new_with_fee(TestNetwork, 0, fee);
    let mut builder = ZcashBuilderBridge::new(builder);

    let spend1: TransparentInputBuilderInfo = serde_json::from_str(T_IN1).unwrap();
    let spend2: TransparentInputBuilderInfo = serde_json::from_str(T_IN2).unwrap();
    let output1: TransparentOutputBuilderInfo = serde_json::from_str(T_OUT1).unwrap();
    let output2: TransparentOutputBuilderInfo = serde_json::from_str(T_OUT2).unwrap();

    builder.add_transparent_input(spend1).unwrap();
    builder.add_transparent_input(spend2).unwrap();
    builder.add_transparent_output(output1).unwrap();
    builder.add_transparent_output(output2).unwrap();

    builder
        .build(
            &SPEND_PATH.to_string(),
            &OUTPUT_PATH.to_string(),
            TX_VERSION as u8,
        )
        .unwrap();
}

#[test]
fn make_transaction_with_2transparent_input_2transparent_output() {
    init_logging();
    log::info!("Test: make_transaction_with_2transparent_input_2transparent_output");
    let json_data = std::fs::read_to_string("tests/data.json").expect("Failed to read JSON file");
    let test_data: Vec<types::InitData> =
        serde_json::from_str(&json_data).expect("Failed to parse JSON data");

    // Test No. 2
    build(&test_data[4]);
}
