use crate::parser::parser_common::*;
use nom::branch::permutation;

pub type TxTuple<'a> = (
    u32,
    ([Option<TxInput<'a>>; MAX_TX_INPUTS], u8),
    ([Option<TxOutput<'a>>; MAX_TX_OUTPUTS], u8),
    u32,
);

#[repr(C)]
// #[derive(Default)]
pub struct Transaction<'a> {
    version: u32,
    inputs: [Option<TxInput<'a>>; MAX_TX_INPUTS],
    pub ilen: usize,
    outputs: [Option<TxOutput<'a>>; MAX_TX_OUTPUTS],
    pub olen: usize,
    pub locktime: u32,
}

impl<'a> Transaction<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ()> {
        let res = permutation((u32_le, get_inputs, get_outputs, u32_le))(bytes).unwrap();
        Ok(Self::from(res.1))
    }

    pub fn get_inputs(&self) -> &[Option<TxInput>] {
        self.inputs[..self.ilen].as_ref()
    }

    pub fn get_outputs(&self) -> &[Option<TxOutput>] {
        self.outputs[..self.olen].as_ref()
    }

    pub fn get_num_items(&self) -> usize {
        1
    }

    pub fn get_item(&self) {}
}

impl<'a> From<TxTuple<'a>> for Transaction<'a> {
    fn from(raw: TxTuple<'a>) -> Self {
        Self {
            version: raw.0,
            inputs: (raw.1).0,
            ilen: (raw.1).1 as _,
            outputs: (raw.2).0,
            olen: (raw.2).1 as _,
            locktime: raw.3,
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use serde::{Deserialize, Serialize};
    use serde_json::{Result, Value};

    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::string::String;
    use std::vec::Vec;

    #[derive(Serialize, Deserialize)]
    struct Inputs {
        sequence: u32,
        output_index: u32,
        addresses: Vec<String>,
    }
    #[derive(Serialize, Deserialize)]
    struct Outputs {
        script: String,
        value: u64,
        addresses: Vec<String>,
    }

    #[derive(Serialize, Deserialize)]
    struct TxJson {
        raw_tx: String,
        outputs: Vec<Outputs>,
        inputs: Vec<Inputs>,
    }

    #[test]
    fn simple_1input_2output() {
        // We have the transaction description in a json file which content
        // corresponds to what is shown in the blockchain explorer
        let input_path = {
            let mut r = PathBuf::new();
            r.push(env!("CARGO_MANIFEST_DIR"));
            r.push("tests");
            r.push("1i2o_simple");
            r.set_extension("json");
            r
        };
        let str = fs::read_to_string(input_path).expect("Error opening json file");
        let json: TxJson = serde_json::from_str(&str).unwrap();

        let bytes = hex::decode(&json.raw_tx).unwrap();
        let transaction = Transaction::from_bytes(&bytes).unwrap();

        // We know the number of inputs and outputs so:
        assert_eq!(transaction.ilen, 1);
        assert_eq!(transaction.olen, 2);

        // for now we just verify if the locktime and amount are valids
        let tx_output_values = transaction
            .get_outputs()
            .iter()
            .filter_map(|&out| out)
            .map(|out| out.value)
            .collect::<Vec<u64>>();

        let json_output_values = json.outputs.iter().map(|v| v.value).collect::<Vec<u64>>();

        // check output values in satoshis
        assert_eq!(&tx_output_values, &json_output_values);

        // checks input sequence
        assert_eq!(
            json.inputs[0].sequence,
            transaction.get_inputs()[0].unwrap().sequence
        );

        // checks transaction output index
        assert_eq!(
            json.inputs[0].output_index,
            transaction.get_inputs()[0].unwrap().outPoint.vout
        );
    }
}
