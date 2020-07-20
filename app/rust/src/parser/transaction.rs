use core::fmt::{self, write, Write};
use nom::{branch::permutation, number::complete::le_u32};

use crate::parser::{
    parser_common::*,
    tx_input::{OutPoint, TxInput},
    tx_output::TxOutput,
};

use crate::zxformat;

pub type TxTuple<'a> = (
    u32, // version number
    ([Option<TxInput<'a>>; MAX_TX_INPUTS], u8),
    ([Option<TxOutput<'a>>; MAX_TX_OUTPUTS], u8),
    u32, // locktime
);

#[repr(C)]
pub struct Transaction<'a> {
    version: u32,
    inputs: [Option<TxInput<'a>>; MAX_TX_INPUTS],
    pub inputs_len: usize,
    outputs: [Option<TxOutput<'a>>; MAX_TX_OUTPUTS],
    pub outputs_len: usize,
    pub locktime: u32,
}

impl<'a> Transaction<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ParserError> {
        match permutation((le_u32, get_inputs, get_outputs, le_u32))(bytes) {
            Ok(tx) => Ok(Self::from(tx.1)),
            Err(_e) => Err(ParserError::parser_unexpected_error),
        }
    }

    pub fn inputs(&self) -> &[Option<TxInput>] {
        self.inputs[..self.inputs_len].as_ref()
    }

    pub fn outputs(&self) -> &[Option<TxOutput>] {
        self.outputs[..self.outputs_len].as_ref()
    }

    pub fn num_items(&self) -> usize {
        // outputs have two values, the destination address and amount
        2 * self.outputs_len
    }

    pub fn get_item(
        &self,
        display_idx: u8,
        out_key: &mut [u8],
        out_value: &mut [u8],
        page_idx: u8,
    ) -> Result<u8, ParserError> {
        if (display_idx as usize) >= self.num_items() {
            return Err(ParserError::parser_display_idx_out_of_range);
        }

        // until now there are just two elements per output
        // the amount and destination
        let items_per_output = 2;
        let out_idx = (display_idx as usize) / self.outputs_len;
        let out_item = display_idx % items_per_output;

        let mut writer_key = zxformat::Writer::new(out_key);
        let tx_output = self.outputs[out_idx]
            .as_ref()
            .ok_or(ParserError::parser_unexpected_error)?;
        let page = if out_item == 0 {
            writer_key
                .write_str("Value")
                .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
            let (written, btc) = tx_output.value_in_btc()?;
            zxformat::pageString(out_value, btc[..written].as_ref(), page_idx)?
        } else {
            writer_key
                .write_str("To")
                .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
            let address = tx_output.address()?;
            zxformat::pageString(out_value, address.destination(), page_idx)?
        };
        Ok(page)
    }
}

impl<'a> From<TxTuple<'a>> for Transaction<'a> {
    fn from(raw: TxTuple<'a>) -> Self {
        Self {
            version: raw.0,
            inputs: (raw.1).0,
            inputs_len: (raw.1).1 as _,
            outputs: (raw.2).0,
            outputs_len: (raw.2).1 as _,
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
    use std::path::PathBuf;
    use std::string::String;
    use std::string::ToString;
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

    const MAX_DISPLAY_SIZE: usize = 15;

    fn check_validity(raw_tx: &Transaction, json_tx: &TxJson) {
        let mut key = [0u8; MAX_DISPLAY_SIZE];
        let mut value = [0u8; MAX_DISPLAY_SIZE];
        let mut page_idx = 0;
        let mut result = std::vec::Vec::new();
        let num_items = raw_tx.num_items();

        assert_eq!(json_tx.outputs.len() * 2, num_items);

        let mut i = 0;
        while i < num_items {
            let json_out = i / 2;
            let json_inner_idx = i % 2;
            let json_output = &json_tx.outputs[json_out];

            let pages = raw_tx
                .get_item(i as u8, key.as_mut(), value.as_mut(), page_idx)
                .unwrap();

            // with inner_idx = 0, we are looking for the
            //  value in btc
            let value_string = if json_inner_idx == 0 {
                // key: Value
                let key_str = core::str::from_utf8(key[..5].as_ref()).unwrap();
                assert_eq!(key_str, "Value");
                result.extend_from_slice(value.as_ref());
                let mut json_value_buff = [0u8; 40];
                let len =
                    super::zxformat::fpu64_to_str(json_value_buff.as_mut(), json_output.value, 8)
                        .unwrap();
                let json_value_str = std::str::from_utf8(json_value_buff[..len].as_ref()).unwrap();

                json_value_str.to_string()

            // if inner_idx = 1 we are looking for an Address
            } else {
                // key: To
                let key_str = std::str::from_utf8(key[..2].as_ref()).unwrap();
                assert_eq!(key_str, "To");
                result.extend_from_slice(value[..MAX_DISPLAY_SIZE - 1].as_ref());
                json_output.addresses[0].clone()
            };

            if page_idx == pages - 1 {
                let raw_value_str = core::str::from_utf8(result.as_ref()).unwrap();
                assert_eq!(
                    value_string.as_str(),
                    raw_value_str.get(..value_string.len()).unwrap()
                );
                // Continue to the next item and clear our result buffer
                i += 1;
                result.clear();
            }

            page_idx += 1;

            if page_idx >= pages {
                page_idx = 0;
            }
        }
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
        let str = std::fs::read_to_string(input_path).expect("Error opening json file");
        let json: TxJson = serde_json::from_str(&str).unwrap();

        let bytes = hex::decode(&json.raw_tx).unwrap();
        let transaction = Transaction::from_bytes(&bytes).unwrap();

        // We know the number of inputs and outputs so:
        assert_eq!(transaction.inputs_len, 1);
        assert_eq!(transaction.outputs_len, 2);

        // for now we just verify if the locktime and amount are valid
        let tx_output_values = transaction
            .outputs()
            .iter()
            .filter_map(|&out| out)
            .map(|out| out.value())
            .collect::<Vec<u64>>();

        let json_output_values = json.outputs.iter().map(|v| v.value).collect::<Vec<u64>>();

        // check output values in satoshis
        assert_eq!(&tx_output_values, &json_output_values);

        // checks input sequence
        assert_eq!(
            json.inputs[0].sequence,
            transaction.inputs()[0].unwrap().sequence
        );

        // checks transaction output index
        assert_eq!(
            json.inputs[0].output_index,
            transaction.inputs()[0].unwrap().out_point.vout
        );

        // similar to an integration test
        // where the UI asks for each item
        check_validity(&transaction, &json);
    }
}
