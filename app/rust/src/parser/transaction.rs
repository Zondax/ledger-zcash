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
    arrayvec::ArrayVec<[&'a [u8]; MAX_TX_INPUTS]>,
    arrayvec::ArrayVec<[TxOutput<'a>; MAX_TX_OUTPUTS]>,
    u32, // locktime
);

impl<'a> From<(TxTuple<'a>, &'a [u8])> for Transaction<'a> {
    fn from(raw: (TxTuple<'a>, &'a [u8])) -> Self {
        Self {
            version: (raw.0).0,
            inputs: (raw.0).1,
            outputs: (raw.0).2,
            locktime: (raw.0).3,
            remainder: raw.1,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Transaction<'a> {
    version: u32,
    inputs: arrayvec::ArrayVec<[&'a [u8]; MAX_TX_INPUTS]>,
    outputs: arrayvec::ArrayVec<[TxOutput<'a>; MAX_TX_OUTPUTS]>,
    pub locktime: u32,
    remainder: &'a [u8],
}

impl<'a> Transaction<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ParserError> {
        match permutation((le_u32, get_inputs, get_outputs, le_u32))(bytes) {
            Ok(tx) => Ok(Self::from((tx.1, tx.0))),
            Err(_e) => Err(ParserError::parser_unexpected_error),
        }
    }

    pub fn read(&mut self, data: &'a [u8]) -> Result<(), ParserError> {
        let (raw, version) = le_u32::<'a, ParserError>(data)
            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
        self.version = version;
        self.remainder = raw;
        self.read_inputs()?;
        self.read_outputs()?;
        let (raw, locktime) = le_u32::<'a, ParserError>(self.remainder)
            .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
        self.locktime = locktime;
        self.remainder = raw;
        Ok(())
    }

    fn read_inputs(&mut self) -> Result<(), ParserError> {
        let (raw, inputs) =
            get_inputs(self.remainder).map_err(|_| ParserError::parser_unexpected_error)?;
        self.inputs = inputs;
        self.remainder = raw;
        Ok(())
    }

    fn read_outputs(&mut self) -> Result<(), ParserError> {
        let (raw, outputs) =
            get_outputs(self.remainder).map_err(|_| ParserError::parser_unexpected_error)?;
        self.outputs = outputs;
        self.remainder = raw;
        Ok(())
    }

    pub fn inputs(&self) -> &[&[u8]] {
        self.inputs.as_ref()
    }

    pub fn outputs(&self) -> &[TxOutput] {
        self.outputs.as_ref()
    }

    pub fn num_items(&self) -> usize {
        // outputs have two values, the destination address and amount
        2 * self.outputs.len()
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
        let out_idx = (display_idx as usize) / self.outputs.len();
        let out_item = display_idx % items_per_output;

        let mut writer_key = zxformat::Writer::new(out_key);
        let tx_output = &self.outputs[out_idx];
        let page = if out_item == 0 {
            writer_key
                .write_str("Value")
                .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
            let value = tx_output.value_in_btc()?;
            zxformat::pageString(out_value, value.as_ref(), page_idx)?
        } else {
            writer_key
                .write_str("To")
                .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
            let address = tx_output.address()?;
            zxformat::pageString(out_value, address.as_ref(), page_idx)?
        };
        Ok(page)
    }

    #[cfg(test)]
    pub fn validate(tx: &Self) -> Result<(), ParserError> {
        let mut key = [0u8; 30];
        let mut value = [0u8; 30];
        let mut page_idx = 0;
        let mut display_idx = 0;

        let num_items = tx.num_items();
        while display_idx < num_items {
            let pages = tx.get_item(display_idx as u8, &mut key, &mut value, page_idx)?;

            page_idx += 1;
            if page_idx >= pages {
                page_idx = 0;
                display_idx += 1;
            }
        }
        Ok(())
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
        let mut transaction = Transaction::from_bytes(&bytes).unwrap();
        transaction.read(&bytes).unwrap();

        // We know the number of inputs and outputs so:
        assert_eq!(transaction.inputs.len(), 1);
        assert_eq!(transaction.outputs.len(), 2);

        // for now we just verify if the locktime and amount are valid
        let tx_output_values = transaction
            .outputs()
            .iter()
            .filter_map(|&out| out.value().ok())
            .collect::<Vec<u64>>();

        let json_output_values = json.outputs.iter().map(|v| v.value).collect::<Vec<u64>>();

        // check output values in satoshis
        assert_eq!(&tx_output_values, &json_output_values);

        // checks input sequence
        let input = TxInput::from_bytes(transaction.inputs()[0]).unwrap().1;
        assert_eq!(json.inputs[0].sequence, input.sequence);

        // checks transaction output index
        assert_eq!(json.inputs[0].output_index, input.vout().unwrap());

        Transaction::validate(&transaction).unwrap();
    }
}
