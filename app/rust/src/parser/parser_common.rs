#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

// http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
// https://bitcoin.stackexchange.com/questions/32628/redeeming-a-raw-transaction-step-by-step-example-required
// https://klmoney.wordpress.com/bitcoin-dissecting-transactions-part-2-building-a-transaction-by-hand/

use nom::{
    branch::permutation,
    bytes::complete::take,
    combinator::{iterator, map_parser},
    number::complete::{le_u32, le_u64, le_u8},
};

/// The max length of the previous transaction id
pub const TRANSACTION_ID_LEN: usize = 32;
const UNSHIELDED_TX_VERSION: u32 = 0x01000000;
pub const UNSHIELDED_TX_SEQUENCE: u32 = 0xffffffff;
/// The max number of inputs
/// allowed per transaction
pub const MAX_TX_INPUTS: usize = 8;
/// The max number of outputs
/// allowed per transaction
pub const MAX_TX_OUTPUTS: usize = 4;
/// The max length for the ScriptSig
pub const MAX_SCRIPT_SIG_LEN: usize = 253;
/// he max length for the scriptPubKey
pub const MAX_SCRIPT_PUB_KEY_LEN: usize = 253;

#[repr(C)]
#[no_mangle]
/// ParserError is the counterpart of
/// the parse_error_t in c,
/// we redeclare it here, just for interpolation
/// purposes
pub enum ParserError {
    // Generic errors
    parser_ok = 0,
    parser_no_data,
    parser_init_context_empty,
    parser_display_idx_out_of_range,
    parser_display_page_out_of_range,
    parser_unexepected_error,
    // Context related errors
    parser_context_mismatch,
    parser_context_unexpected_size,
    parser_context_invalid_chars,
    parser_context_unknown_prefix,
    // Required fields
    parser_required_nonce,
    parser_required_method,
    ////////////////////////
    // Coin specific
    parser_unexpected_type,
    parser_unexpected_method,
    parser_unexpected_buffer_end,
    parser_unexpected_value,
    parser_unexpected_number_items,
    parser_unexpected_characters,
    parser_unexpected_field,
    parser_value_out_of_range,
    parser_invalid_address,
}

impl ParserError {
    pub(crate) fn to_c(self) -> u32 {
        unsafe { core::mem::transmute::<Self, u32>(self) }
    }
}

#[repr(C)]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub bufferLen: u16,
    pub offset: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct OutPoint<'a> {
    /// Previous transaction id
    pub txid: &'a [u8], // should be shown in reverse order
    /// Previous transaction output index
    pub vout: u32,
}

impl<'a> OutPoint<'a> {
    pub fn new(vout: u32, txid: &'a [u8]) -> Self {
        Self { txid, vout }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
/// An unsigned transaction input
pub struct TxInput<'a> {
    pub outPoint: OutPoint<'a>,
    scriptSig: &'a [u8],
    pub sequence: u32,
}

impl<'a> TxInput<'a> {
    pub fn new(outPoint: OutPoint<'a>, sequence: u32, scriptSig: &'a [u8]) -> Self {
        Self {
            outPoint,
            scriptSig,
            sequence,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
// A transaction output
pub struct TxOutput<'a> {
    pub value: u64, // Bytes are disposed in little-endian
    scriptPubKey: &'a [u8],
}

impl<'a> TxOutput<'a> {
    pub fn new(value: u64, scriptPubKey: &'a [u8]) -> Self {
        Self {
            value,
            scriptPubKey,
        }
    }
}

// NOM parser combinators

pub fn previous_tx_id(bytes: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    take(TRANSACTION_ID_LEN)(bytes)
}

pub fn u8_with_limits(limit: u8, bytes: &[u8]) -> nom::IResult<&[u8], u8> {
    if bytes.len() >= 1 && bytes[0] <= limit {
        map_parser(take(1usize), le_u8)(bytes)
    } else {
        Err(nom::Err::Error((bytes, nom::error::ErrorKind::Char)))
    }
}

pub fn u32_le(bytes: &[u8]) -> nom::IResult<&[u8], u32> {
    map_parser(take(4usize), le_u32)(bytes)
}

pub fn u64_le(bytes: &[u8]) -> nom::IResult<&[u8], u64> {
    map_parser(take(8usize), le_u64)(bytes)
}

pub fn get_outpoint(bytes: &[u8]) -> nom::IResult<&[u8], OutPoint> {
    let res = permutation((previous_tx_id, le_u32))(bytes).unwrap();
    let outpoint = OutPoint::new((res.1).1, (res.1).0);
    Ok((res.0, outpoint))
}

pub fn get_script_sig(bytes: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    let len = u8_with_limits(MAX_SCRIPT_SIG_LEN as _, bytes)?;
    let res = take(len.1 as usize)(len.0)?;
    Ok(res)
}

pub fn tx_input(bytes: &[u8]) -> nom::IResult<&[u8], TxInput> {
    let res = permutation((get_outpoint, get_script_sig, u32_le))(bytes)?;
    let input = TxInput::new((res.1).0, (res.1).2, (res.1).1);
    Ok((res.0, input))
}

pub fn tx_output(bytes: &[u8]) -> nom::IResult<&[u8], TxOutput> {
    let amount = u64_le(bytes)?;
    let script_len = u8_with_limits(MAX_SCRIPT_PUB_KEY_LEN as _, amount.0)?;
    let script = take(script_len.1)(script_len.0)?;
    Ok((script.0, TxOutput::new(amount.1, script.1)))
}

pub fn get_inputs(bytes: &[u8]) -> nom::IResult<&[u8], ([Option<TxInput>; MAX_TX_INPUTS], u8)> {
    let num_inputs = u8_with_limits(MAX_TX_INPUTS as _, bytes)?;
    let mut inputs: [Option<TxInput>; MAX_TX_INPUTS] = [None; MAX_TX_INPUTS];
    let mut iter = iterator(num_inputs.0, tx_input);
    iter.take(num_inputs.1 as _).enumerate().for_each(|i| {
        inputs[i.0] = Some(i.1);
    });
    let res = iter.finish()?;
    Ok((res.0, (inputs, num_inputs.1)))
}

pub fn get_outputs(bytes: &[u8]) -> nom::IResult<&[u8], ([Option<TxOutput>; MAX_TX_OUTPUTS], u8)> {
    let num_outputs = u8_with_limits(MAX_TX_OUTPUTS as _, bytes)?;
    let mut outputs: [Option<TxOutput>; MAX_TX_OUTPUTS] = [None; MAX_TX_OUTPUTS];
    let mut iter = iterator(num_outputs.0, tx_output);
    iter.take(num_outputs.1 as _).enumerate().for_each(|i| {
        outputs[i.0] = Some(i.1);
    });
    let res = iter.finish()?;
    Ok((res.0, (outputs, num_outputs.1)))
}
