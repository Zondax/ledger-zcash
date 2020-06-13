#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]
use nom::{
    branch::permutation,
    bytes::complete::take,
    combinator::{iterator, map_parser},
    error::ErrorKind,
    number::complete::{le_u32, le_u64, le_u8},
};

use crate::parser::tx_input::{OutPoint, TxInput};
use crate::parser::tx_output::TxOutput;

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

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
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
    parser_unexpected_error,
    parser_no_memory_for_state,
    // Context related errors
    parser_context_mismatch,
    parser_context_unexpected_size,
    parser_context_invalid_chars,
    parser_context_unknown_prefix,
    // Required fields
    ////////////////////////
    // Coin specific
    parser_invalid_output_script,
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

impl From<ErrorKind> for ParserError {
    fn from(err: ErrorKind) -> Self {
        match err {
            ErrorKind::Eof => ParserError::parser_unexpected_buffer_end,
            ErrorKind::Permutation => ParserError::parser_unexpected_type,
            ErrorKind::TooLarge => ParserError::parser_value_out_of_range,
            _ => ParserError::parser_unexpected_error,
        }
    }
}

impl<I> nom::error::ParseError<I> for ParserError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        Self::from(kind)
    }

    // We don't have enough memory resources to use here an array with the last
    // N errors to be used as a backtrace, so that, we just propagate here the latest
    // reported error
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum OutputScriptType {
    p2pkh,
    p2sh,
    p2wpkh,
    p2wsh,
    unspentable,
    unknown,
}

/******************************* NOM parser combinators *******************************************/
pub fn previous_tx_id(bytes: &[u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
    take(TRANSACTION_ID_LEN)(bytes)
}

pub fn u8_with_limits(limit: u8, bytes: &[u8]) -> nom::IResult<&[u8], u8, ParserError> {
    if !bytes.is_empty() && bytes[0] <= limit {
        map_parser(take(1usize), le_u8)(bytes)
    } else {
        Err(nom::Err::Error(ParserError::parser_value_out_of_range))
    }
}

fn get_outpoint(bytes: &[u8]) -> nom::IResult<&[u8], OutPoint, ParserError> {
    let res = permutation((previous_tx_id, le_u32))(bytes)?;
    let outpoint = OutPoint::new((res.1).1, (res.1).0);
    Ok((res.0, outpoint))
}

fn get_input_script(bytes: &[u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
    let len = u8_with_limits(MAX_SCRIPT_SIG_LEN as _, bytes)?;
    let res = take(len.1 as usize)(len.0)?;
    Ok(res)
}

fn get_output_script(bytes: &[u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
    let script_len = u8_with_limits(MAX_SCRIPT_PUB_KEY_LEN as _, bytes)?;
    let script = take(script_len.1)(script_len.0)?;
    Ok(script)
}

fn tx_input(bytes: &[u8]) -> nom::IResult<&[u8], TxInput, ParserError> {
    let res = permutation((get_outpoint, get_input_script, le_u32))(bytes)?;
    let input = TxInput::new((res.1).0, (res.1).2, (res.1).1);
    Ok((res.0, input))
}

fn tx_output(bytes: &[u8]) -> nom::IResult<&[u8], TxOutput, ParserError> {
    let res = permutation((le_u64, get_output_script))(bytes)?;
    let output = TxOutput::new((res.1).0, (res.1).1).map_err(|e| nom::Err::Error(e))?;
    Ok((res.0, output))
}

pub fn get_inputs(
    bytes: &[u8],
) -> nom::IResult<&[u8], ([Option<TxInput>; MAX_TX_INPUTS], u8), ParserError> {
    let num_inputs = u8_with_limits(MAX_TX_INPUTS as _, bytes)?;
    let mut inputs: [Option<TxInput>; MAX_TX_INPUTS] = [None; MAX_TX_INPUTS];
    let mut iter = iterator(num_inputs.0, tx_input);
    iter.take(num_inputs.1 as _).enumerate().for_each(|i| {
        inputs[i.0] = Some(i.1);
    });
    let res = iter.finish()?;
    Ok((res.0, (inputs, num_inputs.1)))
}

pub fn get_outputs(
    bytes: &[u8],
) -> nom::IResult<&[u8], ([Option<TxOutput>; MAX_TX_OUTPUTS], u8), ParserError> {
    let mut num_outputs = u8_with_limits(MAX_TX_OUTPUTS as _, bytes)?;
    // Not all outputs might be supported
    num_outputs.1 = 0;
    let mut outputs: [Option<TxOutput>; MAX_TX_OUTPUTS] = [None; MAX_TX_OUTPUTS];
    let mut iter = iterator(num_outputs.0, tx_output);
    iter.enumerate().for_each(|i| {
        outputs[i.0] = Some(i.1);
        num_outputs.1 += 1;
    });
    let res = iter.finish()?;
    Ok((res.0, (outputs, num_outputs.1)))
}
