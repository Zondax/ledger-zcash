#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

use arrayvec::ArrayVec;
use nom::{
    branch::permutation,
    bytes::complete::take,
    combinator::{iterator, map_parser},
    error::ErrorKind,
    number::complete::{le_u16, le_u32, le_u64, le_u8},
};

use crate::parser::tx_input::{OutPoint, TxInput};
use crate::parser::tx_output::TxOutput;

/// The max number of inputs
/// allowed per transaction
pub const MAX_TX_INPUTS: usize = 8;
/// The max number of outputs
/// allowed per transaction
pub const MAX_TX_OUTPUTS: usize = 4;

// Returns the var_int described by bytes
// according to https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
pub fn var_int_as_usize<'a>(bytes: &'a [u8]) -> Result<usize, ParserError> {
    if bytes.is_empty() {
        return Err(ParserError::parser_unexpected_buffer_end);
    }
    let len = match bytes[0] {
        x if x < 253 => x as usize,
        253 => {
            let (_, n) = le_u16::<'a, ParserError>(&bytes[1..])
                .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
            n as usize
        }
        254 => {
            let (_, n) = le_u32::<'a, ParserError>(&bytes[1..])
                .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
            n as usize
        }
        255 => {
            let (_, n) = le_u64::<'a, ParserError>(&bytes[1..])
                .map_err(|_| ParserError::parser_unexpected_buffer_end)?;
            n as usize
        }
        _ => return Err(ParserError::parser_invalid_output_script),
    };
    Ok(len)
}

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

pub fn u8_with_limits(limit: u8, bytes: &[u8]) -> nom::IResult<&[u8], u8, ParserError> {
    if !bytes.is_empty() && bytes[0] <= limit {
        map_parser(take(1usize), le_u8)(bytes)
    } else {
        Err(nom::Err::Error(ParserError::parser_value_out_of_range))
    }
}

pub fn get_inputs(
    bytes: &[u8],
) -> nom::IResult<&[u8], ArrayVec<[&[u8]; MAX_TX_INPUTS]>, ParserError> {
    let num_inputs = u8_with_limits(MAX_TX_INPUTS as _, bytes)?;
    let mut inputs: ArrayVec<[&[u8]; MAX_TX_INPUTS]> = ArrayVec::new();
    let mut iter = iterator(num_inputs.0, TxInput::read_as_bytes);
    iter.take(num_inputs.1 as _).for_each(|i| {
        inputs.push(i);
    });
    let res = iter.finish()?;
    Ok((res.0, inputs))
}

pub fn get_outputs(
    bytes: &[u8],
) -> nom::IResult<&[u8], ArrayVec<[TxOutput; MAX_TX_OUTPUTS]>, ParserError> {
    let num_outputs = u8_with_limits(MAX_TX_OUTPUTS as _, bytes)?;
    #[cfg(test)]
    println!("num outputs {}", num_outputs.1);
    let mut outputs: ArrayVec<[TxOutput; MAX_TX_OUTPUTS]> = ArrayVec::new();
    let mut iter = iterator(num_outputs.0, TxOutput::from_bytes);
    iter.take(num_outputs.1 as usize).for_each(|i| {
        outputs.push(i);
    });
    let (res, _) = iter.finish()?;
    Ok((res, outputs))
}
