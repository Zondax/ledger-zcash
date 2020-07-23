use crate::parser::parser_common::{u8_with_limits, ParserError};
use nom::{branch::permutation, bytes::complete::take, number::complete::le_u32};

/// The max length for the ScriptSig
pub const MAX_SCRIPT_SIG_LEN: usize = 253;
/// The max length of the previous transaction id
pub const TRANSACTION_ID_LEN: usize = 32;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct OutPoint<'a> {
    /// Previous transaction id
    pub txid: &'a [u8], // should be shown in reverse order
    /// Previous transaction output index
    pub vout: u32,
}

impl<'a> OutPoint<'a> {
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let res = permutation((take(TRANSACTION_ID_LEN), le_u32))(bytes)?;
        let outpoint = Self {
            txid: (res.1).0,
            vout: (res.1).1,
        };
        Ok((res.0, outpoint))
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
/// An unsigned transaction input
pub struct TxInput<'a> {
    pub out_point: OutPoint<'a>,
    script_sig: &'a [u8],
    pub sequence: u32,
}

impl<'a> TxInput<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let res = permutation((OutPoint::from_bytes, Self::get_input_script, le_u32))(bytes)?;
        let input = Self {
            out_point: (res.1).0,
            script_sig: (res.1).1,
            sequence: (res.1).2,
        };

        Ok((res.0, input))
    }

    fn get_input_script(bytes: &[u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
        let len = u8_with_limits(MAX_SCRIPT_SIG_LEN as _, bytes)?;
        let res = take(len.1 as usize)(len.0)?;
        Ok(res)
    }
}
