use crate::parser::parser_common::{u8_with_limits, var_int_as_usize, ParserError};
use nom::{branch::permutation, bytes::complete::take, number::complete::le_u32};

/// The max length for the ScriptSig
pub const MAX_SCRIPT_SIG_LEN: usize = 253;
/// The max length of the previous transaction id
pub const TRANSACTION_ID_LEN: usize = 32;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct OutPoint<'a>(&'a [u8]);

impl<'a> OutPoint<'a> {
    fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        // we take the transaction_id bytes and 4-bytes vout
        let (res, data) = take(TRANSACTION_ID_LEN + 4)(bytes)?;
        Ok((res, Self(data)))
    }

    pub fn vout(&self) -> Result<u32, ParserError> {
        let at = self.0.len() - 4;
        le_u32::<'a, ParserError>(&self.0[at..])
            .map(|res| res.1)
            .map_err(|_| ParserError::parser_unexpected_buffer_end)
    }

    // should be read in reverse order
    pub fn transaction_id(&self) -> &[u8] {
        let limit = self.0.len() - 4;
        &self.0[..limit]
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

    pub fn read_as_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
        let (left, _) = OutPoint::from_bytes(bytes)?;
        let mut len = var_int_as_usize(left).map_err(|e| nom::Err::Error(e))? + 1;
        len += (TRANSACTION_ID_LEN + 4) + 4;
        take(len)(bytes)
    }

    fn get_input_script(bytes: &[u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
        let len = u8_with_limits(MAX_SCRIPT_SIG_LEN as _, bytes)?;
        let res = take(len.1 as usize)(len.0)?;
        Ok(res)
    }

    pub fn vout(&self) -> Result<u32, ParserError> {
        self.out_point.vout()
    }
}
