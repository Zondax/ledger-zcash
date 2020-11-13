use bs58::encode;
use nom::{
    branch::permutation,
    bytes::complete::take,
    number::complete::{be_u32, le_u16, le_u32, le_u64, le_u8},
};

use crate::parser::parser_common::{
    OutputScriptType, ParserError, u8_with_limits, var_int_as_usize,
};
use crate::zxformat;

const P2SH_LEN: usize = 23;
const P2PKH_LEN: usize = 25;
const P2SH_ADDRESS_HAS_LEN: usize = 20;
const P2PKH_ADDRESS_HAS_LEN: usize = 20;
/// he max length for the scriptPubKey
pub const MAX_SCRIPT_PUB_KEY_LEN: usize = 253;

// The max number of digits after
// the decimal point
const MAX_DECIMAL_PLACES: usize = 8;

// The capacity in bytes of the buffer
// used for conversion from u64 to a fixed
// point decimal string
const MAX_DECIMAL_BUFF_LEN: usize = 70;

// The capacity in bytes of the inner buffer which
// contains a parsed address. This addres could be a P2PKH
// P2SH, P2WPKH, P2WSH
const MAX_ADDRESS_BUFFER_LEN: usize = 40;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
// A transaction output
pub struct TxOutput<'a>(pub &'a [u8]);

#[repr(C)]
#[derive(Copy, Clone)]
pub enum Script<'a> {
    P2pkh(&'a [u8]),
    P2sh(&'a [u8]),
    P2wpkh(&'a [u8]),
    P2wsh(&'a [u8]),
    Unspendable,
}

#[derive(Copy, Clone)]
struct Address;

impl Address {
    fn new_from_p2pkh(
        bytes: &[u8],
    ) -> Result<arrayvec::ArrayVec<[u8; MAX_ADDRESS_BUFFER_LEN]>, ParserError> {
        let mut addr = arrayvec::ArrayVec::from([0u8; MAX_ADDRESS_BUFFER_LEN]);
        let len = Self::encode(bytes, addr.as_mut(), 0)?;
        unsafe { addr.set_len(len) }
        Ok(addr)
    }

    fn new_from_p2sh(
        bytes: &[u8],
    ) -> Result<arrayvec::ArrayVec<[u8; MAX_ADDRESS_BUFFER_LEN]>, ParserError> {
        let mut addr = arrayvec::ArrayVec::from([0u8; MAX_ADDRESS_BUFFER_LEN]);
        let len = Self::encode(bytes, addr.as_mut(), 5)?;
        unsafe { addr.set_len(len) }
        Ok(addr)
    }

    fn encode(data: &[u8], output: &mut [u8], version: u8) -> Result<usize, ParserError> {
        bs58::encode(data)
            .with_check_version(version)
            .into(output)
            .map_err(|_e| ParserError::parser_invalid_address)
    }

    pub fn unspendable() -> arrayvec::ArrayVec<[u8; MAX_ADDRESS_BUFFER_LEN]> {
        let mut addr: arrayvec::ArrayVec<[u8; MAX_ADDRESS_BUFFER_LEN]> = arrayvec::ArrayVec::new();
        b"unspentable".iter().for_each(|c| addr.push(*c));
        addr
    }
}

impl<'a> Script<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, ParserError> {
        let script = match data {
            [0xa9, 0x14, .., 0x87] if data.len() == P2SH_LEN => Self::P2sh(data),
            [0x76, 0xa9, 0x14, .., 0x88, 0xac] if data.len() == P2PKH_LEN => Self::P2pkh(data),
            [0x64] => Self::Unspendable,
            _ => return Err(ParserError::parser_invalid_output_script),
        };
        Ok(script)
    }
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], Self, ParserError> {
        let script_len = u8_with_limits(MAX_SCRIPT_PUB_KEY_LEN as _, bytes)?;
        let script = take(script_len.1)(script_len.0)?;
        let s = Self::new(script.1)
            .map_err(|_| nom::Err::Error(ParserError::parser_invalid_output_script))?;
        Ok((script.0, s))
    }

    pub fn read_as_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], &[u8], ParserError> {
        if bytes.is_empty() {
            return Err(nom::Err::Error(ParserError::parser_invalid_output_script));
        }
        let script_len = var_int_as_usize(bytes)
            .map_err(|_| nom::Err::Error(ParserError::parser_invalid_output_script))?;
        take(script_len + 1)(bytes)
    }

    pub fn is_p2sh(&self) -> bool {
        match self {
            Self::P2sh(..) => true,
            _ => false,
        }
    }

    pub fn is_p2pkh(&self) -> bool {
        match self {
            Self::P2pkh(..) => true,
            _ => false,
        }
    }

    pub fn is_op_return(&self) -> bool {
        match self {
            Self::Unspendable => true,
            _ => false,
        }
    }

    pub fn destination(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; MAX_ADDRESS_BUFFER_LEN]>, ParserError> {
        match self {
            Self::P2sh(data) => {
                let hash = &data[2..data.len() - 1];
                Address::new_from_p2sh(hash)
            }
            Self::P2pkh(data) => {
                let hash = &data[3..data.len() - 2];
                Address::new_from_p2pkh(hash)
            }
            _ => Ok(Address::unspendable()),
        }
    }
}

impl<'a> TxOutput<'a> {
    /// Creates a new output from a byte array
    pub fn from_bytes(bytes: &'a [u8]) -> nom::IResult<&[u8], TxOutput, ParserError> {
        let (raw, _) = permutation((le_u64, Script::read_as_bytes))(bytes)?;
        let len = bytes.len() - raw.len();
        let (left, data) = take(len)(bytes)?;
        Ok((left, Self(data)))
    }

    pub fn value(&self) -> Result<u64, ParserError> {
        le_u64::<'a, ParserError>(self.0)
            .map(|res| res.1)
            .map_err(|_| ParserError::parser_unexpected_buffer_end)
    }

    pub fn script(&self) -> Result<Script, ParserError> {
        Script::from_bytes(&self.0[8..])
            .map(|res| res.1)
            .map_err(|_| ParserError::parser_invalid_output_script)
    }

    pub fn address(&self) -> Result<arrayvec::ArrayVec<[u8; MAX_ADDRESS_BUFFER_LEN]>, ParserError> {
        Script::from_bytes(&self.0[8..])
            .map(|res| res.1)
            .map_err(|_| ParserError::parser_invalid_output_script)?
            .destination()
    }

    pub fn value_in_btc(
        &self,
    ) -> Result<arrayvec::ArrayVec<[u8; crate::zxformat::MAX_STR_BUFF_LEN]>, ParserError> {
        let mut output = arrayvec::ArrayVec::from([0u8; crate::zxformat::MAX_STR_BUFF_LEN]);
        let value = self.value()?;
        let written =
            zxformat::fpu64_to_str_check_test(output.as_mut(), value, MAX_DECIMAL_PLACES as _)?;
        unsafe {
            output.set_len(written);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod test {
    use super::Script;

    #[test]
    fn test_is_pay_to_script_hash() {
        let raw_script = "a9143b80842f4ea32806ce5e723a255ddd6490cfd28d87";
        let raw_script2 = "76a91461aac8b58ac880a45fb06eeedfcf3017679778a988ac";
        let bytes = hex::decode(raw_script).unwrap();
        let bytes2 = hex::decode(raw_script2).unwrap();
        let script = Script::new(&bytes).unwrap();
        let script2 = Script::new(&bytes2).unwrap();
        assert!(script.is_p2sh());
        assert!(!script2.is_p2sh());
    }

    #[test]
    fn test_is_pay_to_pub_key_hash() {
        let raw_script = "76a9144fc16e1766808c0ab090be4376cea9d3a0bbe12988ac";
        let raw_script2 = "a9143b80842f4ea32806ce5e723a255ddd6490cfd28d87";
        let bytes = hex::decode(raw_script).unwrap();
        let bytes2 = hex::decode(raw_script2).unwrap();
        let script = Script::new(&bytes).unwrap();
        let script2 = Script::new(&bytes2);
        assert!(script.is_p2pkh());
        assert!(!script2.is_err());
    }

    #[test]
    fn test_destination_from_pub_key_hash() {
        let raw_script = "76a9144fc16e1766808c0ab090be4376cea9d3a0bbe12988ac";
        let bytes = hex::decode(raw_script).unwrap();
        let script = Script::new(&bytes).unwrap();
        assert!(script.is_p2pkh());
        let address = script.destination().unwrap();
        assert_eq!(
            core::str::from_utf8(&address).unwrap(),
            "18Gi6umH8FTsw8K96F3FuQsjQv64MtojLu"
        );
    }

    #[test]
    fn test_destination_from_pay_to_script_hash() {
        let raw_script = "a9143b80842f4ea32806ce5e723a255ddd6490cfd28d87";
        let bytes = hex::decode(raw_script).unwrap();
        let script = Script::new(&bytes).unwrap();
        assert!(script.is_p2sh());
        let address = script.destination().unwrap();
        assert_eq!(
            core::str::from_utf8(&address).unwrap(),
            "377dkLL56GxGUe7mhsAZDvgJBY2BauJHpi",
        );
    }
}
