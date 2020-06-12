use crate::parser::parser_common::{OutputScriptType, ParserError};
use bs58::encode;
use nom::bytes::complete::take;

const P2SH_LEN: usize = 23;
const P2PKH_LEN: usize = 25;
const P2SH_ADDRESS_HAS_LEN: usize = 20;
const P2PKH_ADDRESS_HAS_LEN: usize = 20;

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

extern "C" {
    fn fp_uint64_to_str(out: *mut i8, outLen: u16, value: u64, decimals: u8) -> u16;
}

#[repr(C)]
#[derive(Copy, Clone)]
// A transaction output
pub struct TxOutput<'a> {
    value: u64, // Bytes are disposed in little-endian
    script: Script<'a>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Script<'a> {
    data: &'a [u8],
    script_type: OutputScriptType,
}

#[derive(Copy, Clone)]
pub struct Address {
    addr: [u8; MAX_ADDRESS_BUFFER_LEN],
    pub len: usize,
}

impl Address {
    fn new_from_p2pkh(bytes: &[u8]) -> Result<Self, ParserError> {
        let mut addr = [0u8; MAX_ADDRESS_BUFFER_LEN];
        let len = bs58::encode(bytes)
            .with_check_version(0)
            .into(addr.as_mut())
            .map_err(|_e| ParserError::parser_invalid_address)?;
        Ok(Address { addr, len })
    }

    fn new_from_p2sh(bytes: &[u8]) -> Result<Self, ParserError> {
        let mut addr = [0u8; MAX_ADDRESS_BUFFER_LEN];
        let len = bs58::encode(bytes)
            .with_check_version(5)
            .into(addr.as_mut())
            .map_err(|_e| ParserError::parser_invalid_address)?;
        Ok(Address { addr, len })
    }

    pub fn destination(&self) -> &[u8] {
        &self.addr[..self.len]
    }
}

impl Default for Address {
    fn default() -> Self {
        let value = b"unspentable";
        let len = value.len();
        let mut addr = [0u8; MAX_ADDRESS_BUFFER_LEN];
        addr.copy_from_slice(value);
        Address { addr, len }
    }
}

impl<'a> Script<'a> {
    fn new(data: &'a [u8]) -> Result<Self, ParserError> {
        let script_type = match data {
            [0xa9, 0x14, .., 0x87] if data.len() == P2SH_LEN => OutputScriptType::p2sh,
            [0x76, 0xa9, 0x14, .., 0x88, 0xac] if data.len() == P2PKH_LEN => {
                OutputScriptType::p2pkh
            }
            [0x64] => OutputScriptType::unspentable,
            _ => return Err(ParserError::parser_invalid_output_script),
        };
        Ok(Self { data, script_type })
    }

    pub fn script_type(&self) -> OutputScriptType {
        self.script_type
    }

    pub fn is_p2sh(&self) -> bool {
        self.script_type == OutputScriptType::p2sh
    }

    pub fn is_p2pkh(&self) -> bool {
        self.script_type == OutputScriptType::p2pkh
    }

    pub fn is_op_return(&self) -> bool {
        self.script_type == OutputScriptType::unspentable
    }

    pub fn destination(&self) -> Result<Address, ParserError> {
        match self.script_type {
            OutputScriptType::p2sh => {
                let hash = &self.data[2..self.data.len() - 1];
                Address::new_from_p2sh(hash)
            }
            OutputScriptType::p2pkh => {
                let hash = &self.data[3..self.data.len() - 2];
                Address::new_from_p2pkh(hash)
            }
            _ => Ok(Address::default()),
        }
    }
}

impl<'a> TxOutput<'a> {
    /// Creates a new output
    ///
    /// This method would return None if the script_pub_key
    /// is unsupported
    pub fn new(value: u64, script: &'a [u8]) -> Result<Self, ParserError> {
        let script = Script::new(script)?;
        Ok(Self { value, script })
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn script(&self) -> &Script {
        &self.script
    }

    pub fn address(&self) -> Result<Address, ParserError> {
        self.script.destination()
    }

    //zxformat::pageString(out_value, amount_buffer[..written].as_mut(), page_idx)?
    //#[cfg(not(test))]
    pub fn value_in_btc(
        &self,
    ) -> Result<(usize, [u8; crate::zxformat::MAX_NUM_STR_BUFF_LEN]), ParserError> {
        let mut output = [0u8; crate::zxformat::MAX_NUM_STR_BUFF_LEN];
        if cfg!(test) {
            let written =
                crate::zxformat::fpu64_to_str(output.as_mut(), self.value, MAX_DECIMAL_PLACES as _)
                    .map_err(|_| ParserError::parser_value_out_of_range)?;
            Ok((written, output))
        } else {
            unsafe {
                let written = fp_uint64_to_str(
                    output.as_mut_ptr() as _,
                    output.len() as _,
                    self.value as _,
                    MAX_DECIMAL_PLACES as _,
                );
                Ok((written as usize, output))
            }
        }
    }

    fn script_type(&self) -> OutputScriptType {
        self.script.script_type()
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::{Address, Script};
    use std::println;
    use std::vec::Vec;

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
        let addr = address.destination();
        assert_eq!(
            std::str::from_utf8(&addr[..34]).unwrap(),
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
        let addr = address.destination();
        assert_eq!(
            std::str::from_utf8(&addr[..34]).unwrap(),
            "377dkLL56GxGUe7mhsAZDvgJBY2BauJHpi",
        );
    }
}
