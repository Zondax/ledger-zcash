#![allow(non_camel_case_types, non_snake_case)]
use core::cell::UnsafeCell;

use crate::parser::{
    parser_common::{parser_context_t, OutPoint, ParserError, TxInput, TxOutput},
    transaction::Transaction,
};

type TxCell<T> = UnsafeCell<Option<T>>;

struct TxHandler<'a>(TxCell<Transaction<'a>>);

const TX_INIT: TxCell<Transaction> = UnsafeCell::new(None);

// This is the rust version of the parser_context_t..?
// the handler is a parsed raw transaction
static TRANSACTION: TxHandler = TxHandler(TX_INIT);

impl<'a> TxHandler<'a> {
    fn get(&self) -> Option<&Transaction> {
        unsafe { (*self.0.get()).as_ref() }
    }

    fn replace(&'a self, tx: Transaction<'a>) -> Option<Transaction<'_>> {
        unsafe { (*self.0.get()).replace(tx) }
    }
}

unsafe impl<'a> Sync for TxHandler<'a> {}

#[no_mangle]
pub extern "C" fn _read(_context: *const parser_context_t, data: *const u8, len: u16) -> u32 {
    let slice = unsafe {
        let data = core::slice::from_raw_parts(data, len as _);
        core::mem::transmute::<&[u8], &'static [u8]>(data)
    };
    // Parsing bytes to transaction occurs here,
    match Transaction::from_bytes(slice) {
        Ok(transaction) => {
            TRANSACTION.replace(transaction);
            ParserError::parser_ok.to_c()
        }
        Err(_e) => ParserError::parser_unexepected_error.to_c(),
    }
}

#[no_mangle]
pub extern "C" fn _validate(_ctx: *const parser_context_t) -> u32 {
    // TODO
    ParserError::parser_ok.to_c()
}

#[no_mangle]
pub extern "C" fn _getNumItems(_ctx: *const parser_context_t, num_items: *mut u16) {
    unsafe {
        // TODO
        *num_items = 1;
    }
}

// JUST for testing

const KEY: [i8; 2] = [b't' as _, b'o' as _];
const VALUE: [i8; 2] = [b'x' as _, b'y' as _];
#[no_mangle]
pub extern "C" fn _getItem(
    _ctx: *const parser_context_t,
    _displayIdx: u8,
    outKey: *mut i8,
    _outKeyLen: u16,
    outValue: *mut i8,
    _outValueLen: u16,
    _pageIdx: u8,
    pageCount: *mut u8,
) {
    unsafe {
        // TODO
        *outKey = (&KEY).as_ptr() as *const i8 as _;
        *outValue = (&VALUE).as_ptr() as *const i8 as _;
        *pageCount = 0;
    }
}
