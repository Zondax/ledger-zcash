#![allow(non_camel_case_types, non_snake_case)]
use core::cell::UnsafeCell;

use crate::parser::{
    parser_common::ParserError,
    transaction::Transaction,
    tx_input::{OutPoint, TxInput},
    tx_output::TxOutput,
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

#[repr(C)]
#[no_mangle]
pub struct parser_context_t {
    pub buffer: *const u8,
    pub bufferLen: u16,
    pub offset: u16,
}

#[repr(C)]
#[no_mangle]
pub struct parse_tx_t {
    method: u64,
}

#[no_mangle]
pub extern "C" fn _parser_init(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    bufferSize: u16,
) -> u32 {
    parser_init_context(ctx, buffer, bufferSize).into_c()
}

fn parser_init_context(
    ctx: *mut parser_context_t,
    buffer: *const u8,
    bufferSize: u16,
) -> ParserError {
    unsafe {
        (*ctx).offset = 0;

        if bufferSize == 0 || buffer.is_null() {
            // Not available, use defaults
            (*ctx).buffer = core::ptr::null_mut();
            (*ctx).bufferLen = 0;
            return ParserError::parser_init_context_empty;
        }

        (*ctx).buffer = buffer;
        (*ctx).bufferLen = bufferSize;
        return ParserError::parser_ok;
    }
}

#[no_mangle]
pub extern "C" fn _read(context: *const parser_context_t, _tx_t: *mut parse_tx_t) -> u32 {
    let slice = unsafe {
        let data = core::slice::from_raw_parts((*context).buffer, (*context).bufferLen as _);
        core::mem::transmute::<&[u8], &'static [u8]>(data)
    };
    // Parsing bytes to transaction occurs here
    match Transaction::from_bytes(slice) {
        Ok(transaction) => {
            TRANSACTION.replace(transaction);
            ParserError::parser_ok.into_c()
        }
        Err(e) => e.into_c(),
    }
}

#[no_mangle]
pub extern "C" fn _validate(_ctx: *const parser_context_t, _tx_t: *const parse_tx_t) -> u32 {
    // TODO
    ParserError::parser_ok.into_c()
}

#[no_mangle]
pub extern "C" fn _getNumItems(_ctx: *const parser_context_t, _tx_t: *const parse_tx_t) -> u8 {
    // TODO this can not be changed if so, some tests fail
    if let Some(tx) = TRANSACTION.get() {
        return tx.num_items() as _;
    }
    0
}

#[no_mangle]
pub extern "C" fn _getItem(
    _ctx: *const parser_context_t,
    displayIdx: u8,
    outKey: *mut i8,
    outKeyLen: u16,
    outValue: *mut i8,
    outValueLen: u16,
    pageIdx: u8,
    pageCount: *mut u8,
) -> u32 {
    unsafe {
        *pageCount = 0u8;
        let key = core::slice::from_raw_parts_mut(outKey as *mut u8, outKeyLen as usize);
        let value = core::slice::from_raw_parts_mut(outValue as *mut u8, outValueLen as usize);
        if let Some(tx) = TRANSACTION.get() {
            match tx.get_item(displayIdx, key, value, pageIdx) {
                Ok(page) => {
                    *pageCount = page;
                    return ParserError::parser_ok.into_c();
                }
                Err(e) => {
                    return e.into_c();
                }
            }
        }
        ParserError::parser_context_mismatch.into_c()
    }
}
