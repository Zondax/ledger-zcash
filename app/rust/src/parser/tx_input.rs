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
    pub out_point: OutPoint<'a>,
    script_sig: &'a [u8],
    pub sequence: u32,
}

impl<'a> TxInput<'a> {
    pub fn new(out_point: OutPoint<'a>, sequence: u32, script_sig: &'a [u8]) -> Self {
        Self {
            out_point,
            script_sig,
            sequence,
        }
    }
}
