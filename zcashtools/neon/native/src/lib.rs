use neon::prelude::*;

use std::path::Path;

use neon_serde::ResultExt;
use rand_core::OsRng;
use zcash_hsmbuilder::errors::Error;
use zcash_hsmbuilder as ZcashBuilder;
use zcash_hsmbuilder::data::{HsmTxData, InitData, OutputBuilderInfo, SpendBuilderInfo, TransactionSignatures, TransparentInputBuilderInfo, TransparentOutputBuilderInfo};
use zcash_hsmbuilder::{hsmauth, txprover};
use zcash_primitives;
use ledger_zcash::zcash::primitives::consensus::TestNetwork;
use ledger_zcash::zcash::primitives::{consensus,
                                      transaction::
                                      {components::{transparent, sapling}
                                      }};
use zcash_hsmbuilder::txbuilder::hsmauth::MixedAuthorization;
use zcash_primitives::transaction::components::TxOut;

// reference
// https://neon-bindings.com/docs/primitives

//bridge stuff only

fn get_inittx_data(mut cx: FunctionContext) -> JsResult<JsValue> {
    // First get call arguments
    let arg0 = cx.argument::<JsValue>(0)?;
    let arg0_value: InitData = neon_serde::from_value(&mut cx, arg0).throw(&mut cx)?;
    let output = arg0_value.to_hsm_bytes();
    let js_value;
    js_value = neon_serde::to_value(&mut cx, &output).throw(&mut cx)?;
    Ok(js_value)
}

pub struct ZcashBuilderBridge  {
    unauth_zcashbuilder: ZcashBuilder::txbuilder::Builder<TestNetwork, OsRng,hsmauth::Unauthorized>,
    auth_zcashbuilder: Option<ZcashBuilder::txbuilder::Builder<TestNetwork, OsRng, MixedAuthorization<transparent::Authorized, sapling::Authorized> >> ,
}

impl ZcashBuilderBridge {
    pub fn add_transparent_input(&mut self, t: TransparentInputBuilderInfo) -> Result<(), Error> {
        self.unauth_zcashbuilder.add_transparent_input(t.pk, t.outp, TxOut {
            value: t.value,
            script_pubkey: t.address
        })
    }

    pub fn add_transparent_output(
        &mut self,
        input: TransparentOutputBuilderInfo,
    ) -> Result<(), Error> {
        self.unauth_zcashbuilder.add_transparent_output(input.address, input.value)
    }

    pub fn add_sapling_spend(&mut self, input: SpendBuilderInfo) -> Result<(), Error> {
        let div = *input.address.diversifier();
        let pk_d = *input.address.pk_d();
        let note = ledger_zcash::zcash::primitives::sapling::Note {
            value: u64::from(input.value),
            g_d: div.g_d().unwrap(),
            pk_d,
            rseed: input.rseed,
        };
        self.unauth_zcashbuilder.add_sapling_spend(div, note, input.witness, input.alpha, input.proofkey, input.rcv)
    }

    pub fn add_sapling_output(&mut self, input: OutputBuilderInfo) -> Result<(), Error> {
        self.unauth_zcashbuilder.add_sapling_output(input.ovk, input.address, input.value, input.memo, input.rcv, input.rseed, input.hash_seed)
    }

    pub fn build(&mut self, spendpath: &String, outputpath: &String) -> Result<HsmTxData, Error> {
        let mut prover = txprover::LocalTxProver::new(Path::new(spendpath), Path::new(outputpath));
        self.unauth_zcashbuilder.build(consensus::BranchId::Sapling, &mut prover)
    }

    pub fn add_signatures(&mut self, input: TransactionSignatures) -> Result< (), Error> {
        let builder_authorize_z = self.unauth_zcashbuilder.add_signatures_spend(input.spend_sigs);
        if builder_authorize_z.is_err() {
            return Err(builder_authorize_z.err().unwrap())
        }
        let builder_authorize_t = builder_authorize_z.unwrap().add_signatures_transparent(input.transparent_sigs);
        if builder_authorize_t.is_err() {
            return Err(builder_authorize_t.err().unwrap())
        }

        self.auth_zcashbuilder = Some(builder_authorize_t.unwrap());
        Ok(())
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>, Error> {
        if self.auth_zcashbuilder.is_none(){
            return Err(Error::Finalization)
        }
        self.auth_zcashbuilder.as_ref().unwrap().finalize_js()
    }
}

declare_types! {
    pub class JsZcashBuilder for ZcashBuilderBridge {
        init(mut cx) {
            let f = cx.argument::<JsNumber>(0)?.value();
            let unauth_zcashbuilder = ZcashBuilder::txbuilder::Builder::new_with_fee(TestNetwork, 0, f as u64);
            Ok(ZcashBuilderBridge {
                unauth_zcashbuilder,
                auth_zcashbuilder: None,
            })
        }

        method add_transparent_input(mut cx) {
            let arg0 = cx.argument::<JsValue>(0)?;
            let arg0_value :TransparentInputBuilderInfo = neon_serde::from_value(&mut cx, arg0).throw(&mut cx)?;
            let value;
            {
            let mut this = cx.this();
            let guard = cx.lock();
            let mut thishandler = this.borrow_mut(&guard);

            //grab input
            value = thishandler.add_transparent_input(arg0_value);
            }
            if value.is_ok(){
                Ok(cx.boolean(true).upcast())
            }else{
                cx.throw_error(value.err().unwrap().to_string())
            }
        }

        method add_transparent_output(mut cx) {
            let arg0 = cx.argument::<JsValue>(0)?;
            let arg0_value :TransparentOutputBuilderInfo = neon_serde::from_value(&mut cx, arg0).throw(&mut cx)?;
            let value;
            {
            let mut this = cx.this();
            let guard = cx.lock();
            let mut thishandler = this.borrow_mut(&guard);

            //grab input
            value = thishandler.add_transparent_output(arg0_value);
            }
            if value.is_ok(){
                Ok(cx.boolean(true).upcast())
            }else{
                cx.throw_error(value.err().unwrap().to_string())
            }
        }

        method add_sapling_spend(mut cx) {
            let arg0 = cx.argument::<JsValue>(0)?;
            let arg0_value :SpendBuilderInfo = neon_serde::from_value(&mut cx, arg0).throw(&mut cx)?;
            let value;
            {
            let mut this = cx.this();
            let guard = cx.lock();
            let mut thishandler = this.borrow_mut(&guard);

            //grab input
            value = thishandler.add_sapling_spend(arg0_value);
            }
            if value.is_ok(){
                Ok(cx.boolean(true).upcast())
            }else{
                cx.throw_error(value.err().unwrap().to_string())
            }
        }

        method add_sapling_output(mut cx) {
            let arg0 = cx.argument::<JsValue>(0)?;
            let arg0_value :OutputBuilderInfo = neon_serde::from_value(&mut cx, arg0).throw(&mut cx)?;
            let value;
            {
            let mut this = cx.this();
            let guard = cx.lock();
            let mut thishandler = this.borrow_mut(&guard);

            //grab input
            value = thishandler.add_sapling_output(arg0_value);
            }
            if value.is_ok(){
                Ok(cx.boolean(true).upcast())
            }else{
                cx.throw_error(value.err().unwrap().to_string())
            }
        }

        method build(mut cx){
            let spendpath: String = cx.argument::<JsString>(0)?.value();
            let outputpath: String = cx.argument::<JsString>(1)?.value();
            let value;
            {
            let mut this = cx.this();
            let guard = cx.lock();
            let mut thishandler = this.borrow_mut(&guard);

            //grab input
            value = thishandler.build(&spendpath, &outputpath);
            }
            if value.is_ok(){
                let js_value = neon_serde::to_value(&mut cx, &value.unwrap().to_hsm_bytes().unwrap()).throw(&mut cx)?;
                Ok(js_value)
            }else{
                cx.throw_error(value.err().unwrap().to_string())
            }
        }

        method add_signatures(mut cx) {
            let arg0 = cx.argument::<JsValue>(0)?;
            let arg0_value :TransactionSignatures = neon_serde::from_value(&mut cx, arg0).throw(&mut cx)?;
            let value;
            {
            let mut this = cx.this();
            let guard = cx.lock();
            let mut thishandler = this.borrow_mut(&guard);

            //grab input
            value = thishandler.add_signatures(arg0_value);
            }
            if value.is_ok(){
                Ok(cx.boolean(true).upcast())
            }else{
                cx.throw_error(value.err().unwrap().to_string())
            }
        }

        method finalize(mut cx) {
            let value;
            {
            let mut this = cx.this();
            let guard = cx.lock();
            let mut thishandler = this.borrow_mut(&guard);
            //grab input
            value = thishandler.finalize();
            }
            if value.is_ok(){
                let js_value = neon_serde::to_value(&mut cx, &value.unwrap()).throw(&mut cx)?;
                Ok(js_value)
            }else{
                cx.throw_error(value.err().unwrap().to_string())
            }
        }
    }
}

register_module!(mut m, {
    m.export_class::<JsZcashBuilder>("zcashtools")?;
    m.export_function("get_inittx_data", get_inittx_data)?;
    Ok(())
});
