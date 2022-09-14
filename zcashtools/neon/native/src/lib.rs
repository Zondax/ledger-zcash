use neon::prelude::*;

use std::path::Path;

use ledger_zcash::zcash::primitives::consensus::TestNetwork;
use ledger_zcash::zcash::primitives::{
    consensus, transaction,
    transaction::components::{sapling as sapling_ledger, transparent as transparent_ledger},
};
use neon_serde::ResultExt;
use rand_core::OsRng;
use zcash_hsmbuilder as ZcashBuilder;
use zcash_hsmbuilder::data::{
    HsmTxData, InitData, OutputBuilderInfo, SpendBuilderInfo, TransactionSignatures,
    TransparentInputBuilderInfo, TransparentOutputBuilderInfo,
};
use zcash_hsmbuilder::errors::Error;
use zcash_hsmbuilder::txbuilder::hsmauth::MixedAuthorization;
use zcash_hsmbuilder::{hsmauth, txprover};
use zcash_primitives;
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

pub struct ZcashBuilderBridge {
    unauth_zcashbuilder:
        ZcashBuilder::txbuilder::Builder<TestNetwork, OsRng, hsmauth::Unauthorized>,
    auth_zcashbuilder: Option<
        ZcashBuilder::txbuilder::Builder<
            TestNetwork,
            OsRng,
            MixedAuthorization<transparent_ledger::Authorized, sapling_ledger::Authorized>,
        >,
    >,
}

pub enum AuthorisationStatus {
    Unauthorized(ZcashBuilder::txbuilder::Builder<TestNetwork, OsRng, hsmauth::Unauthorized>),
    TransparentAuthorized(
        ZcashBuilder::txbuilder::Builder<
            TestNetwork,
            OsRng,
            hsmauth::MixedAuthorization<transparent_ledger::Authorized, hsmauth::sapling::Unauthorized>,
        >,
    ),
    SaplingAuthorized(
        ZcashBuilder::txbuilder::Builder<
            TestNetwork,
            OsRng,
            hsmauth::MixedAuthorization<hsmauth::transparent::Unauthorized, sapling_ledger::Authorized>,
        >,
    ),
    Authorized(
        ZcashBuilder::txbuilder::Builder<
            TestNetwork,
            OsRng,
            hsmauth::MixedAuthorization<transparent_ledger::Authorized, sapling_ledger::Authorized>,
        >,
    ),
}

pub struct BuilderBridge<'a> {
    zcashbuilder: &'a mut AuthorisationStatus,
}

impl<'a> BuilderBridge<'a> {
    pub fn add_transparent_input(&mut self, t: TransparentInputBuilderInfo) -> Result<(), Error> {
        let res : Result<(), Error>;
        match self.zcashbuilder {
            AuthorisationStatus::Unauthorized(builder) => {
                res = builder.add_transparent_input(
                    t.pk,
                    t.outp,
                    TxOut {
                        value: t.value,
                        script_pubkey: t.address,
                    },
                )
            }
            AuthorisationStatus::Authorized { .. } => return Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            _ => res = Err(Error::UnknownAuthorization),
        }
        .expect("Error: Unrecognized authorisation status");
        res
    }

    pub fn add_transparent_output(
        &mut self,
        input: TransparentOutputBuilderInfo,
    ) -> Result<(), Error> {
        let res: Result<(), Error>;
        match self.zcashbuilder {
            AuthorisationStatus::Unauthorized(builder) => {
                res = builder
                    .add_transparent_output(input.address, input.value);
            }
            AuthorisationStatus::Authorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::AlreadyAuthorized),
            _ => res = Err(Error::UnknownAuthorization),
        }
        .expect("Error: Unrecognized authorisation status");
        res
    }

    pub fn add_sapling_spend(&mut self, input: SpendBuilderInfo) -> Result<(), Error> {
        let res: Result<(), Error>;
        match self.zcashbuilder {
            AuthorisationStatus::Unauthorized { .. } => {
                let div = *input.address.diversifier();
                let pk_d = *input.address.pk_d();
                let note = ledger_zcash::zcash::primitives::sapling::Note {
                    value: u64::from(input.value),
                    g_d: div.g_d().unwrap(),
                    pk_d,
                    rseed: input.rseed,
                };
                res = self.zcashbuilder.add_sapling_spend(
                    div,
                    note,
                    input.witness,
                    input.alpha,
                    input.proofkey,
                    input.rcv,
                )
            }
            AuthorisationStatus::Authorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::AlreadyAuthorized),
            _ => res = Err(Error::UnknownAuthorization),
        }
        .expect("Error: Unrecognized authorisation status");
        res
    }

    pub fn add_sapling_output(&mut self, input: OutputBuilderInfo) -> Result<(), Error> {
        let res: Result<(), Error>;
        match self.zcashbuilder {
            AuthorisationStatus::Unauthorized { .. } => {
                res = self.zcashbuilder.add_sapling_output(
                    input.ovk,
                    input.address,
                    input.value,
                    input.memo,
                    input.rcv,
                    input.rseed,
                    input.hash_seed,
                );
            }
            AuthorisationStatus::Authorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::AlreadyAuthorized),
            _ => res = Err(Error::UnknownAuthorization),
        }
        .expect("Error: Unrecognized authorisation status");
        res
    }

    pub fn build(&mut self, spendpath: &String, outputpath: &String) -> Result<HsmTxData, Error> {
        let res: Result<HsmTxData, Error>;
        match self.zcashbuilder {
            AuthorisationStatus::Unauthorized { .. } => {
                let mut prover =
                    txprover::LocalTxProver::new(Path::new(spendpath), Path::new(outputpath));
                res = self
                    .zcashbuilder
                    .build(consensus::BranchId::Sapling, &mut prover);
            }
            AuthorisationStatus::Authorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::AlreadyAuthorized),
            _ => res = Err(Error::UnknownAuthorization),
        }
        .expect("Error: Unrecognized authorisation status");
        res
    }

    pub fn add_signatures(&mut self, input: TransactionSignatures) -> Result<(), Error> {
        let res: Result<(), Error>;
        match self.zcashbuilder {
            AuthorisationStatus::Unauthorized { .. } => {
                let builder_authorize_z = self.zcashbuilder.add_signatures_spend(input.spend_sigs);
                if builder_authorize_z.is_err() {
                    return Err(builder_authorize_z.err().unwrap());
                }
                let builder_authorize_t = builder_authorize_z
                    .unwrap()
                    .add_signatures_transparent(input.transparent_sigs);
                if builder_authorize_t.is_err() {
                    return Err(builder_authorize_t.err().unwrap());
                }
                self.zcashbuilder = builder_authorize_t;
                res = Ok(())
            }
            AuthorisationStatus::Authorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::AlreadyAuthorized),
            _ => res = Err(Error::UnknownAuthorization),
        }
        .expect("Error: Unrecognized authorisation status");
        res
    }

    pub fn finalize(&mut self) -> Result<Vec<u8>, Error> {
        let res: Result<Vec<u8>, Error>;
        match self.zcashbuilder {
            AuthorisationStatus::Authorized { .. } => {
                if self.zcashbuilder.is_none() {
                    return Err(Error::Finalization);
                }
                res = self.zcashbuilder.as_ref().unwrap().finalize_js()
            }
            AuthorisationStatus::Unauthorized { .. } => res = Err(Error::UnAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => res = Err(Error::UnAuthorized),
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::UnAuthorized),
            _ => res = Err(Error::UnknownAuthorization),
        }
        .expect("Error: Unrecognized authorisation status");
        res
    }
}

declare_types! {
    pub class JsBuilder for BuilderBridge {
        init(mut cx) {
            let f = cx.argument::<JsNumber>(0)?.value();
            let mut zcashbuilder = ZcashBuilder::txbuilder::Builder::new_with_fee(TestNetwork, 0, f as u64);
            Ok(BuilderBridge {
                zcashbuilder: zcashbuilder,
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
    m.export_class::<JsBuilder>("zcashtools")?;
    m.export_function("get_inittx_data", get_inittx_data)?;
    Ok(())
});
