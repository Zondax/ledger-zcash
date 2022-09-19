use neon::prelude::*;
use std::cell::RefCell;
use std::path::Path;
use std::borrow::BorrowMut;

use ledger_zcash::zcash::primitives::consensus::TestNetwork;
use ledger_zcash::zcash::primitives::{
    consensus,
    transaction::components::{sapling as sapling_ledger, transparent as transparent_ledger},
};
use rand_core::OsRng;
use zcash_hsmbuilder as ZcashBuilder;
use zcash_hsmbuilder::data::{
    HsmTxData, InitData, OutputBuilderInfo, SpendBuilderInfo, TransactionSignatures,
    TransparentInputBuilderInfo, TransparentOutputBuilderInfo,
};
use zcash_hsmbuilder::errors::Error;
use zcash_hsmbuilder::{hsmauth, txprover};
use zcash_primitives;
use zcash_primitives::transaction::components::TxOut;

// reference
// https://neon-bindings.com/docs/primitives

//bridge stuff only

fn get_inittx_data(mut cx: FunctionContext) -> JsResult<JsValue> {
    // First get call arguments
    let arg0 = cx.argument::<JsValue>(0)?;
    //let arg0_value: InitData = neon_serde::from_value(&mut cx, arg0).throw(&mut cx)?;
    let arg0_value: InitData = neon_serde::from_value(&mut cx, arg0).expect("Error getting arg0_value");
    let output = arg0_value.to_hsm_bytes();
    let js_value;
    //js_value = neon_serde::to_value(&mut cx, &output).throw(&mut cx)?;
    js_value = neon_serde::to_value(&mut cx, &output).expect("Error getting js_value");
    Ok(js_value)
}


type BoxedBuilder = JsBox<RefCell<ZcashBuilderBridge>>;

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
    Taken(),
}

pub struct ZcashBuilderBridge {
    zcashbuilder: AuthorisationStatus,
}

impl Finalize for ZcashBuilderBridge{}

// Internal implementation
impl ZcashBuilderBridge {
    pub fn add_transparent_input(&mut self, t: TransparentInputBuilderInfo) -> Result<(), Error> {
        let res : Result<(), Error>;
        match std::mem::replace(&mut self.zcashbuilder, self::AuthorisationStatus::Taken()) {
            AuthorisationStatus::Unauthorized(mut builder) => {
                res = builder.add_transparent_input(
                    t.pk,
                    t.outp,
                    TxOut {
                        value: t.value,
                        script_pubkey: t.address,
                    },
                );
                match res {
                    Ok(()) => self.zcashbuilder = AuthorisationStatus::Unauthorized(builder),
                    Err(_) => ()
                }
            }
            AuthorisationStatus::Authorized { .. } => return Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            },
            AuthorisationStatus::Taken { .. } => {
                res = Err(Error::UnknownAuthorization)
            },
        };
        res
    }

    pub fn add_transparent_output(
        &mut self,
        input: TransparentOutputBuilderInfo,
    ) -> Result<(), Error> {
        let res: Result<(), Error>;
        match std::mem::replace(&mut self.zcashbuilder, self::AuthorisationStatus::Taken()) {
            AuthorisationStatus::Unauthorized(mut builder) => {
                res = builder
                    .add_transparent_output(input.address, input.value);
                match res {
                    Ok(()) => self.zcashbuilder = AuthorisationStatus::Unauthorized(builder),
                    Err(_) => ()
                }
            }
            AuthorisationStatus::Authorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken { .. } => {
                res = Err(Error::UnknownAuthorization)
            },
        };
        res
    }

    pub fn add_sapling_spend(&mut self, input: SpendBuilderInfo) -> Result<(), Error> {
        let res: Result<(), Error>;
        match std::mem::replace(&mut self.zcashbuilder, self::AuthorisationStatus::Taken()) {
            AuthorisationStatus::Unauthorized(mut builder)=> {
                let div = *input.address.diversifier();
                let pk_d = *input.address.pk_d();
                let note = ledger_zcash::zcash::primitives::sapling::Note {
                    value: u64::from(input.value),
                    g_d: div.g_d().unwrap(),
                    pk_d,
                    rseed: input.rseed,
                };
                res = builder.add_sapling_spend(
                    div,
                    note,
                    input.witness,
                    input.alpha,
                    input.proofkey,
                    input.rcv,
                );
                match res {
                    Ok(()) => self.zcashbuilder = AuthorisationStatus::Unauthorized(builder),
                    Err(_) => ()
                }
            }
            AuthorisationStatus::Authorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken { .. } => {
                res = Err(Error::UnknownAuthorization)
            },
        };
        res
    }

    pub fn add_sapling_output(&mut self, input: OutputBuilderInfo) -> Result<(), Error> {
        let res: Result<(), Error>;
        match std::mem::replace(&mut self.zcashbuilder, self::AuthorisationStatus::Taken()) {
            AuthorisationStatus::Unauthorized (mut builder) => {
                res = builder.add_sapling_output(
                    input.ovk,
                    input.address,
                    input.value,
                    input.memo,
                    input.rcv,
                    input.rseed,
                    input.hash_seed,
                );
                match res {
                    Ok(()) => self.zcashbuilder = AuthorisationStatus::Unauthorized(builder),
                    Err(_) => ()
                }
            }
            AuthorisationStatus::Authorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken { .. } => {
                res = Err(Error::UnknownAuthorization)
            },
        };
        res
    }

    pub fn build(&mut self, spendpath: &String, outputpath: &String) -> Result<HsmTxData, Error> {
        let res: Result<HsmTxData, Error>;
        match std::mem::replace(&mut self.zcashbuilder, self::AuthorisationStatus::Taken()) {
            AuthorisationStatus::Unauthorized( mut builder) => {
                let mut prover =
                    txprover::LocalTxProver::new(Path::new(spendpath), Path::new(outputpath));
                res = builder.build(consensus::BranchId::Sapling, &mut prover);
                match res {
                    Ok(_) => self.zcashbuilder = AuthorisationStatus::Unauthorized(builder),
                    Err(_) => ()
                }
            }
            AuthorisationStatus::Authorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken { .. } => {
                res = Err(Error::UnknownAuthorization)
            },
        };
        res
    }

    pub fn add_signatures(&mut self, input: TransactionSignatures) -> Result<(), Error> {
        let res: Result<(), Error>;
        match std::mem::replace(&mut self.zcashbuilder, self::AuthorisationStatus::Taken()) {
            AuthorisationStatus::Unauthorized (builder) => {
                let builder_authorize_z =
                    builder.add_signatures_spend(input.spend_sigs);
                if builder_authorize_z.is_err() {
                    return Err(builder_authorize_z.err().unwrap());
                }
                let builder_authorize_t = builder_authorize_z
                    .unwrap()
                    .add_signatures_transparent(input.transparent_sigs);
                match builder_authorize_t {
                    Ok(b) => self.zcashbuilder = AuthorisationStatus::Authorized(b),
                    Err(err) => return Err(err),
                };
                res = Ok(())
            }
            AuthorisationStatus::Authorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => {
                res = Err(Error::AlreadyAuthorized)
            }
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken { .. } => {
                res = Err(Error::UnknownAuthorization)
            },
        };
        res
    }

    pub fn finalize_builder(&mut self) -> Result<Vec<u8>, Error> {
        let res: Result<Vec<u8>, Error>;
        match std::mem::replace(&mut self.zcashbuilder, self::AuthorisationStatus::Taken()) {
            AuthorisationStatus::Authorized (mut builder) => {
                res = builder.finalize_js()
            }
            AuthorisationStatus::Unauthorized { .. } => res = Err(Error::Unauthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => res = Err(Error::Unauthorized),
            AuthorisationStatus::SaplingAuthorized { .. } => res = Err(Error::Unauthorized),
            AuthorisationStatus::Taken { .. } => {
                res = Err(Error::UnknownAuthorization)
            },
        };
        res
    }
}

// Methods exposed to javascript
impl ZcashBuilderBridge {
    fn js_create_builder(mut cx: FunctionContext) -> JsResult<JsBox<ZcashBuilderBridge>> {
        let f = cx.argument::<JsNumber>(0)?.value(&mut cx);
        let zcashbuilder = ZcashBuilder::txbuilder::Builder::new_with_fee(TestNetwork, 0, f as u64);
        let zcashbuilder = AuthorisationStatus::Unauthorized(zcashbuilder);
        Ok(
            cx.boxed(
                ZcashBuilderBridge {
                    zcashbuilder,
                }))
    }

    fn js_add_transparent_input(mut cx: FunctionContext) -> JsResult<JsBoolean> {
        let arg0 = cx.argument::<JsValue>(0)?;
        let arg0_value: TransparentInputBuilderInfo = neon_serde::from_value(&mut cx, arg0)
            .expect("Failled to get arg0_value for transparent builder");
        let value;
        {
            // let mut this = cx.this();
            let mut this = cx.this().downcast_or_throw::<JsBox<ZcashBuilderBridge>, _>(&mut cx)?;
            //let guard = cx.lock();
            let mut this_handler = this.borrow_mut();//(&guard);

            //grab input
            value = this_handler.add_transparent_input(arg0_value);
        }
        if value.is_ok() {
            Ok(cx.boolean(true))
        } else {
            cx.throw_error(value.err().unwrap().to_string())
        }
    }

    fn js_add_transparent_output(mut cx: FunctionContext)->JsResult<JsBoolean>{
        let arg0 = cx.argument::<JsValue>(0)?;
        let arg0_value :TransparentOutputBuilderInfo = neon_serde::from_value(&mut cx, arg0)
            .expect("Failled to get arg0_value for transparent output builder");

        let value;
        {
            let mut this = cx.this().downcast_or_throw::<JsBox<ZcashBuilderBridge>, _>(&mut cx)?;
            //let guard = cx.lock();
            let mut thishandler = this.borrow_mut();//(&guard);

            //grab input
            value = thishandler.add_transparent_output(arg0_value);
        }
        if value.is_ok(){
            Ok(cx.boolean(true))
        }else{
            cx.throw_error(value.err().unwrap().to_string())
        }
    }
    fn js_add_sapling_spend(mut cx: FunctionContext)->JsResult<JsBoolean>{
        let arg0 = cx.argument::<JsValue>(0)?;
        let arg0_value :SpendBuilderInfo = neon_serde::from_value(&mut cx, arg0)
            .expect("Failled to get arg0_value for sapling spend");
        let value;
        {
            let mut this = cx.this().downcast_or_throw::<JsBox<ZcashBuilderBridge>, _>(&mut cx)?;
            //let guard = cx.lock();
            let mut thishandler = this.borrow_mut();//(&guard);

            //grab input
            value = thishandler.add_sapling_spend(arg0_value);
        }
        if value.is_ok(){
            Ok(cx.boolean(true))
        }else{
            cx.throw_error(value.err().unwrap().to_string())
        }
    }

    fn js_add_sapling_output(mut cx: FunctionContext)->JsResult<JsBoolean>{
        let arg0 = cx.argument::<JsValue>(0)?;
        let arg0_value :OutputBuilderInfo = neon_serde::from_value(&mut cx, arg0)
            .expect("Failled to get arg0_value for sapling output");

        let value;
        {
            let mut this = cx.this().downcast_or_throw::<JsBox<ZcashBuilderBridge>, _>(&mut cx)?;
            //let guard = cx.lock();
            let mut thishandler = this.borrow_mut();//(&guard);

            //grab input
            value = thishandler.add_sapling_output(arg0_value);
        }
        if value.is_ok(){
            Ok(cx.boolean(true))
        }else{
            cx.throw_error(value.err().unwrap().to_string())
        }
    }
    fn js_build(mut cx: FunctionContext)->JsResult<JsValue>{
        let spendpath: String = cx.argument::<JsString>(0)?.value(&mut cx);
        let outputpath: String = cx.argument::<JsString>(1)?.value(&mut cx);
        let value;
        {
            let mut this = cx.this().downcast_or_throw::<JsBox<ZcashBuilderBridge>, _>(&mut cx)?;
            //let guard = cx.lock();
            let mut thishandler = this.borrow_mut();//(&guard);

            //grab input
            value = thishandler.build(&spendpath, &outputpath);
        }
        if value.is_ok(){
            let js_value = neon_serde::to_value(&mut cx, &value.unwrap().to_hsm_bytes().unwrap())
                .expect("Failed to get js_value for js_build");

            Ok(js_value)
        }else{
            cx.throw_error(value.err().unwrap().to_string())
        }
    }

    fn js_add_signatures(mut cx: FunctionContext)->JsResult<JsBoolean>{
        let arg0 = cx.argument::<JsValue>(0)?;
        let arg0_value :TransactionSignatures = neon_serde::from_value(&mut cx, arg0)
            .expect("Failed to get js_value for js_add_signatures");

        let value;
        {
            let mut this = cx.this().downcast_or_throw::<JsBox<ZcashBuilderBridge>, _>(&mut cx)?;
            //let guard = cx.lock();
            let mut thishandler = this.borrow_mut();//(&guard);

            //grab input
            value = thishandler.add_signatures(arg0_value);
        }
        if value.is_ok(){
            Ok(cx.boolean(true))
        }else{
            cx.throw_error(value.err().unwrap().to_string())
        }
    }
    fn js_finalize(mut cx: FunctionContext)->JsResult<JsValue>{
        let mut this = cx.this().downcast_or_throw::<JsBox<ZcashBuilderBridge>, _>(&mut cx)?;
            //let guard = cx.lock();
        let mut thishandler = this.borrow_mut();//(&guard);
            //grab input
        let value = thishandler.finalize_builder();

        match value {
            Ok(val) => {
                let js_value = neon_serde::to_value(&mut cx, &val)
                    .expect("Failed to get js_value for js_afinalize");
                Ok(js_value)
            },
            Err(err)=> cx.throw_error(err.to_string())
        }
    }
    }

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    //cx.export_class::<ZcashBuilderBridge>("zcashtools")?;
    cx.export_function("builderNew", ZcashBuilderBridge::js_create_builder)?;
    cx.export_function("builderAddTransparentInput", ZcashBuilderBridge::js_add_transparent_input)?;
    cx.export_function("builderAddTransparentOutput", ZcashBuilderBridge::js_add_transparent_output)?;
    cx.export_function("builderAddSaplingSpend", ZcashBuilderBridge::js_add_sapling_spend)?;
    cx.export_function("builderAddSaplingOutput", ZcashBuilderBridge::js_add_sapling_output)?;
    cx.export_function("builderBuild", ZcashBuilderBridge::js_build)?;
    cx.export_function("builderAddSignatures", ZcashBuilderBridge::js_add_signatures)?;
    cx.export_function("builderFinalize", ZcashBuilderBridge::js_finalize)?;

    Ok(())
}