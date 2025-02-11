use wasm_bindgen::prelude::*;

use ledger_zcash_chain_builder::data::{
    HsmTxData, InitData, OutputBuilderInfo, SpendBuilderInfo, TransactionSignatures,
    TransparentInputBuilderInfo, TransparentOutputBuilderInfo,
};
use ledger_zcash_chain_builder::errors::Error;
use ledger_zcash_chain_builder::{hsmauth, txbuilder, txprover};

use zcash_primitives::consensus::TestNetwork;
use zcash_primitives::{
    consensus, sapling,
    transaction::components::{
        sapling as sapling_ledger, transparent as transparent_ledger, TxOut,
    },
    transaction::TxVersion,
};

use rand_core::OsRng;

#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = r#"
// Pure type definition
type GrowToSize<T, N extends number, A extends T[]> = A["length"] extends N
  ? A
  : GrowToSize<T, N, [...A, T]>;

export type FixedArray<T, N extends number> = GrowToSize<T, N, []>;

export interface TinData {
    path: FixedArray<number, 5>;
    address: string;
    value: number;
}

export interface ToutData {
    address: string;
    value: number;
}

export interface SaplingSpendData {
  path: number,
  address: string,
  value: number,
}

export interface SaplingOutputData {
  ovk: string | null,
  address: string,
  value: number,
  memo_type: number,
}

export interface InitData {
  t_in: TinData[],
  t_out: ToutData[],
  s_spend: SaplingSpendData[],
  s_output: SaplingOutputData[],
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const INIT_TX_SIGNATURE: &'static str = r#"
export function get_inittx_data(input: InitData): Uint8Array;
"#;

#[wasm_bindgen(skip_typescript)]
pub fn get_inittx_data(input: JsValue) -> Result<JsValue, JsError> {
    let arg0_value: InitData = serde_wasm_bindgen::from_value(input)
        .map_err(|e| JsError::new(&format!("Failed to deserialize input: {}", e)))?;
    
    let output = arg0_value.to_hsm_bytes();
    
    Ok(serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsError::new(&format!("Failed to serialize output: {}", e)))?)
}


#[wasm_bindgen]
pub fn calculate_zip0317_fee(n_tin: u32, n_tout: u32, n_spend: u32, n_sout: u32) -> u64 {
    ledger_zcash_app_builder::builder::Builder::calculate_zip0317_fee(
        n_tin as usize,
        n_tout as usize,
        n_spend as usize,
        n_sout as usize,
    ).into()
}

pub enum AuthorisationStatus {
    Unauthorized(txbuilder::Builder<TestNetwork, OsRng, hsmauth::Unauthorized>),
    TransparentAuthorized(
        txbuilder::Builder<
            TestNetwork,
            OsRng,
            hsmauth::MixedAuthorization<
                transparent_ledger::Authorized,
                hsmauth::sapling::Unauthorized,
            >,
        >,
    ),
    SaplingAuthorized(
        txbuilder::Builder<
            TestNetwork,
            OsRng,
            hsmauth::MixedAuthorization<
                hsmauth::transparent::Unauthorized,
                sapling_ledger::Authorized,
            >,
        >,
    ),
    Authorized(
        txbuilder::Builder<
            TestNetwork,
            OsRng,
            hsmauth::MixedAuthorization<transparent_ledger::Authorized, sapling_ledger::Authorized>,
        >,
    ),
    Taken,
}

pub struct ZcashBuilderBridge {
    zcashbuilder: AuthorisationStatus,
}


impl ZcashBuilderBridge {
    pub fn new(builder: txbuilder::Builder<TestNetwork, OsRng, hsmauth::Unauthorized>) -> Self {
        ZcashBuilderBridge {
            zcashbuilder: AuthorisationStatus::Unauthorized(builder),
        }
    }
}

// Internal implementation
impl ZcashBuilderBridge {
    pub fn add_transparent_input(&mut self, t: TransparentInputBuilderInfo) -> Result<(), Error> {
        match std::mem::replace(&mut self.zcashbuilder, AuthorisationStatus::Taken) {
            AuthorisationStatus::Unauthorized(mut builder) => {
                let res = builder.add_transparent_input(
                    t.pk,
                    t.outp,
                    TxOut {
                        value: t.value,
                        script_pubkey: t.address,
                    },
                );
                match res {
                    Ok(()) => self.zcashbuilder = AuthorisationStatus::Unauthorized(builder),
                    Err(_) => (),
                }
                res
            }
            AuthorisationStatus::Authorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::SaplingAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken => Err(Error::UnknownAuthorization),
        }
    }

    pub fn add_transparent_output(
        &mut self,
        input: TransparentOutputBuilderInfo,
    ) -> Result<(), Error> {
        match std::mem::replace(&mut self.zcashbuilder, AuthorisationStatus::Taken) {
            AuthorisationStatus::Unauthorized(mut builder) => {
                let res = builder.add_transparent_output(input.address, input.value);
                match res {
                    Ok(()) => self.zcashbuilder = AuthorisationStatus::Unauthorized(builder),
                    Err(_) => (),
                }
                res
            }
            AuthorisationStatus::Authorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::SaplingAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken => Err(Error::UnknownAuthorization),
        }
    }

    pub fn add_sapling_spend(&mut self, input: SpendBuilderInfo) -> Result<(), Error> {
        match std::mem::replace(&mut self.zcashbuilder, AuthorisationStatus::Taken) {
            AuthorisationStatus::Unauthorized(mut builder) => {
                let div = *input.address.diversifier();
                let pk_d = *input.address.pk_d();
                let note = sapling::Note {
                    value: u64::from(input.value),
                    g_d: div.g_d().unwrap(),
                    pk_d,
                    rseed: input.rseed,
                };
                let res = builder.add_sapling_spend(
                    div,
                    note,
                    input.witness,
                    input.alpha,
                    input.proofkey,
                    input.rcv,
                );
                match res {
                    Ok(()) => self.zcashbuilder = AuthorisationStatus::Unauthorized(builder),
                    Err(_) => (),
                }
                res
            }
            AuthorisationStatus::Authorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::SaplingAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken => Err(Error::UnknownAuthorization),
        }
    }

    pub fn add_sapling_output(&mut self, input: OutputBuilderInfo) -> Result<(), Error> {
        match std::mem::replace(&mut self.zcashbuilder, AuthorisationStatus::Taken) {
            AuthorisationStatus::Unauthorized(mut builder) => {
                let res = builder.add_sapling_output(
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
                    Err(_) => (),
                }
                res
            }
            AuthorisationStatus::Authorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::SaplingAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken => Err(Error::UnknownAuthorization),
        }
    }

    pub fn build(
        &mut self,
        spendbin: Vec<u8>,
        outputbin: Vec<u8>,
        tx_version: u8,
    ) -> Result<HsmTxData, Error> {
        let tx_ver = match tx_version {
            4 => Some(TxVersion::Sapling),
            5 => Some(TxVersion::Zip225),
            _ => None,
        };
        log::info!("tx_ver is {:#?}", tx_ver);
        match std::mem::replace(&mut self.zcashbuilder, AuthorisationStatus::Taken) {
            AuthorisationStatus::Unauthorized(mut builder) => {
                let mut prover =
                    txprover::LocalTxProver::from_bytes(&spendbin, &outputbin);
                let res = builder.build(consensus::BranchId::Nu6, tx_ver, &mut prover);
                match res {
                    Ok(_) => self.zcashbuilder = AuthorisationStatus::Unauthorized(builder),
                    Err(ref e) => {
                        log::error!("Error in build {:?}", e.to_string());
                    }
                }
                res
            }
            AuthorisationStatus::Authorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::SaplingAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken => Err(Error::UnknownAuthorization),
        }
    }

    pub fn add_signatures(&mut self, input: TransactionSignatures) -> Result<(), Error> {
        match std::mem::replace(&mut self.zcashbuilder, AuthorisationStatus::Taken) {
            AuthorisationStatus::Unauthorized(builder) => {
                let builder_authorize_z = builder.add_signatures_spend(input.sapling_sigs);
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
                Ok(())
            }
            AuthorisationStatus::Authorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::SaplingAuthorized { .. } => Err(Error::AlreadyAuthorized),
            AuthorisationStatus::Taken => Err(Error::UnknownAuthorization),
        }
    }

    pub fn finalize_builder(&mut self) -> Result<Vec<u8>, Error> {
        match std::mem::replace(&mut self.zcashbuilder, AuthorisationStatus::Taken) {
            AuthorisationStatus::Authorized(mut builder) => builder.finalize_js(),
            AuthorisationStatus::Unauthorized { .. } => Err(Error::Unauthorized),
            AuthorisationStatus::TransparentAuthorized { .. } => Err(Error::Unauthorized),
            AuthorisationStatus::SaplingAuthorized { .. } => Err(Error::Unauthorized),
            AuthorisationStatus::Taken => Err(Error::UnknownAuthorization),
        }
    }
}


#[wasm_bindgen]
pub struct ZcashBuilder {
    inner: ZcashBuilderBridge
}

#[wasm_bindgen]
impl ZcashBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(fee: f64, height: f64) -> Self {
        let zcashbuilder = txbuilder::Builder::new_with_fee(
            TestNetwork,
            height as u32,
            fee as u64
        );
        let inner = ZcashBuilderBridge::new(zcashbuilder);
        Self { inner }
    }

    #[wasm_bindgen]
    pub fn add_transparent_input(&mut self, input: JsValue) -> Result<bool, JsError> {
        let input: TransparentInputBuilderInfo = serde_wasm_bindgen::from_value(input)
            .map_err(|e| JsError::new(&format!("Failed to deserialize input: {}", e)))?;
        
        self.inner.add_transparent_input(input)
            .map(|_| true)
            .map_err(|e| JsError::new(&e.to_string()))
    }
    #[wasm_bindgen]
    pub fn add_transparent_output(&mut self, input: JsValue) -> Result<bool, JsError> {
        let output_info: TransparentOutputBuilderInfo = serde_wasm_bindgen::from_value(input)
            .map_err(|e| JsError::new(&format!("Failed to deserialize output info: {}", e)))?;
        
        self.inner.add_transparent_output(output_info)
            .map(|_| true)
            .map_err(|e| JsError::new(&e.to_string()))
    }
    
    #[wasm_bindgen]
    pub fn add_sapling_spend(&mut self, input: JsValue) -> Result<bool, JsError> {
        let spend_info: SpendBuilderInfo = serde_wasm_bindgen::from_value(input)
            .map_err(|e| JsError::new(&format!("Failed to deserialize spend info: {}", e)))?;
        
        self.inner.add_sapling_spend(spend_info)
            .map(|_| true)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn add_sapling_output(&mut self, input: JsValue) -> Result<bool, JsError> {
        let output_info: OutputBuilderInfo = serde_wasm_bindgen::from_value(input)
            .map_err(|e| JsError::new(&format!("Failed to deserialize output info: {}", e)))?;
        
        self.inner.add_sapling_output(output_info)
            .map(|_| true)
            .map_err(|e| JsError::new(&e.to_string()))
    }
    
    #[wasm_bindgen]
    pub fn build(&mut self, spendbin: Vec<u8>, outputbin: Vec<u8>, tx_version: u8) -> Result<JsValue, JsError> {
        let result = self.inner.build(spendbin, outputbin, tx_version)?;
        Ok(serde_wasm_bindgen::to_value(&result.to_hsm_bytes().unwrap())
            .map_err(|e| JsError::new(&format!("Failed to serialize output: {}", e)))?)
    }
    #[wasm_bindgen]
    pub fn add_signatures(&mut self, input: JsValue) -> Result<bool, JsError> {
        let signatures: TransactionSignatures = serde_wasm_bindgen::from_value(input)
            .map_err(|e| JsError::new(&format!("Failed to deserialize signatures: {}", e)))?;
        
        match self.inner.add_signatures(signatures) {
            Ok(_) => Ok(true),
            Err(e) => Err(JsError::new(&e.to_string()))
        }
    }
    
    #[wasm_bindgen]
    pub fn finalize(&mut self) -> Result<Vec<u8>, JsError> {
        self.inner.finalize_builder()
            .map_err(|e| JsError::new(&e.to_string()))
    }
}

// Remove the neon::main and replace with wasm_bindgen initialization if needed
#[wasm_bindgen(start)]
pub fn main() {
    #[cfg(target_arch = "wasm32")]
    // Initialize panic hook for better error messages
    console_error_panic_hook::set_once();
}