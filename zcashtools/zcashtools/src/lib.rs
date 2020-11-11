#![allow(dead_code, unused_imports, unused_mut, unused_variables, clippy::too_many_arguments)]

mod neon_bridge;
mod prover_ledger;
mod sighashdata_ledger;
pub mod txbuilder_ledger;
pub mod txprover_ledger;
pub mod zcashtools_errors;

use blake2b_simd::Params as Blake2bParams;
use jubjub::AffinePoint;
use zcash_primitives::consensus;
use zcash_primitives::consensus::*;
use zcash_primitives::keys::*;
use zcash_primitives::legacy::*;
use zcash_primitives::merkle_tree::*;
use zcash_primitives::note_encryption::Memo;
use zcash_primitives::primitives::*;
use zcash_primitives::primitives::{PaymentAddress, ProofGenerationKey};
use zcash_primitives::redjubjub::*;
use zcash_primitives::sapling::*;
use zcash_primitives::transaction::components::*;
use zcash_primitives::transaction::components::{Amount, OutPoint};
use zcash_primitives::transaction::Transaction;

extern crate hex;

use crate::txprover_ledger::LocalTxProverLedger;
use group::{cofactor::CofactorCurveAffine, GroupEncoding};
use rand::RngCore;
use rand_core::OsRng;

use crate::sighashdata_ledger::TransactionDataSighash;
use crate::txbuilder_ledger::*;
use crate::zcashtools_errors::Error;

#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_derive;
use crate::neon_bridge::*;

#[derive(Debug, Deserialize)]
pub struct TinData {
    path: [u32; 5],
    #[serde(deserialize_with = "script_deserialize")]
    address: Script,
    #[serde(deserialize_with = "amount_deserialize")]
    value: Amount,
}
#[derive(Debug, Deserialize)]
pub struct ToutData {
    #[serde(deserialize_with = "script_deserialize")]
    address: Script,
    #[serde(deserialize_with = "amount_deserialize")]
    value: Amount,
}
#[derive(Debug, Deserialize)]
pub struct ShieldedSpendData {
    path: u32,
    #[serde(deserialize_with = "s_address_deserialize")]
    address: PaymentAddress,
    #[serde(deserialize_with = "amount_deserialize")]
    value: Amount,
}
#[derive(Debug, Deserialize)]
pub struct ShieldedOutputData {
    #[serde(deserialize_with = "s_address_deserialize")]
    address: PaymentAddress,
    #[serde(deserialize_with = "amount_deserialize")]
    value: Amount,
    memotype: u8,
    #[serde(deserialize_with = "ovk_deserialize")]
    ovk: Option<OutgoingViewingKey>,
}

#[derive(Debug, Deserialize)]
pub struct LedgerInitData {
    pub t_in: Vec<TinData>,
    pub t_out: Vec<ToutData>,
    pub s_spend: Vec<ShieldedSpendData>,
    pub s_output: Vec<ShieldedOutputData>,
}

impl LedgerInitData {
    pub fn to_ledger_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();

        data.push(self.t_in.len() as u8);
        data.push(self.t_out.len() as u8);
        data.push(self.s_spend.len() as u8);
        data.push(self.s_output.len() as u8);

        for info in self.t_in.iter() {
            for p in info.path.iter() {
                data.extend_from_slice(&p.to_le_bytes());
            }
            info.address.write(&mut data)?;
            data.extend_from_slice(&info.value.to_i64_le_bytes());
        }

        for info in self.t_out.iter() {
            info.address.write(&mut data)?;
            data.extend_from_slice(&info.value.to_i64_le_bytes());
        }

        for info in self.s_spend.iter() {
            data.extend_from_slice(&info.path.to_le_bytes());
            data.extend_from_slice(&info.address.to_bytes());
            data.extend_from_slice(&info.value.to_i64_le_bytes());
        }

        for info in self.s_output.iter() {
            data.extend_from_slice(&info.address.to_bytes());
            data.extend_from_slice(&info.value.to_i64_le_bytes());
            data.push(info.memotype);
            if info.ovk.is_some() {
                data.extend_from_slice(&info.ovk.unwrap().0);
            } else {
                data.extend_from_slice(&[0u8; 32]);
            }
        }
        Ok(data)
    }
}

pub struct LedgerTxData {
    pub t_script_data: Vec<TransparentScriptData>,
    pub s_spend_old_data: Vec<NullifierInput>,
    pub s_spend_new_data: Vec<SpendDescriptionLedger>,
    pub s_output_data: Vec<OutputDescriptionLedger>,
    pub tx_hash_data: TransactionDataSighash,
}

impl LedgerTxData {
    pub fn to_ledger_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        for t_data in self.t_script_data.iter() {
            t_data.write(&mut data)?;
        }
        for spend_old_data in self.s_spend_old_data.iter() {
            spend_old_data.write(&mut data)?;
        }
        for spend_new_data in self.s_spend_new_data.iter() {
            spend_new_data.write(&mut data)?;
        }
        for output_data in self.s_output_data.iter() {
            output_data.write(&mut data)?;
        }
        data.extend_from_slice(&self.tx_hash_data.to_bytes());
        Ok(data)
    }
}

pub struct ZcashBuilderLedger {
    secret_key: Option<[u8; 32]>,
    public_key: Option<[u8; 32]>,
    session_key: Option<[u8; 32]>,
    numtransparentinputs: usize,
    numtransparentoutputs: usize,
    numspends: usize,
    numoutputs: usize,
    builder: txbuilder_ledger::Builder<TestNetwork, OsRng>,
    branch: consensus::BranchId,
}

#[derive(Debug, Deserialize)]
pub struct TransparentInputBuilderInfo {
    #[serde(deserialize_with = "outpoint_deserialize")]
    pub outp: OutPoint,
    #[serde(deserialize_with = "t_pk_deserialize")]
    pub pk: secp256k1::PublicKey,
    #[serde(deserialize_with = "script_deserialize")]
    pub address: Script,
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount,
}

#[derive(Debug, Deserialize)]
pub struct TransparentOutputBuilderInfo {
    #[serde(deserialize_with = "script_deserialize")]
    pub address: Script, //26
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount, //8
}

#[derive(Deserialize)]
pub struct SpendBuilderInfo {
    #[serde(deserialize_with = "pgk_deserialize")]
    pub proofkey: ProofGenerationKey,
    #[serde(deserialize_with = "fr_deserialize")]
    pub rcv: jubjub::Fr,
    #[serde(deserialize_with = "fr_deserialize")]
    pub alpha: jubjub::Fr,
    #[serde(deserialize_with = "ovk_deserialize")]
    pub ovk: Option<OutgoingViewingKey>,
    #[serde(deserialize_with = "s_address_deserialize")]
    pub address: PaymentAddress,
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount,
    #[serde(deserialize_with = "witness_deserialize")]
    pub witness: IncrementalWitness<Node>,
    #[serde(deserialize_with = "rseed_deserialize")]
    pub rseed: Rseed,
}

#[derive(Debug, Deserialize)]
pub struct OutputBuilderInfo {
    #[serde(deserialize_with = "fr_deserialize")]
    pub rcv: jubjub::Fr,
    #[serde(deserialize_with = "rseed_deserialize")]
    pub rseed: Rseed,
    #[serde(deserialize_with = "ovk_deserialize")]
    pub ovk: Option<OutgoingViewingKey>,
    #[serde(deserialize_with = "s_address_deserialize")]
    pub address: PaymentAddress,
    #[serde(deserialize_with = "amount_deserialize")]
    pub value: Amount,
    #[serde(deserialize_with = "memo_deserialize")]
    pub memo: Option<Memo>,
}

#[derive(Debug, Deserialize)]
pub struct TransactionSignatures {
    #[serde(deserialize_with = "t_sig_deserialize")]
    pub transparent_sigs: Vec<secp256k1::Signature>,
    #[serde(deserialize_with = "s_sig_deserialize")]
    pub spend_sigs: Vec<Signature>,
}

impl ZcashBuilderLedger {
    pub fn new(fee: u64) -> ZcashBuilderLedger {
        ZcashBuilderLedger {
            secret_key: None,
            public_key: None,
            session_key: None,
            numtransparentinputs: 0,
            numtransparentoutputs: 0,
            numspends: 0,
            numoutputs: 0,
            builder: txbuilder_ledger::Builder::<TestNetwork, OsRng>::new_with_fee(0, fee),
            branch: consensus::BranchId::Sapling,
        }
    }

    pub fn get_public_key(&mut self) -> Result<Vec<u8>, Error> {
        if self.secret_key == None || self.public_key == None {
            return Err(Error::BuilderNoKeys);
        }
        let mut v: Vec<u8> = Vec::with_capacity(32);
        v.extend_from_slice(&self.public_key.unwrap());
        Ok(v)
    }

    pub fn keygen(&mut self) {
        let mut rng = OsRng;
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let f = jubjub::Fr::from_bytes_wide(&bytes);
        let p = AffinePoint::generator() * f;
        self.secret_key = Some(f.to_bytes());
        self.public_key = Some(p.to_bytes());
    }

    pub fn set_session_key(&mut self, input: &[u8]) -> Result<(), Error> {
        if self.secret_key == None || self.public_key == None {
            return Err(Error::BuilderNoKeys);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(input);
        let pubclient = AffinePoint::from_bytes(bytes).unwrap().mul_by_cofactor();
        let f = jubjub::Fr::from_bytes(&self.secret_key.unwrap()).unwrap();
        let session_jubjub = pubclient * f;

        pub const PRF_SESSION_PERSONALIZATION: &[u8; 16] = b"Zcash_SessionKey";
        let h = Blake2bParams::new()
            .hash_length(32)
            .personal(PRF_SESSION_PERSONALIZATION)
            .hash(&session_jubjub.to_bytes());

        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&h.as_bytes());
        assert_ne!(session_key, [0u8; 32]);
        self.session_key = Some(session_key);
        Ok(())
    }

    pub fn add_transparent_input(
        &mut self,
        info: TransparentInputBuilderInfo,
    ) -> Result<(), Error> {
        let coin = TxOut {
            value: info.value,
            script_pubkey: info.address,
        };
        let r = self.builder.add_transparent_input(info.pk, info.outp, coin);
        if r.is_ok() {
            self.numtransparentinputs += 1;
        }
        r
    }

    pub fn add_transparent_output(
        &mut self,
        info: TransparentOutputBuilderInfo,
    ) -> Result<(), Error> {
        let r = self
            .builder
            .add_transparent_output(info.address, info.value);
        if r.is_ok() {
            self.numtransparentoutputs += 1;
        }
        r
    }

    pub fn add_sapling_spend(&mut self, info: SpendBuilderInfo) -> Result<(), Error> {
        //todo: add decryption here
        let note = info
            .address
            .create_note(u64::from(info.value), info.rseed)
            .unwrap();

        let r = self.builder.add_sapling_spend(
            *info.address.diversifier(),
            note,
            info.witness.path().unwrap(),
            info.alpha,
            info.proofkey,
            info.ovk,
            info.rcv,
        );
        if r.is_ok() {
            self.numspends += 1;
        }
        r
    }

    pub fn add_sapling_output(&mut self, info: OutputBuilderInfo) -> Result<(), Error> {
        //todo: add decryption here
        let r = self.builder.add_sapling_output(
            info.ovk,
            info.address,
            info.value,
            info.memo,
            info.rcv,
            info.rseed,
        );
        if r.is_ok() {
            self.numoutputs += 1;
        }
        r
    }

    pub fn build(&mut self, prover: &mut LocalTxProverLedger) -> Result<Vec<u8>, Error> {
        let r = self.builder.build(self.branch, prover);
        match r.is_ok() {
            true => {
                let tx_ledger_data = r.unwrap();
                tx_ledger_data.to_ledger_bytes()
            }
            false => Err(r.err().unwrap()),
        }
    }

    pub fn add_signatures(&mut self, input: TransactionSignatures) -> Result<(), Error> {
        let r = self
            .builder
            .add_signatures_transparant(input.transparent_sigs, self.branch);
        if r.is_err() {
            return r;
        }
        self.builder.add_signatures_spend(input.spend_sigs)
    }

    pub fn finalize(mut self) -> Result<(Transaction, TransactionMetadata), Error> {
        self.builder.finalize()
    }

    pub fn finalize_js(&mut self) -> Result<Vec<u8>, Error> {
        self.builder.finalize_js()
    }
}
