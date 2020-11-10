//! Structs for building transactions.
use crate::txprover_ledger::{TxProverLedger};
use group::GroupEncoding;
use rand::{rngs::OsRng, CryptoRng, RngCore};
use std::io::{self, Write};
use std::marker::PhantomData;
use zcash_primitives::primitives::{Diversifier, Note, PaymentAddress, ProofGenerationKey, Rseed};
use zcash_primitives::transaction::Transaction;

use crate::LedgerTxData;
use crate::sighashdata_ledger::{
    signature_hash_input_data,
};

use zcash_primitives::{
    consensus,
    keys::OutgoingViewingKey,
    legacy::TransparentAddress,
    merkle_tree::MerklePath,
    note_encryption::{Memo},
    redjubjub::{PublicKey},
    sapling::{Node},
    transaction::{
        components::{amount::*, *},
        signature_hash_data, TransactionData, SIGHASH_ALL,
    },
    util::generate_random_rseed,
};

use zcash_primitives::{
    legacy::Script,
    transaction::components::{OutPoint, TxIn},
};

use zcash_primitives::constants::SPENDING_KEY_GENERATOR;
use zcash_primitives::redjubjub::Signature;

use zcash_primitives::note_encryption::*;

use crate::zcashtools_errors::Error;

const DEFAULT_TX_EXPIRY_DELTA: u32 = 20;

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See https://github.com/zcash/zcash/issues/3615
const MIN_SHIELDED_OUTPUTS: usize = 2;

#[derive(Clone)]
struct SpendDescriptionInfoLedger {
    //extsk: ExtendedSpendingKey, //change this to path in ledger
    diversifier: Diversifier,
    note: Note,
    alpha: jubjub::Fr, //get both from ledger and generate self
    merkle_path: MerklePath<Node>,
    proofkey: ProofGenerationKey, //get from ledger
    ovk: Option<OutgoingViewingKey>,
    rcv: jubjub::Fr,
}

#[derive(Clone)]
pub struct SaplingOutputLedger {
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<OutgoingViewingKey>, //get from ledger
    to: PaymentAddress,
    note: Note,
    memo: Memo,
    rcv: jubjub::Fr, //get from ledger
}

impl SaplingOutputLedger {
    pub fn new<R: RngCore + CryptoRng, P: consensus::Parameters>(
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<Memo>,
        rcv: jubjub::Fr,
        rseed: Rseed,
    ) -> Result<Self, Error> {
        let g_d = match to.g_d() {
            Some(g_d) => g_d,
            None => return Err(Error::InvalidAddress),
        };
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        //let rseed = generate_random_rseed::<P, R>(height, rng);

        let note = Note {
            g_d,
            pk_d: to.pk_d().clone(),
            value: value.into(),
            rseed,
        };

        Ok(SaplingOutputLedger {
            ovk,
            to,
            note,
            memo: memo.unwrap_or_default(),
            rcv,
        })
    }

    pub fn build<P: TxProverLedger, R: RngCore + CryptoRng>(
        self,
        prover: &P,
        ctx: &mut P::SaplingProvingContext,
        rng: &mut R,
    ) -> OutputDescription {

        let mut encryptor = SaplingNoteEncryption::new(
            self.ovk,
            self.note.clone(),
            self.to.clone(),
            self.memo,
            rng,
        );

        let (zkproof, cv) = prover.output_proof(
            ctx,
            *encryptor.esk(),
            self.to,
            self.note.rcm(),
            self.note.value,
            self.rcv,
        );

        let cmu = self.note.cmu();

        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu);

        let ephemeral_key = encryptor.epk().clone().into();

        OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        }
    }
}

struct TransparentInputInfoLedger {
    pubkey: secp256k1::PublicKey,
    coin: TxOut,
}

struct TransparentInputs {
    secp: secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    inputs: Vec<TransparentInputInfoLedger>,
}

impl Default for TransparentInputs {
    fn default() -> Self {
        TransparentInputs {
            secp: secp256k1::Secp256k1::gen_new(),
            inputs: Default::default(),
        }
    }
}

impl TransparentInputs {
    fn push(
        &mut self,
        mtx: &mut TransactionData,
        pubkey: secp256k1::PublicKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        if coin.value.is_negative() {
            return Err(Error::InvalidAmount);
        }
        match coin.script_pubkey.address() {
            Some(TransparentAddress::PublicKey(hash)) => {
                use ripemd160::Ripemd160;
                use sha2::{Digest, Sha256};
                if &hash[..] != &Ripemd160::digest(&Sha256::digest(&pubkey.serialize()))[..] {
                    return Err(Error::InvalidAddressHash);
                }
            }
            _ => return Err(Error::InvalidAddressFormat),
        }

        mtx.vin.push(TxIn::new(utxo));
        self.inputs
            .push(TransparentInputInfoLedger { pubkey, coin });

        Ok(())
    }

    fn value_sum(&self) -> Amount {
        {
            self.inputs
                .iter()
                .map(|input| input.coin.value)
                .sum::<Amount>()
        }
    }
    fn apply_signatures(
        &self,
        signatures: Vec<secp256k1::Signature>,
        mtx: &mut TransactionData,
        consensus_branch_id: consensus::BranchId,
    ) -> Result<(), Error> {
        if signatures.len() != self.inputs.len() {
            return Err(Error::TranspararentSig);
        }
        let mut sighash = [0u8; 32];

        for (i, info) in self.inputs.iter().enumerate() {
            sighash.copy_from_slice(&signature_hash_data(
                mtx,
                consensus_branch_id,
                SIGHASH_ALL,
                Some((i, &info.coin.script_pubkey, info.coin.value)),
            ));

            let msg = secp256k1::Message::from_slice(&sighash).expect("32 bytes");
            let sig = signatures[i];
            let pk = info.pubkey;
            if !self.secp.verify(&msg, &sig, &pk).is_ok() {
                return Err(Error::TranspararentSig);
            }
            // Signature has to have "SIGHASH_ALL" appended to it
            let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
            sig_bytes.extend(&[SIGHASH_ALL as u8]);

            // P2PKH scriptSig
            mtx.vin[i].script_sig =
                Script::default() << &sig_bytes[..] << &info.pubkey.serialize()[..];
        }
        Ok(())
    }
}

/// Metadata about a transaction created by a [`Builder`].
#[derive(Debug, PartialEq, Clone)]
pub struct TransactionMetadata {
    spend_indices: Vec<usize>,
    output_indices: Vec<usize>,
}

impl TransactionMetadata {
    fn new() -> Self {
        TransactionMetadata {
            spend_indices: vec![],
            output_indices: vec![],
        }
    }

    /// Returns the index within the transaction of the [`SpendDescription`] corresponding
    /// to the `n`-th call to [`Builder::add_sapling_spend`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first spend
    /// they added (via the first call to [`Builder::add_sapling_spend`]) is the first
    /// [`SpendDescription`] in the transaction.
    pub fn spend_index(&self, n: usize) -> Option<usize> {
        self.spend_indices.get(n).copied()
    }

    /// Returns the index within the transaction of the [`OutputDescription`] corresponding
    /// to the `n`-th call to [`Builder::add_sapling_output`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`Builder::add_sapling_output`]) is the first
    /// [`OutputDescription`] in the transaction.
    pub fn output_index(&self, n: usize) -> Option<usize> {
        self.output_indices.get(n).copied()
    }
}

/// Generates a [`Transaction`] from its inputs and outputs.
pub struct Builder<P: consensus::Parameters, R: RngCore + CryptoRng> {
    rng: R,
    height: u32,
    mtx: TransactionData,
    fee: Amount,
    anchor: Option<bls12_381::Scalar>,
    spends: Vec<SpendDescriptionInfoLedger>,
    outputs: Vec<SaplingOutputLedger>,
    transparent_inputs: TransparentInputs,
    phantom: PhantomData<P>,
    pub sighash: [u8; 32],
}

impl<P: consensus::Parameters> Builder<P, OsRng> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height,
    /// using default values for general transaction fields and the default OS random.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new(height: u32) -> Self {
        Builder::new_with_rng(height, OsRng)
    }

    pub fn new_with_fee(height: u32, fee: u64) -> Self {
        Builder::new_with_fee_rng(height, OsRng, fee)
    }
}

fn spend_old_data_fromtx(data: &Vec<SpendDescriptionInfoLedger>) -> Vec<NullifierInput> {
    let mut v = Vec::new();
    for info in data.iter(){
        let n = NullifierInput {
            rcm_old: info.note.rcm().to_bytes(),
            notepos: info.merkle_path.position.to_le_bytes(),
        };
        v.push(n);
    }
    v
}

fn transparent_script_data_fromtx(
    tx: &TransactionData,
    inputs: &Vec<TransparentInputInfoLedger>,
) -> Result<Vec<TransparentScriptData>, Error> {
    let mut data = Vec::new();
    for (i, info) in inputs.iter().enumerate() {
        let mut prevout = [0u8; 36];
        prevout[0..32].copy_from_slice(&tx.vin[i].prevout.hash().as_ref());
        prevout[32..36].copy_from_slice(&tx.vin[i].prevout.n().to_le_bytes());

        let mut script_pubkey = [0u8; 26];
        info.coin.script_pubkey.write(&mut script_pubkey[..])?;

        let mut value = [0u8; 8];
        value.copy_from_slice(&info.coin.value.to_i64_le_bytes());

        let mut sequence = [0u8; 4];
        sequence.copy_from_slice(&tx.vin[i].sequence.to_le_bytes());

        let ts = TransparentScriptData {
            prevout,
            script_pubkey,
            value,
            sequence,
        };
        data.push(ts);
    }
    Ok(data)
}

fn spenddataledger_fromtx(input: &Vec<SpendDescription>) -> Vec<SpendDescriptionLedger> {
    let mut data = Vec::new();
    for info in input.iter() {
        let description = SpendDescriptionLedger::from(info);
        data.push(description);
    }
    data
}

fn outputdataledger_fromtx(input: &Vec<OutputDescription>) -> Vec<OutputDescriptionLedger> {
    let mut data = Vec::new();
    for info in input.iter() {
        let description = OutputDescriptionLedger::from(info);
        data.push(description);
    }
    data
}

#[derive(Clone)]
pub struct NullifierInput {
    pub rcm_old: [u8; 32],
    pub notepos: [u8; 8],
}

impl NullifierInput {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.rcm_old)?;
        writer.write_all(&self.notepos)
    }
}

#[derive(Clone)]
pub struct TransparentScriptData {
    pub prevout: [u8; 36],
    pub script_pubkey: [u8; 26],
    pub value: [u8; 8],
    pub sequence: [u8; 4],
}

impl TransparentScriptData {
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.prevout)?;
        writer.write_all(&self.script_pubkey)?;
        writer.write_all(&self.value)?;
        writer.write_all(&self.sequence)
    }
}

#[derive(Clone)]
pub struct SpendDescriptionLedger {
    pub cv: [u8; 32],
    pub anchor: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub zkproof: [u8; GROTH_PROOF_SIZE],
}

impl SpendDescriptionLedger {
    pub fn from(info: &SpendDescription) -> SpendDescriptionLedger {
        SpendDescriptionLedger {
            cv: info.cv.to_bytes(),
            anchor: info.anchor.to_bytes(),
            nullifier: info.nullifier.clone(),
            rk: info.rk.0.to_bytes(),
            zkproof: info.zkproof.clone(),
        }
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv)?;
        writer.write_all(&self.anchor)?;
        writer.write_all(&self.nullifier)?;
        writer.write_all(&self.rk)?;
        writer.write_all(&self.zkproof)
    }
}

#[derive(Clone)]
pub struct OutputDescriptionLedger {
    pub cv: [u8; 32],
    pub cmu: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
    pub zkproof: [u8; GROTH_PROOF_SIZE],
}

impl OutputDescriptionLedger {
    pub fn from(info: &OutputDescription) -> OutputDescriptionLedger {
        OutputDescriptionLedger {
            cv: info.cv.to_bytes(),
            cmu: info.cmu.to_bytes(),
            ephemeral_key: info.ephemeral_key.to_bytes(),
            enc_ciphertext: info.enc_ciphertext.clone(),
            out_ciphertext: info.out_ciphertext.clone(),
            zkproof: info.zkproof.clone(),
        }
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv)?;
        writer.write_all(&self.cmu)?;
        writer.write_all(&self.ephemeral_key)?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)?;
        writer.write_all(&self.zkproof)
    }
}

impl<P: consensus::Parameters, R: RngCore + CryptoRng> Builder<P, R> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height
    /// and randomness source, using default values for general transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    ///
    /// The fee will be set to the default fee (0.0001 ZEC).
    pub fn new_with_rng(height: u32, rng: R) -> Builder<P, R> {
        let mut mtx = TransactionData::new();
        mtx.expiry_height = height + DEFAULT_TX_EXPIRY_DELTA;

        Builder {
            rng,
            height,
            mtx,
            fee: DEFAULT_FEE,
            anchor: None,
            spends: vec![],
            outputs: vec![],
            transparent_inputs: TransparentInputs::default(),
            phantom: PhantomData,
            sighash: [0u8; 32],
        }
    }

    pub fn new_with_fee_rng(height: u32, rng: R, fee: u64) -> Builder<P, R> {
        let mut mtx = TransactionData::new();
        mtx.expiry_height = height + DEFAULT_TX_EXPIRY_DELTA;
        let txfee = Amount::from_u64(fee).unwrap();

        Builder {
            rng,
            height,
            mtx,
            fee: txfee,
            anchor: None,
            spends: vec![],
            outputs: vec![],
            transparent_inputs: TransparentInputs::default(),
            phantom: PhantomData,
            sighash: [0u8; 32],
        }
    }

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_sapling_spend(
        &mut self,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
        alpha: jubjub::Fr,               //get from ledger
        proofkey: ProofGenerationKey,    //get from ledger
        ovk: Option<OutgoingViewingKey>, //get from ledger
        rcv: jubjub::Fr,                 //get from ledger
    ) -> Result<(), Error> {
        // Consistency check: all anchors must equal the first one
        //Fixme: add this later when we get info from chain
        self.anchor = Some(bls12_381::Scalar::one());
        /*
        let cmu = Node::new(note.cmu().into());
        if let Some(anchor) = self.anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(cmu).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.anchor = Some(merkle_path.root(cmu).into())
        }
         */

        self.mtx.value_balance += Amount::from_u64(note.value).map_err(|_| Error::InvalidAmount)?;

        self.spends.push(SpendDescriptionInfoLedger {
            diversifier,
            note,
            alpha,
            merkle_path,
            proofkey,
            ovk,
            rcv,
        });

        Ok(())
    }

    /// Adds a Sapling address to send funds to.
    pub fn add_sapling_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        value: Amount,
        memo: Option<Memo>,
        rcv: jubjub::Fr,
        rseed: Rseed,
    ) -> Result<(), Error> {
        let output = SaplingOutputLedger::new::<R, P>(
            ovk,
            to,
            value,
            memo,
            rcv,
            rseed,
        )?;

        self.mtx.value_balance -= value;

        self.outputs.push(output);

        Ok(())
    }

    /// Adds a transparent coin to be spent in this transaction.
    pub fn add_transparent_input(
        &mut self,
        pubkey: secp256k1::PublicKey,
        utxo: OutPoint,
        coin: TxOut,
    ) -> Result<(), Error> {
        self.transparent_inputs
            .push(&mut self.mtx, pubkey, utxo, coin)
    }

    /// Adds a transparent address to send funds to.
    pub fn add_transparent_output(&mut self, to: Script, value: Amount) -> Result<(), Error> {
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        self.mtx.vout.push(TxOut {
            value,
            script_pubkey: to,
        });

        Ok(())
    }

    /// Sets the Sapling address to which any change will be sent.
    ///
    /// By default, change is sent to the Sapling address corresponding to the first note
    /// being spent (i.e. the first call to [`Builder::add_sapling_spend`]).
    /*
    pub fn send_change_to(
        &mut self,
        ovk: OutgoingViewingKey,
        to: PaymentAddress,
        rcv: jubjub::Fr,
        rcm: jubjub::Fr,
        esk: jubjub::Fr,
    ) {
        self.change_address = Some((ovk, to, rcv, rcm, esk));
    }
    */
    /// Builds a transaction from the configured spends and outputs.
    ///
    /// Upon success, returns a tuple containing the final transaction, and the
    /// [`TransactionMetadata`] generated during the build process.
    ///
    /// `consensus_branch_id` must be valid for the block height that this transaction is
    /// targeting. An invalid `consensus_branch_id` will *not* result in an error from
    /// this function, and instead will generate a transaction that will be rejected by
    /// the network.
    pub fn build(
        &mut self,
        consensus_branch_id: consensus::BranchId,
        prover: &impl TxProverLedger,
    ) -> Result<LedgerTxData, Error> {
        let mut localrng = OsRng;

        let mut buf = [0u8; 64];

        localrng.fill_bytes(&mut buf);
        //
        // Consistency checks
        //

        // Valid change
        let change = self.mtx.value_balance - self.fee + self.transparent_inputs.value_sum()
            - self
                .mtx
                .vout
                .iter()
                .map(|output| output.value)
                .sum::<Amount>();
        if change.is_negative() {
            return Err(Error::ChangeIsNegative);
        }

        //
        // Change output
        //

        if change.is_positive() {
            // Send change to the specified change address. If no change address
            // was set, then error as Ledger otherwise needs to give keys and randomness.
            return Err(Error::NoChangeAddress);
        }

        //
        // Record initial positions of spends and outputs
        //
        let spends: Vec<_> = self.spends.clone().into_iter().enumerate().collect();
        let mut outputs: Vec<_> = self.outputs.clone().into_iter().enumerate().collect();

        //
        // Sapling spends and outputs
        //

        //let mut ctx: <impl TxProver as LocalTxProverLedger>::SaplingProvingContextLedger = SaplingProvingContextLedger::new();
        let mut ctx = prover.new_sapling_proving_context();

        // Pad Sapling outputs
        if !spends.is_empty() && outputs.len() < MIN_SHIELDED_OUTPUTS{
            return Err(Error::MinShieldedOuputs);
        }

        // Record if we'll need a binding signature
        let binding_sig_needed = !spends.is_empty() || !outputs.is_empty();

        // Create Sapling SpendDescriptions
        if !spends.is_empty() {
            let anchor = self.anchor.expect("anchor was set if spends were added");

            for (_,spend) in spends.iter() {
                let proof_generation_key = spend.proofkey.clone();

                let mut nullifier = [0u8; 32];
                nullifier.copy_from_slice(&spend.note.nf(
                    &proof_generation_key.to_viewing_key(),
                    spend.merkle_path.position,
                ));
                let (zkproof, cv, rk) = prover
                    .spend_proof(
                        &mut ctx,
                        proof_generation_key,
                        spend.diversifier,
                        spend.note.rseed,
                        spend.alpha,
                        spend.note.value,
                        anchor,
                        spend.merkle_path.clone(),
                        spend.rcv,
                    )
                    .map_err(|()| Error::SpendProof)?;

                self.mtx.shielded_spends.push(SpendDescription {
                    cv,
                    anchor,
                    nullifier,
                    rk: PublicKey(rk.0.clone()),
                    zkproof,
                    spend_auth_sig: None,
                });

                // Record the post-randomized spend location
            }
        }

        // Create Sapling OutputDescriptions
        for (_,output) in outputs.into_iter() {
            let output_desc = output.build(prover, &mut ctx, &mut self.rng);
            self.mtx.shielded_outputs.push(output_desc);
        }

        //
        // Signatures
        //

        self.sighash.copy_from_slice(&signature_hash_data(
            &self.mtx,
            consensus_branch_id,
            SIGHASH_ALL,
            None,
        ));

        // Add a binding signature if needed
        if binding_sig_needed {
            self.mtx.binding_sig = Some(
                prover
                    .binding_sig(&mut ctx, self.mtx.value_balance, &self.sighash)
                    .map_err(|()| Error::BindingSig)?,
            );
        } else {
            self.mtx.binding_sig = None;
        }

        let r =
            transparent_script_data_fromtx(&self.mtx, &self.transparent_inputs.inputs);
        if r.is_err(){
            return Err(r.err().unwrap());
        }

        let trans_scripts = r.unwrap();
        let hash_input = signature_hash_input_data(&self.mtx, SIGHASH_ALL);

        let spend_olddata = spend_old_data_fromtx(&self.spends);
        let spenddata = spenddataledger_fromtx(&self.mtx.shielded_spends);
        let outputdata = outputdataledger_fromtx(&self.mtx.shielded_outputs);

        Ok(LedgerTxData {
            t_script_data: trans_scripts,
            s_spend_old_data: spend_olddata,
            s_spend_new_data: spenddata,
            s_output_data: outputdata,
            tx_hash_data: hash_input,
        })
    }

    pub fn add_signatures_transparant(
        &mut self,
        signatures: Vec<secp256k1::Signature>, //get from ledger
        consensus_branch_id: consensus::BranchId,
    ) -> Result<(), Error> {
        self.transparent_inputs.apply_signatures(
            signatures,
            &mut self.mtx,
            consensus_branch_id,
        )
    }

    pub fn add_signatures_spend(
        &mut self,
        sign: Vec<Signature>, //get from ledger
    ) -> Result<(), Error> {
        if self.spends.len() == 0 {
            return Ok(());
        }
        if sign.len() != self.spends.len() {
            return Err(Error::SpendSig);
        }

        let p_g = SPENDING_KEY_GENERATOR;
        let mut all_signatures_valid: bool = true;
        for i in 0..self.spends.len() {
            let rk = PublicKey(self.spends[i].proofkey.ak.into())
                .randomize(self.spends[i].alpha, SPENDING_KEY_GENERATOR);
            all_signatures_valid &= rk.verify(&self.sighash, &sign[i], p_g);
            self.mtx.shielded_spends[i].spend_auth_sig = Some(sign[i]);
        }
        /*
        let mut spends: Vec<_> = self.spends.clone().into_iter().enumerate().collect();
        let mut all_signatures_valid: bool = true;
        for (i, (_, spend)) in spends.into_iter().enumerate() {
            let rk = PublicKey(spend.proofkey.ak.into()).randomize(spend.alpha,SPENDING_KEY_GENERATOR);
            all_signatures_valid &= rk.verify(&self.sighash, &sign[i], p_g);
            self.mtx.shielded_spends[i].spend_auth_sig = Some(sign[i]);
        }
         */

        match all_signatures_valid {
            true => Ok(()),
            false => Err(Error::SpendSig),
        }
    }

    pub fn finalize(mut self) -> Result<(Transaction, TransactionMetadata), Error>{
        let r = self.mtx.freeze();
        let tx;
        match r {
            Ok(t) => tx = t,
            Err(_) => return Err(Error::Finalization),
        }
        let mut tx_meta = TransactionMetadata::new();
        tx_meta.spend_indices = (0..self.spends.len()).collect();
        tx_meta.output_indices = (0..self.outputs.len()).collect();
        Ok((tx, tx_meta.clone()))
    }

    /*
        pub overwintered: bool,
    pub version: u32,
    pub version_group_id: u32,
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub value_balance: Amount,
    pub shielded_spends: Vec<SpendDescription>,
    pub shielded_outputs: Vec<OutputDescription>,
    pub joinsplits: Vec<JSDescription>,
    pub joinsplit_pubkey: Option<[u8; 32]>,
    pub joinsplit_sig: Option<[u8; 64]>,
    pub binding_sig: Option<Signature>,
     */
    pub fn finalize_js(&mut self) -> Result<Vec<u8>, Error>{
        let mut txdata_copy = TransactionData::new();
        txdata_copy.overwintered = self.mtx.overwintered;
        txdata_copy.version = self.mtx.version;
        txdata_copy.version_group_id = self.mtx.version_group_id;
        txdata_copy.vin = vec![];
        for info in self.mtx.vin.iter(){
            let tin = TxIn{
                prevout: info.prevout.clone(),
                script_sig: info.script_sig.clone(),
                sequence: info.sequence,
            };
            txdata_copy.vin.push(tin);
        }
        txdata_copy.vout = vec![];
        for info in self.mtx.vout.clone(){
            txdata_copy.vout.push(info);
        }
        txdata_copy.lock_time = self.mtx.lock_time;
        txdata_copy.expiry_height = self.mtx.expiry_height;
        txdata_copy.value_balance = self.mtx.value_balance;
        txdata_copy.shielded_spends = vec![];
        for info in self.mtx.shielded_spends.iter(){
            let spend = SpendDescription{
                cv : info.cv,
                anchor: info.anchor,
                nullifier:info.nullifier,
                rk: PublicKey(info.rk.0),
                zkproof: info.zkproof,
                spend_auth_sig: info.spend_auth_sig,
            };
            txdata_copy.shielded_spends.push(spend);
        }

        for info in self.mtx.shielded_outputs.iter(){
            let output = OutputDescription{
                cv: info.cv,
                cmu: info.cmu,
                ephemeral_key: info.ephemeral_key,
                enc_ciphertext: info.enc_ciphertext,
                out_ciphertext: info.out_ciphertext,
                zkproof: info.zkproof
            };
            txdata_copy.shielded_outputs.push(output);
        }
        txdata_copy.joinsplits = vec![];
        txdata_copy.joinsplit_pubkey = None;
        txdata_copy.joinsplit_sig = None;
        txdata_copy.binding_sig = self.mtx.binding_sig;
        let r = txdata_copy.freeze();
        let tx;
        match r {
            Ok(t) => tx = t,
            Err(_) => return Err(Error::Finalization),
        }
        let mut v = Vec::new();
        tx.write(&mut v)?;
        Ok(v)
    }
}
/*
#[cfg(test)]
mod tests {
    use ff::{Field, PrimeField};
    use rand_core::OsRng;
    use std::marker::PhantomData;

    use super::{Builder, Error};
    use zcash_primitives::{
        *,
        consensus::*,
        consensus::TestNetwork,
        legacy::TransparentAddress,
        merkle_tree::{CommitmentTree, IncrementalWitness},
        primitives::Rseed,
        prover::*,
        sapling::Node,
        transaction::components::Amount,
        zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
        transaction::{
            components::{amount::DEFAULT_FEE, OutputDescription, SpendDescription, TxOut},
            signature_hash_data, Transaction, TransactionData, SIGHASH_ALL,
        },
    };
    use zcash_primitives::primitives::ProofGenerationKey;
    use jubjub::{SubgroupPoint, ExtendedPoint};
    use zcash_primitives::keys::OutgoingViewingKey;
    use zcash_primitives::redjubjub::PublicKey;

    #[test]
    fn fails_on_negative_output() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = extfvk.fvk.ovk;
        let to = extfvk.default_address().unwrap().1;
        let mut builder = Builder::<TestNetwork, OsRng>::new(0);
        assert_eq!(
            builder.add_sapling_output(Some(ovk), to, Amount::from_i64(-1).unwrap(), None),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn binding_sig_absent_if_no_shielded_spend_or_output() {
        use crate::consensus::{NetworkUpgrade, Parameters};
        use crate::transaction::{
            builder::{self, TransparentInputs},
            TransactionData,
        };

        let sapling_activation_height =
            TestNetwork::activation_height(NetworkUpgrade::Sapling).unwrap();

        // Create a builder with 0 fee, so we can construct t outputs
        let mut builder = Builder::<TestNetwork, OsRng> {
            rng: OsRng,
            height: sapling_activation_height,
            mtx: TransactionData::new(),
            fee: Amount::zero(),
            anchor: None,
            spends: vec![],
            outputs: vec![],
            transparent_inputs: TransparentInputs::default(),
            change_address: None,
            phantom: PhantomData,
            sighash: [0u8;32]
        };

        // Create a tx with only t output. No binding_sig should be present
        builder
            .add_transparent_output(&TransparentAddress::PublicKey([0; 20]), Amount::zero())
            .unwrap();
/*      there is not public MockTxProver
        let (tx, _) = builder
            .build(consensus::BranchId::Sapling, &MockTxProver)
            .unwrap();
        // No binding signature, because only t input and outputs
        assert!(tx.binding_sig.is_none());

 */
    }

    #[test]
    fn binding_sig_present_if_shielded_spend() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let to = extfvk.default_address().unwrap().1;

        let mut rng = OsRng;

        let note1 = to
            .create_note(50000, Rseed::BeforeZip212(jubjub::Fr::one())) //fixme))
            .unwrap();
        let cmu1 = Node::new(note1.cmu().to_repr());
        let mut tree = CommitmentTree::new();
        tree.append(cmu1).unwrap();
        let witness1 = IncrementalWitness::from_tree(&tree);

        let mut builder = Builder::<TestNetwork, OsRng>::new(0);

        // Create a tx with a sapling spend. binding_sig should be present
        builder
            .add_sapling_spend(
                *to.diversifier(),
                note1.clone(),
                witness1.path().unwrap(),
                jubjub::Fr::one(),
                ProofGenerationKey{ak:SubgroupPoint::default(),nsk:jubjub::Fr::one()},
                PublicKey(ExtendedPoint::default()),
                Some(OutgoingViewingKey([0xaa;32]))
            )
            .unwrap();

        builder
            .add_transparent_output(&TransparentAddress::PublicKey([0; 20]), Amount::zero())
            .unwrap();

        // Expect a binding signature error, because our inputs aren't valid, but this shows
        // that a binding signature was attempted
        assert_eq!(
            builder.build(consensus::BranchId::Sapling, &MockTxProver),
            Err(Error::BindingSig)
        );
    }

    #[test]
    fn fails_on_negative_transparent_output() {
        let mut builder = Builder::<TestNetwork, OsRng>::new(0);
        assert_eq!(
            builder.add_transparent_output(
                &TransparentAddress::PublicKey([0; 20]),
                Amount::from_i64(-1).unwrap(),
            ),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn fails_on_negative_change() {
        let mut rng = OsRng;

        // Just use the master key as the ExtendedSpendingKey for this test
        let extsk = ExtendedSpendingKey::master(&[]);

        // Fails with no inputs or outputs
        // 0.0001 t-ZEC fee
        {
            let builder = Builder::<TestNetwork, OsRng>::new(0);
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-10000).unwrap()))
            );
        }

        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = Some(extfvk.fvk.ovk);
        let to = extfvk.default_address().unwrap().1;

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = Builder::<TestNetwork, OsRng>::new(0);
            builder
                .add_sapling_output(
                    ovk.clone(),
                    to.clone(),
                    Amount::from_u64(50000).unwrap(),
                    None,
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-60000).unwrap()))
            );
        }

        // Fail if there is only a transparent output
        // 0.0005 t-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = Builder::<TestNetwork, OsRng>::new(0);
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(50000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-60000).unwrap()))
            );
        }

        let note1 = to
            .create_note(59999, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cmu1 = Node::new(note1.cmu().to_repr());
        let mut tree = CommitmentTree::new();
        tree.append(cmu1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(&tree);

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.00059999 z-ZEC in
        {
            let mut builder = Builder::<TestNetwork, OsRng>::new(0);
            builder
                .add_sapling_spend(
                    extsk.clone(),
                    *to.diversifier(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output(
                    ovk.clone(),
                    to.clone(),
                    Amount::from_u64(30000).unwrap(),
                    None,
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(20000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_i64(-1).unwrap()))
            );
        }

        let note2 = to
            .create_note(1, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cmu2 = Node::new(note2.cmu().to_repr());
        tree.append(cmu2).unwrap();
        witness1.append(cmu2).unwrap();
        let witness2 = IncrementalWitness::from_tree(&tree);

        // Succeeds if there is sufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.0006 z-ZEC in
        //
        // (Still fails because we are using a MockTxProver which doesn't correctly
        // compute bindingSig.)
        {
            let mut builder = Builder::<TestNetwork, OsRng>::new(0);
            builder
                .add_sapling_spend(
                    extsk.clone(),
                    *to.diversifier(),
                    note1,
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_spend(extsk, *to.diversifier(), note2, witness2.path().unwrap())
                .unwrap();
            builder
                .add_sapling_output(ovk, to, Amount::from_u64(30000).unwrap(), None)
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    Amount::from_u64(20000).unwrap(),
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::BindingSig)
            )
        }
    }
}
*/
