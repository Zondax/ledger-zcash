//! Abstractions over the proving system and parameters for ease of use.

use bellman::groth16::{Parameters, PreparedVerifyingKey};
use bls12_381::Bls12;
use zcash_primitives::{
    merkle_tree::MerklePath,
    primitives::{Diversifier, PaymentAddress, ProofGenerationKey, Rseed},
    prover::TxProver,
    redjubjub::{PublicKey, Signature},
    sapling::Node,
    transaction::components::{Amount, GROTH_PROOF_SIZE},
};

use crate::prover_ledger::SaplingProvingContextLedger;

// Circuit names
const SAPLING_SPEND_NAME: &str = "sapling-spend.params";
const SAPLING_OUTPUT_NAME: &str = "sapling-output.params";

// Circuit hashes
const SAPLING_SPEND_HASH: &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
const SAPLING_OUTPUT_HASH: &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
const SPROUT_HASH: &str = "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a";

use std::path::Path;
use zcash_proofs::{default_params_folder, load_parameters};

/// An implementation of [`TxProver`] using Sapling Spend and Output parameters from
/// locally-accessible paths.
pub struct LocalTxProverLedger {
    spend_params: Parameters<Bls12>,
    spend_vk: PreparedVerifyingKey<Bls12>,
    output_params: Parameters<Bls12>,
}

impl LocalTxProverLedger {
    /// Creates a `LocalTxProver` using parameters from the given local paths.
    ///
    /// # Examples
    ///
    /// ```should_panic
    /// use std::path::Path;
    /// use zcash_proofs::prover::LocalTxProver;
    ///
    /// let tx_prover = LocalTxProver::new(
    ///     Path::new("/path/to/sapling-spend.params"),
    ///     Path::new("/path/to/sapling-output.params"),
    /// );
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if the paths do not point to valid parameter files with
    /// the expected hashes.
    pub fn new(spend_path: &Path, output_path: &Path) -> Self {
        let (spend_params, spend_vk, output_params, _, _) =
            load_parameters(spend_path, output_path, None);
        LocalTxProverLedger {
            spend_params,
            spend_vk,
            output_params,
        }
    }

    /// Attempts to create a `LocalTxProver` using parameters from the default local
    /// location.
    ///
    /// Returns `None` if any of the parameters cannot be found in the default local
    /// location.
    ///
    /// # Examples
    ///
    /// ```
    /// use zcash_proofs::prover::LocalTxProver;
    ///
    /// match LocalTxProver::with_default_location() {
    ///     Some(tx_prover) => (),
    ///     None => println!("Please run zcash-fetch-params or fetch-params.sh to download the parameters."),
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function will panic if the parameters in the default local location do not
    /// have the expected hashes.
    #[cfg(feature = "local-prover")]
    #[cfg_attr(docsrs, doc(cfg(feature = "local-prover")))]
    pub fn with_default_location() -> Option<Self> {
        let params_dir = default_params_folder()?;
        let (spend_path, output_path) = if params_dir.exists() {
            (
                params_dir.join(SAPLING_SPEND_NAME),
                params_dir.join(SAPLING_OUTPUT_NAME),
            )
        } else {
            return None;
        };
        if !(spend_path.exists() && output_path.exists()) {
            return None;
        }

        Some(LocalTxProverLedger::new(&spend_path, &output_path))
    }

    /// Creates a `LocalTxProver` using Sapling parameters bundled inside the binary.
    ///
    /// This requires the `bundled-prover` feature, which will increase the binary size by
    /// around 50 MiB.
    #[cfg(feature = "bundled-prover")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bundled-prover")))]
    pub fn bundled() -> Self {
        let (spend_buf, output_buf) = wagyu_zcash_parameters::load_sapling_parameters();
        let (spend_params, spend_vk, output_params, _, _) =
            parse_parameters(&spend_buf[..], &output_buf[..], None);

        LocalTxProverLedger {
            spend_params,
            spend_vk,
            output_params,
        }
    }
}

pub trait TxProverLedger {
    /// Type for persisting any necessary context across multiple Sapling proofs.
    type SaplingProvingContext;

    /// Instantiate a new Sapling proving context.
    fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext;

    /// Create the value commitment, re-randomized key, and proof for a Sapling
    /// [`SpendDescription`], while accumulating its value commitment randomness inside
    /// the context for later use.
    ///
    /// [`SpendDescription`]: crate::transaction::components::SpendDescription
    fn spend_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
        rcv: jubjub::Fr,
    ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey), ()>;

    /// Create the value commitment and proof for a Sapling [`OutputDescription`],
    /// while accumulating its value commitment randomness inside the context for later
    /// use.
    ///
    /// [`OutputDescription`]: crate::transaction::components::OutputDescription
    fn output_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: u64,
        rcv: jubjub::Fr,
    ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint);

    /// Create the `bindingSig` for a Sapling transaction. All calls to
    /// [`TxProver::spend_proof`] and [`TxProver::output_proof`] must be completed before
    /// calling this function.
    fn binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        value_balance: Amount,
        sighash: &[u8; 32],
    ) -> Result<Signature, ()>;
}

impl TxProverLedger for LocalTxProverLedger {
    type SaplingProvingContext = SaplingProvingContextLedger;

    fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {
        SaplingProvingContextLedger::new()
    }

    fn spend_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
        rcv: jubjub::Fr,
    ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey), ()> {
        let (proof, cv, rk) = ctx.spend_proof(
            proof_generation_key,
            diversifier,
            rseed,
            ar,
            value,
            anchor,
            merkle_path,
            &self.spend_params,
            &self.spend_vk,
            rcv,
        )?;

        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        proof
            .write(&mut zkproof[..])
            .expect("should be able to serialize a proof");

        Ok((zkproof, cv, rk))
    }

    fn output_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: u64,
        rcv: jubjub::Fr,
    ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
        let (proof, cv) =
            ctx.output_proof(esk, payment_address, rcm, value, &self.output_params, rcv);

        let mut zkproof = [0u8; GROTH_PROOF_SIZE];
        proof
            .write(&mut zkproof[..])
            .expect("should be able to serialize a proof");

        (zkproof, cv)
    }

    fn binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        value_balance: Amount,
        sighash: &[u8; 32],
    ) -> Result<Signature, ()> {
        ctx.binding_sig(value_balance, sighash)
    }
}
