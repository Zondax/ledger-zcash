/** ******************************************************************************
 *  (c) 2020-2024 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu, { ButtonKind, DEFAULT_START_OPTIONS } from '@zondax/zemu'
import ZCashApp from '@zondax/ledger-zcash'
import { APP_SEED, models } from './_config'
import { get_inittx_data, ZcashBuilderBridge, SPEND_PATH, OUTPUT_PATH } from '@zondax/zcashtools'
import { fee_for, TX_INPUT_DATA } from './_vectors'
import crypto from 'crypto'
import { takeLastSnapshot } from './utils'

const tx_version = 0x05

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
}

jest.setTimeout(600000)

describe('End to end transactions', function () {
  test.concurrent.each(models)('make a transaction with 2 spend 2 outputs', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      // Simulate a transaction where Alice sends 55000 ZEC to Bob. Includes:
      // - Two spend notes of 50000 ZEC each, associated with Alice's address at path: 1000.
      // - Two output notes for transaction distribution.
      // - A transaction fee compliant with ZIP-0317.
      // Transaction data is collected from the UI and formatted into JSON structures.

      const tx_input_data = TX_INPUT_DATA[0]
      const {
        s_spend: [s_spend1, s_spend2],
        s_output: [s_out1, s_out2],
      } = tx_input_data

      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      // get_inittx_data function takes transaction inputs and returns a blob for the ledger device.
      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(Buffer.from(ledgerblob_initdata).byteLength)

      // Transmit the output from get_inittx_data to the ledger for validation.
      // The ledger displays the transaction inputs for user verification.
      // Upon confirmation, it calculates the necessary randomness for shielded spends and outputs.

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      const testname = `${m.prefix.toLowerCase()}-2-spend-2-out`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit

      console.log(req)
      expect(req.txdataRaw.length).toEqual(32)

      // Create the SHA-256 hash instance
      let hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      let h = hash.digest('hex')
      expect(req.txdata).toEqual(h)

      // Begin transaction construction using the builder.

      // For each shielded spend, the builder requires:
      // - Proof generation key (proofkey)
      // - Randomness for value commitment (rcv)
      // - Randomness for the random verification key (alpha)
      // These are obtained from the ledger via an extractSpendData call, which requires no inputs.
      // The ledger is pre-informed of the required data size post-initial transaction setup.

      const req2 = await app.extractSpendData()
      console.log(req2)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)
      const expected_proofkey =
        '0bbb1d4bfe70a4f4fc762e2f980ab7c600a060c28410ccd03972931fe310f2a53022d5db92c9dc180dd12e2d74162396f13513016719e38d2616f7730d09a909'
      expect(req2.key).toEqual(expected_proofkey)

      // The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      // It also uses the spend address and value from the UI.
      // We also need the witness from the blockchain, which is now a fake/incorrect one.

      const spendj1 = {
        proofkey: req2.key,
        rcv: req2.rcv,
        alpha: req2.alpha,
        address: s_spend1.address,
        value: s_spend1.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      // The builder adds the spend to its state.
      const b1 = builder.add_sapling_spend(spendj1)
      console.log(b1)

      // Repeat the process for the second spend.
      const req3 = await app.extractSpendData()
      console.log(req3)
      expect(req3.key).toEqual(expected_proofkey)

      const spendj2 = {
        proofkey: req3.key,
        rcv: req3.rcv,
        alpha: req3.alpha,
        address: s_spend2.address,
        value: s_spend2.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      const b2 = builder.add_sapling_spend(spendj2)
      console.log(b2)

      // All spends added. No more spend data can be retrieved from the ledger.
      // Start the shielded output process.

      // To add a shielded output to the builder, we need:
      // - the randomness needed for the value commitment (rcv)
      // - the randomness needed for the note commitment (rcm)
      // - the randomness needed for the random encryption key (esk)
      // All this is retrieved from the ledger using a extractoutputdata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.

      const req4 = await app.extractOutputData()
      console.log(req4)

      // The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      // It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      // It furthermore uses the output address, value and memo from the UI.

      const outj1 = {
        rcv: req4.rcv,
        rseed: req4.rseed,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hashSeedRaw,
      }

      console.log(req4.hashSeedRaw)
      // The builder adds the shielded output to its state.
      const b3 = builder.add_sapling_output(outj1)
      console.log(b3)

      // This process needs to be repeated for the second output.
      // Note that this output address belongs to Alice.
      // There is no concept of a "change address" as all inputs and outputs need to be known in advance for the ledger verification on screen.
      // The UI needs to take care of this before initializing a transaction to the ledger.

      const req5 = await app.extractOutputData()
      console.log(req5)

      console.log(req5.hashSeedRaw)

      const outj2 = {
        rcv: req5.rcv,
        rseed: req5.rseed,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hashSeedRaw,
      }

      const b4 = builder.add_sapling_output(outj2)
      console.log(b4)

      // All shielded outputs added to the builder.
      // All inputs the builder needs for this transaction are now added.
      // Let the builder build the transaction, including the ZK proofs.
      // The builder returns a txdata blob.
      // The ledger needs this blob to validate the correctness of the tx.

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, tx_version)

      // Now the ledger will validate the txdata blob.
      // For this, it uses the input from inittx to verify.
      // If all checks are ok, the ledger signs the transaction.
      // console.log(ledgerblob_txdata.slice(10 * 250 + 116))

      const req6 = await app.checkAndSign(ledgerblob_txdata, tx_version)
      console.log(req6)

      // Check the hash of the return
      hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_txdata))
      h = hash.digest('hex')
      expect(req6.signdata).toEqual(h)

      // The builder needs these signatures to add it to the transaction blob.
      // We need to do this one by one.
      // So we first gather all signatures we need.

      const req7 = await app.extractSpendSignature()
      console.log(req7)

      const req8 = await app.extractSpendSignature()
      console.log(req8)

      // At this point we gathered all signatures.
      // We now add these signatures to the builder.
      // Note that for this transaction, we do not have any transparent signatures.

      const signatures = {
        transparent_sigs: [],
        sapling_sigs: [req7.signature, req8.signature],
      }

      const b5 = builder.add_signatures(signatures)
      console.log(b5)

      await takeLastSnapshot(testname, last_index, sim)

      // The builder is now done and the transaction is complete.
      const b6 = builder.finalize()
      console.log(b6)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('make a tx with 1 transparent input 1 spend 2 shielded outputs', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      // In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
      // For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
      // She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
      // The inputs to the initialization is therefore:
      // - one transparent input and one transparent output
      // - one shielded spend notes and two shielded output notes.
      // She takes a transaction fee accorind to ZIP-0317 and all leftovers is sent shielded to her own address.
      // All this info is gathered from the UI and put in the correct jsons.

      const tx_input_data = TX_INPUT_DATA[1]
      const {
        t_in: [tin1],
        s_spend: [s_spend1],
        s_output: [s_out1, s_out2],
      } = tx_input_data
      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      // The inputs to the get_inittx_data function are the inputs to the transaction.
      // The output is a blob that can be send to the ledger device.

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      // The output of the get_inittx_data can be send to the ledger.
      // The ledger will check this data and show the inputs on screen for verification.
      // If confirmed, the ledger also computes the randomness needed for :
      //     - The shielded spends
      //     - the shielded outputs

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      const testname = `${m.prefix.toLowerCase()}-1-tr-in-1-spend-2-sh-out`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit

      // const req = await app.initNewTx(ledgerblob_initdata);
      console.log(req)
      expect(req.txdata.length).toEqual(32)

      // Check the hash of the return
      let hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      let h = hash.digest('hex')
      expect(req.txdata).toEqual(h)

      // Now we start building the transaction using the builder.

      // To add transparent inputs to the builder, we dont need fresh information from the ledger.
      // The builder does need the secp256k1 public key belonging to the address.
      // The builder also need outpoint from the blockchain.

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      const bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

      // To add a shielded spend to the builder, we need:
      //     - the proof generation key belonging to the spend address (proofkey)
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the random verification key (alpha)
      // All this is retrieved from the ledger using a extractspenddata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.

      const req2 = await app.extractSpendData()
      console.log(req2)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      // The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      // It furthermore uses the spend address and value from the UI.

      const spendj1 = {
        proofkey: req2.key,
        rcv: req2.rcv,
        alpha: req2.alpha,
        address: s_spend1.address,
        value: s_spend1.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      // The builder adds the spend to its state.

      const b1 = builder.add_sapling_spend(spendj1)
      console.log(b1)

      // At this point we added all spends.
      // We cannot get more spend data from the ledger.
      // We now start the shielded output process.

      // To add a shielded output to the builder, we need:
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the note commitment (rcm)
      //     - the randomness needed for the random encryption key (esk)
      // All this is retrieved from the ledger using a extractoutputdata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.

      const req4 = await app.extractOutputData()
      console.log(req4)

      // The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      // It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      // It furthermore uses the output address, value and memo from the UI.

      const outj1 = {
        rcv: req4.rcv,
        rseed: req4.rseed,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hashSeedRaw,
      }

      // The builder adds the shielded output to its state.

      const b3 = builder.add_sapling_output(outj1)
      console.log(b3)

      // This process needs to be repeated for the second output.
      // Note that this output address belongs to Alice.

      const req5 = await app.extractOutputData()
      console.log(req5)

      const outj2 = {
        rcv: req5.rcv,
        rseed: req5.rseed,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hashSeedRaw,
      }

      const b4 = builder.add_sapling_output(outj2)
      console.log(b4)

      // We are now done with adding the shielded outputs to the builder.
      // In fact, we are done adding all inputs the builder needs for this transaction.
      // We now let the builder build the transaction, including the ZK proofs.
      // The builder returns a txdata blob.
      // The ledger needs this blob to validate the correctness of the tx.

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, tx_version)

      // Now the ledger will validate the txdata blob.
      // For this, it uses the input from inittx to verify.
      // If all checks are ok, the ledger signs the transaction.

      const req6 = await app.checkAndSign(ledgerblob_txdata, tx_version)
      console.log(req6)

      // Check the hash of the return

      hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_txdata))
      h = hash.digest('hex')
      expect(req6.signdata).toEqual(h)

      // The builder needs the spend signatures to add it to the transaction blob.
      // We need to do this one by one.
      // So we first gather all signatures we need.

      const req7 = await app.extractSpendSignature()
      console.log(req7)

      // The builder also needs the transparent signature for the transparent input.

      const req9 = await app.extractTransparentSig()
      console.log(req9)

      // At this point we gathered all signatures.
      // We now add these signaturs to the builder.
      // Note that for this transaction, we do not have any transparent signatures.

      const signatures = {
        transparent_sigs: [req9.signature],
        sapling_sigs: [req7.signature],
      }

      console.log(signatures)

      const b5 = builder.add_signatures(signatures)
      console.log(b5)

      await takeLastSnapshot(testname, last_index, sim)
      // The builder is now done and the transaction is complete.

      const b6 = builder.finalize()
      console.log(b6)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('make a tx with 1 transparent output 1 spend 2 shielded outputs', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      /*
      In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
      For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
      She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
      The inputs to the initialization is therefore:
      - one transparent input and one transparent output
      - one shielded spend notes and two shielded output notes.
      She takes a transaction fee accorind to ZIP-0317 and all leftovers is sent shielded to her own address.
      All this info is gathered from the UI and put in the correct jsons.
       */

      const tx_input_data = TX_INPUT_DATA[2]

      const {
        t_out: [tout1],
        s_spend: [s_spend1],
        s_output: [s_out1, s_out2],
      } = tx_input_data
      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      /*
      The inputs to the get_inittx_data function are the inputs to the transaction.
      The output is a blob that can be send to the ledger device.
      */

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      /*
      The output of the get_inittx_data can be send to the ledger.
      The ledger will check this data and show the inputs on screen for verification.
      If confirmed, the ledger also computes the randomness needed for :
          - The shielded spends
          - the shielded outputs
       */

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      const testname = `${m.prefix.toLowerCase()}-1-tr-out-1-spend-2-sh-out`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit

      // const req = await app.initNewTx(ledgerblob_initdata);
      console.log(req)

      expect(req.txdata.length).toEqual(32)

      /*
      Check the hash of the return
      */
      let hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      let h = hash.digest('hex')
      expect(req.txdata).toEqual(h)

      /*
      Now we start building the transaction using the builder.
      /*

      /*
      To add a transparent output, the builder does not need anything other than the input to the inittx.
       */
      const t_out_data = {
        address: tout1.address,
        value: tout1.value,
      }

      const bt1 = builder.add_transparent_output(t_out_data)
      console.log(bt1)

      /*
     To add a shielded spend to the builder, we need:
         - the proof generation key belonging to the spend address (proofkey)
         - the randomness needed for the value commitment (rcv)
         - the randomness needed for the random verification key (alpha)
     All this is retrieved from the ledger using a extractspenddata call with no inputs.
     The ledger already knows how much data it needs to send after the inittx call.
     */

      const req2 = await app.extractSpendData()
      console.log(req2)

      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      /*
      The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      It furthermore uses the spend address and value from the UI.
       */

      const spendj1 = {
        proofkey: req2.key,
        rcv: req2.rcv,
        alpha: req2.alpha,
        address: s_spend1.address,
        value: s_spend1.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      /*
      The builder adds the spend to its state.
       */

      const b1 = builder.add_sapling_spend(spendj1)
      console.log(b1)

      /*
      At this point we added all spends.
      We cannot get more spend data from the ledger.
      We now start the shielded output process.
       */

      /*
     To add a shielded output to the builder, we need:
         - the randomness needed for the value commitment (rcv)
         - the randomness needed for the note commitment (rcm)
         - the randomness needed for the random encryption key (esk)
     All this is retrieved from the ledger using a extractoutputdata call with no inputs.
     The ledger already knows how much data it needs to send after the inittx call.
     */

      const req4 = await app.extractOutputData()
      console.log(req4)

      /*
      The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      It furthermore uses the output address, value and memo from the UI.
      */

      const outj1 = {
        rcv: req4.rcv,
        rseed: req4.rseed,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hashSeedRaw,
      }

      /*
      The builder adds the shielded output to its state.
       */

      const b3 = builder.add_sapling_output(outj1)
      console.log(b3)

      /*
      This process needs to be repeated for the second output.
      Note that this output address belongs to Alice.
       */

      const req5 = await app.extractOutputData()
      console.log(req5)

      const outj2 = {
        rcv: req5.rcv,
        rseed: req5.rseed,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hashSeedRaw,
      }

      const b4 = builder.add_sapling_output(outj2)
      console.log(b4)

      /*
      We are now done with adding the shielded outputs to the builder.
      In fact, we are done adding all inputs the builder needs for this transaction.
      We now let the builder build the transaction, including the ZK proofs.
      The builder returns a txdata blob.
      The ledger needs this blob to validate the correctness of the tx.
       */

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, tx_version)

      /*
      Now the ledger will validate the txdata blob.
      For this, it uses the input from inittx to verify.
      If all checks are ok, the ledger signs the transaction.
       */

      const req6 = await app.checkAndSign(ledgerblob_txdata, tx_version)
      console.log(req6)

      /*
      Check the hash of the return
      */

      hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_txdata))
      h = hash.digest('hex')
      expect(req6.signdata).toEqual(h)

      /*
      The builder needs the spend signatures to add it to the transaction blob.
      We need to do this one by one.
      So we first gather all signatures we need.
       */

      const req7 = await app.extractSpendSignature()
      console.log(req7)

      /*
     At this point we gathered all signatures (only for shielded inputs as there are no transparent ones)
     We now add these signatures to the builder.
     Note that for this transaction, we do not have any transparent signatures.
      */

      const signatures = {
        transparent_sigs: [],
        sapling_sigs: [req7.signature],
      }

      const b5 = builder.add_signatures(signatures)
      console.log(b5)

      await takeLastSnapshot(testname, last_index, sim)

      /*
      The builder is now done and the transaction is complete.
       */

      const b6 = builder.finalize()
      console.log(b6)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('make a transaction with 1 transparent input 1 transparent output 1 spend 2 shielded outputs', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      // In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
      // For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
      // She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
      // The inputs to the initialization is therefore:
      // - one transparent input and one transparent output
      // - one shielded spend notes and two shielded output notes.
      // She takes a transaction fee according to ZIP-0317 and all leftovers is sent shielded to her own address.
      // All this info is gathered from the UI and put in the correct jsons.

      const tx_input_data = TX_INPUT_DATA[3]
      const {
        t_in: [tin1],
        t_out: [tout1],
        s_spend: [s_spend1],
        s_output: [s_out1, s_out2],
      } = tx_input_data
      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      // The inputs to the get_inittx_data function are the inputs to the transaction.
      // The output is a blob that can be send to the ledger device.

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      // The output of the get_inittx_data can be send to the ledger.
      // The ledger will check this data and show the inputs on screen for verification.
      // If confirmed, the ledger also computes the randomness needed for :
      //     - The shielded spends
      //     - the shielded outputs

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      const testname = `${m.prefix.toLowerCase()}-1-tr-in-1-tr-out-1-spend-2-sh-out`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit

      // const req = await app.initNewTx(ledgerblob_initdata);
      console.log(req)
      expect(req.txdata.length).toEqual(32)

      // Check the hash of the return
      let hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      let h = hash.digest('hex')
      expect(req.txdata).toEqual(h)

      // Now we start building the transaction using the builder.
      //

      // To add transparent inputs to the builder, we don't need fresh information from the ledger.
      // The builder does need the secp256k1 public key belonging to the address.
      // The builder also need outpoint from the blockchain.

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      const bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

      // To add a transparent output, the builder does not need anything other than the input to the inittx.
      const t_out_data = {
        address: tout1.address,
        value: tout1.value,
      }

      const bt1 = builder.add_transparent_output(t_out_data)
      console.log(bt1)

      // To add a shielded spend to the builder, we need:
      //     - the proof generation key belonging to the spend address (proofkey)
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the random verification key (alpha)
      // All this is retrieved from the ledger using a extractspenddata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.

      const req2 = await app.extractSpendData()
      console.log(req2)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      // The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      // It furthermore uses the spend address and value from the UI.

      const spendj1 = {
        proofkey: req2.key,
        rcv: req2.rcv,
        alpha: req2.alpha,
        address: s_spend1.address,
        value: s_spend1.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      // The builder adds the spend to its state.

      const b1 = builder.add_sapling_spend(spendj1)
      console.log(b1)

      // At this point we added all spends.
      // We cannot get more spend data from the ledger.
      // We now start the shielded output process.

      // To add a shielded output to the builder, we need:
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the note commitment (rcm)
      //     - the randomness needed for the random encryption key (esk)
      // All this is retrieved from the ledger using a extractoutputdata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.

      const req4 = await app.extractOutputData()
      console.log(req4)

      // The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      // It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      // It furthermore uses the output address, value and memo from the UI.

      const outj1 = {
        rcv: req4.rcv,
        rseed: req4.rseed,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hashSeedRaw,
      }

      // The builder adds the shielded output to its state.

      const b3 = builder.add_sapling_output(outj1)
      console.log(b3)

      // This process needs to be repeated for the second output.
      // Note that this output address belongs to Alice.

      const req5 = await app.extractOutputData()
      console.log(req5)

      const outj2 = {
        rcv: req5.rcv,
        rseed: req5.rseed,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hashSeedRaw,
      }

      const b4 = builder.add_sapling_output(outj2)
      console.log(b4)

      // We are now done with adding the shielded outputs to the builder.
      // In fact, we are done adding all inputs the builder needs for this transaction.
      // We now let the builder build the transaction, including the ZK proofs.
      // The builder returns a txdata blob.
      // The ledger needs this blob to validate the correctness of the tx.

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, tx_version)

      // Now the ledger will validate the txdata blob.
      // For this, it uses the input from inittx to verify.
      // If all checks are ok, the ledger signs the transaction.

      const req6 = await app.checkAndSign(ledgerblob_txdata, tx_version)
      console.log(req6)

      // Check the hash of the return

      hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_txdata))
      h = hash.digest('hex')
      expect(req6.signdata).toEqual(h)

      // The builder needs the spend signatures to add it to the transaction blob.
      // We need to do this one by one.
      // So we first gather all signatures we need.

      const req7 = await app.extractSpendSignature()
      console.log(req7)

      // The builder also needs the transparent signature for the transparent input.

      const req9 = await app.extractTransparentSig()
      console.log(req9)

      // At this point we gathered all signatures.
      // We now add these signatures to the builder.
      // Note that for this transaction, we do not have any transparent signatures.

      const signatures = {
        transparent_sigs: [req9.signature],
        sapling_sigs: [req7.signature],
      }

      const b5 = builder.add_signatures(signatures)
      console.log(b5)

      await takeLastSnapshot(testname, last_index, sim)
      // The builder is now done and the transaction is complete.

      const b6 = builder.finalize()
      console.log(b6)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('make a transaction with 2 transparent input 2 transparent output', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      // In this test, Alice wants to send 10000 ZEC to Bob transparent and send the change back to herself.
      

      const tx_input_data = TX_INPUT_DATA[4]
      const {
        t_in: [tin1],
        t_out: [tout1, tout2],
      } = tx_input_data
      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      const testname = `${m.prefix.toLowerCase()}-2-tr-in-2-tr-out`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit
      expect(req.txdata.length).toEqual(32)

      let hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      let h = hash.digest('hex')
      expect(req.txdata).toEqual(h)

      // Now we start building the transaction using the builder.
      

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      let bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

      const t_data2 = {
        outp: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      bt0 = builder.add_transparent_input(t_data2)
      console.log(bt0)

      // To add a transparent output, the builder does not need anything other than the input to the inittx.
       

      const bt1 = builder.add_transparent_output(tout1)
      console.log(bt1)

      const bt2 = builder.add_transparent_output(tout2)
      console.log(bt2)

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, tx_version)

      const req6 = await app.checkAndSign(ledgerblob_txdata, tx_version)
      console.log(req6)

      hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_txdata))
      h = hash.digest('hex')
      expect(req6.signdata).toEqual(h)

      const req9 = await app.extractTransparentSig()
      console.log(req9)

      const req10 = await app.extractTransparentSig()
      console.log(req10)

      // At this point we gathered all signatures.
      // We now add these signatures to the builder.
      // Note that for this transaction, we do not have any transparent signatures.
       

      const signatures = {
        transparent_sigs: [req9.signature, req10.signature],
        sapling_sigs: [],
      }

      const b5 = builder.add_signatures(signatures)
      console.log(b5)

      await takeLastSnapshot(testname, last_index, sim)

      // The builder is now done and the transaction is complete.
       

      const b6 = builder.finalize()
      console.log(b6)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('extracting signatures without checkandsign', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      // In this test, we try to extract signatures without having done the checks and signing.
      
      const tx_input_data = TX_INPUT_DATA[5]

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      const testname = `${m.prefix.toLowerCase()}-ext-sig-without-checkandsign`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit
      expect(req.txdata.length).toEqual(32)

      const req2 = await app.extractSpendData()
      console.log(req2)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      const req3 = await app.extractSpendData()
      console.log(req3)
      expect(req3.keyRaw).toEqual(expected_proofkeyRaw)

      const req4 = await app.extractOutputData()
      console.log(req4)

      const req5 = await app.extractOutputData()
      console.log(req5)

      const req7 = await app.extractSpendSignature()
      console.log(req7)

      const req8 = await app.extractTransparentSig()
      console.log(req8)

      await takeLastSnapshot(testname, last_index, sim)
    } finally {
      await sim.close()
    }
  })
})

describe('Failing transactions', function () {
  test.each(models)('try to extract spend data without calling inittx', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const req = await app.extractSpendData()
      expect(req.keyRaw).toEqual(undefined)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('extracting output without extracting spend data', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      // In this test, we try to extract signatures without having done the checks and signing.
      

      const tx_input_data = TX_INPUT_DATA[5]

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-ext-output-without-ext-spend-data`)

      const req = await reqinit

      expect(req.txdata.length).toEqual(32)

      const req4 = await app.extractOutputData()
      console.log(req4)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('extracting more signatures than needed for tx', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      // In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
      // For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
      // She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
      // The inputs to the initialization is therefore:
      // - one transparent input and one transparent output
      // - one shielded spend notes and two shielded output notes.
      // She takes a transaction fee accorind to ZIP-0317 and all leftovers is sent shielded to her own address.
      // All this info is gathered from the UI and put in the correct jsons.
      

      const tx_input_data = TX_INPUT_DATA[3]
      const {
        t_in: [tin1],
        t_out: [tout1],
        s_spend: [s_spend1],
        s_output: [s_out1, s_out2],
      } = tx_input_data
      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      // The inputs to the get_inittx_data function are the inputs to the transaction.
      // The output is a blob that can be send to the ledger device.
      

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      // The output of the get_inittx_data can be send to the ledger.
      // The ledger will check this data and show the inputs on screen for verification.
      // If confirmed, the ledger also computes the randomness needed for :
      //     - The shielded spends
      //     - the shielded outputs
       

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-ext-more-sigs-than-needed-for-tx`)

      const req = await reqinit
      expect(req.txdata.length).toEqual(32)

      // Now we start building the transaction using the builder.
      //

      // To add transparent inputs to the builder, we don't need fresh information from the ledger.
      // The builder does need the secp256k1 public key belonging to the address.
      // The builder also need outpoint from the blockchain.
       

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      const bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

      // To add a transparent output, the builder does not need anything other than the input to the inittx.
       

      const bt1 = builder.add_transparent_output(tout1)
      console.log(bt1)

      // To add a shielded spend to the builder, we need:
      //     - the proof generation key belonging to the spend address (proofkey)
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the random verification key (alpha)
      // All this is retrieved from the ledger using a extractspenddata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.
       

      const req2 = await app.extractSpendData()
      console.log(req2)

      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      // The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      // It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      // It furthermore uses the spend address and value from the UI.
       

      const spendj1 = {
        proofkey: req2.key,
        rcv: req2.rcv,
        alpha: req2.alpha,
        address: s_spend1.address,
        value: s_spend1.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      // The builder adds the spend to its state.
       

      const b1 = builder.add_sapling_spend(spendj1)
      console.log(b1)

      // At this point we added all spends.
      // We cannot get more spend data from the ledger.
      // We now start the shielded output process.
       

      // To add a shielded output to the builder, we need:
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the note commitment (rcm)
      //     - the randomness needed for the random encryption key (esk)
      // All this is retrieved from the ledger using a extractoutputdata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.
       

      const req4 = await app.extractOutputData()
      console.log(req4)

      // The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      // It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      // It furthermore uses the output address, value and memo from the UI.
      

      const outj1 = {
        rcv: req4.rcv,
        rseed: req4.rseed,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hashSeedRaw,
      }

      // The builder adds the shielded output to its state.
       

      const b3 = builder.add_sapling_output(outj1)
      console.log(b3)

      // This process needs to be repeated for the second output.
      // Note that this output address belongs to Alice.
       

      const req5 = await app.extractOutputData()
      console.log(req5)

      const outj2 = {
        rcv: req5.rcv,
        rseed: req5.rseed,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hashSeedRaw,
      }

      const b4 = builder.add_sapling_output(outj2)
      console.log(b4)

      // We are now done with adding the shielded outputs to the builder.
      // In fact, we are done adding all inputs the builder needs for this transaction.
      // We now let the builder build the transaction, including the ZK proofs.
      // The builder returns a txdata blob.
      // The ledger needs this blob to validate the correctness of the tx.
       

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, tx_version)

      // Now the ledger will validate the txdata blob.
      // For this, it uses the input from inittx to verify.
      // If all checks are ok, the ledger signs the transaction.
       

      const req6 = await app.checkAndSign(ledgerblob_txdata, tx_version)
      console.log(req6)

      // The builder needs the spend signatures to add it to the transaction blob.
      // We need to do this one by one.
      // So we first gather all signatures we need.
       

      const req7 = await app.extractSpendSignature()
      console.log(req7)

      // The builder also needs the transparent signature for the transparent input.
       

      const req9 = await app.extractTransparentSig()
      console.log(req9)

      // At this point we gathered all signatures.
      // We now add these signaturs to the builder.
      // Note that for this transaction, we do not have any transparent signatures.
       

      // Below are the failing extractions
       

      const req10 = await app.extractSpendSignature()
      console.log(req10)

      const req11 = await app.extractTransparentSig()
      console.log(req11)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('not using ledger randomness for tx', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      // In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
      // For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
      // She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
      // The inputs to the initialization is therefore:
      // - one transparent input and one transparent output
      // - one shielded spend notes and two shielded output notes.
      // She takes a transaction fee according to ZIP-0317 and all leftovers is sent shielded to her own address.
      // All this info is gathered from the UI and put in the correct jsons.
      

      const tx_input_data = TX_INPUT_DATA[3]
      const {
        t_in: [tin1],
        t_out: [tout1],
        s_spend: [s_spend1],
        s_output: [s_out1, s_out2],
      } = tx_input_data
      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      // The inputs to the get_inittx_data function are the inputs to the transaction.
      // The output is a blob that can be send to the ledger device.
      

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(Buffer.from(ledgerblob_initdata).toString('hex'))

      // The output of the get_inittx_data can be send to the ledger.
      // The ledger will check this data and show the inputs on screen for verification.
      // If confirmed, the ledger also computes the randomness needed for :
      //     - The shielded spends
      //     - the shielded outputs
       

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      // check for error
      const events = await sim.getEvents()
      console.log(events)
      events.forEach((element: any) => {
        expect(element['text'].includes('ERROR')).toBeFalsy()
      })

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-not-using-ledger-rnd-for-tx`)

      const req = await reqinit
      expect(req.txdata.length).toEqual(32)

      // Now we start building the transaction using the builder.
      //

      // To add transparent inputs to the builder, we dont need fresh information from the ledger.
      // The builder does need the secp256k1 public key belonging to the address.
      // The builder also need outpoint from the blockchain.
       

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      const bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

      // To add a transparent output, the builder does not need anything other than the input to the inittx.
       

      const bt1 = builder.add_transparent_output(tout1)
      console.log(bt1)

      // To add a shielded spend to the builder, we need:
      //     - the proof generation key belonging to the spend address (proofkey)
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the random verification key (alpha)
      // All this is retrieved from the ledger using a extractspenddata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.
       

      const req2 = await app.extractSpendData()
      console.log(req2)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      // The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      // It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      // It furthermore uses the spend address and value from the UI.
       

      const spendj1 = {
        proofkey: req2.key,
        rcv: req2.rcv,
        alpha: req2.alpha,
        address: s_spend1.address,
        value: s_spend1.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      // The builder adds the spend to its state.
       

      const b1 = builder.add_sapling_spend(spendj1)
      console.log(b1)

      // At this point we added all spends.
      // We cannot get more spend data from the ledger.
      // We now start the shielded output process.
       

      // To add a shielded output to the builder, we need:
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the note commitment (rcm)
      //     - the randomness needed for the random encryption key (esk)
      // All this is retrieved from the ledger using a extractoutputdata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.
       

      const req4 = await app.extractOutputData()
      console.log(req4)

      // The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      // It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      // It furthermore uses the output address, value and memo from the UI.
      

      const outj1 = {
        rcv: req4.rcv,
        rseed: req4.rseed,
        ovk: null,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hashSeedRaw,
      }

      // The builder adds the shielded output to its state.
       

      const b3 = builder.add_sapling_output(outj1)
      console.log(b3)

      // This process needs to be repeated for the second output.
      // Note that this output address belongs to Alice.
       

      const req5 = await app.extractOutputData()
      console.log(req5)

      // Here we use the wrong rseed!!
       

      const outj2 = {
        rcv: req5.rcv,
        rseed: req5.rseed,
        ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hashSeedRaw,
      }

      const b4 = builder.add_sapling_output(outj2)
      console.log(b4)

      // We are now done with adding the shielded outputs to the builder.
      // In fact, we are done adding all inputs the builder needs for this transaction.
      // We now let the builder build the transaction, including the ZK proofs.
      // The builder returns a txdata blob.
      // The ledger needs this blob to validate the correctness of the tx.
       

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, tx_version)

      // Now the ledger will validate the txdata blob.
      // For this, it uses the input from inittx to verify.
      // If all checks are ok, the ledger signs the transaction.
       

      const req6 = await app.checkAndSign(ledgerblob_txdata, tx_version)
      console.log(req6)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('use other address in builder than in inittx', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      // In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
      // For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
      // She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
      // The inputs to the initialization is therefore:
      // - one transparent input and one transparent output
      // - one shielded spend notes and two shielded output notes.
      // She takes a transaction fee according to ZIP-0317 and all leftovers is sent shielded to her own address.
      // All this info is gathered from the UI and put in the correct jsons.

      const tx_input_data = TX_INPUT_DATA[3]
      const {
        t_in: [tin1],
        t_out: [tout1],
        s_spend: [s_spend1],
        s_output: [s_out1, s_out2],
      } = tx_input_data

      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      // The inputs to the get_inittx_data function are the inputs to the transaction.
      // The output is a blob that can be send to the ledger device.
      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      // The output of the get_inittx_data can be send to the ledger.
      // The ledger will check this data and show the inputs on screen for verification.
      // If confirmed, the ledger also computes the randomness needed for :
      //     - The shielded spends
      //     - the shielded outputs

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-builder-addr-diff-to-inittx-addr`)

      const req = await reqinit

      expect(req.txdata.length).toEqual(32)

      // Now we start building the transaction using the builder.
      //

      // To add transparent inputs to the builder, we dont need fresh information from the ledger.
      // The builder does need the secp256k1 public key belonging to the address.
      // The builder also need outpoint from the blockchain.

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      const bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

      // To add a transparent output, the builder does not need anything other than the input to the inittx.

      const bt1 = builder.add_transparent_output(tout1)
      console.log(bt1)

      // To add a shielded spend to the builder, we need:
      //     - the proof generation key belonging to the spend address (proofkey)
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the random verification key (alpha)
      // All this is retrieved from the ledger using a extractspenddata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.

      const req2 = await app.extractSpendData()
      console.log(req2)

      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      // The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      // It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      // It furthermore uses the spend address and value from the UI.

      const spendj1 = {
        proofkey: req2.key,
        rcv: req2.rcv,
        alpha: req2.alpha,
        address: s_spend1.address,
        value: s_spend1.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      // The builder adds the spend to its state.

      const b1 = builder.add_sapling_spend(spendj1)
      console.log(b1)

      // At this point we added all spends.
      // We cannot get more spend data from the ledger.
      // We now start the shielded output process.
      //

      // To add a shielded output to the builder, we need:
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the note commitment (rcm)
      //     - the randomness needed for the random encryption key (esk)
      // All this is retrieved from the ledger using a extractoutputdata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.

      const req4 = await app.extractOutputData()
      console.log(req4)

      // The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      // It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      // It furthermore uses the output address, value and memo from the UI.

      const outj1 = {
        rcv: req4.rcv,
        rseed: req4.rseed,
        ovk: null,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hashSeedRaw,
      }

      // The builder adds the shielded output to its state.

      const b3 = builder.add_sapling_output(outj1)
      console.log(b3)

      // This process needs to be repeated for the second output.
      // Note that this output address belongs to Alice.

      const req5 = await app.extractOutputData()
      console.log(req5)

      // Here we use the wrong address and send the change funds to Bob instead.

      const outj2 = {
        rcv: req5.rcv,
        rseed: req5.rseed,
        ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
        address: s_out1.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hashSeedRaw,
      }

      const b4 = builder.add_sapling_output(outj2)
      console.log(b4)

      // We are now done with adding the shielded outputs to the builder.
      // In fact, we are done adding all inputs the builder needs for this transaction.
      // We now let the builder build the transaction, including the ZK proofs.
      // The builder returns a txdata blob.
      // The ledger needs this blob to validate the correctness of the tx.

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, tx_version)

      // Now the ledger will validate the txdata blob.
      // For this, it uses the input from inittx to verify.
      // If all checks are ok, the ledger signs the transaction.

      const req6 = await app.checkAndSign(ledgerblob_txdata, tx_version)
      console.log(req6)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('try non ZIP-0317 fee', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      //use stringify+parse for deep copy
      const tx_input_data = JSON.parse(JSON.stringify(TX_INPUT_DATA[3]))
      tx_input_data.s_output[1].value -= 500 //change fee to something invalid

      // The inputs to the get_inittx_data function are the inputs to the transaction.
      // The output is a blob that can be send to the ledger device.
      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      // The output of the get_inittx_data can be send to the ledger.
      // The ledger will check this data and show the inputs on screen for verification.
      // If confirmed, the ledger also computes the randomness needed for :
      //     - The shielded spends
      //     - the shielded outputs
      const reqinit = app.initNewTx(ledgerblob_initdata)

      const req = await reqinit

      console.log(req)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('extract data after tx reject', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name, rejectKeyword: m.name === 'stax' ? 'Hold' : '' })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      // In this test, Alice wants to send 55000 ZEC to Bob.
      // For this she needs two notes of 50000 ZEC sent to her address belonging to path: 1000.
      // The inputs to the initialization is therefore two spend notes and two output notes.
      // All this info is gathered from the UI and put in the correct jsons.
      const tx_input_data = TX_INPUT_DATA[5]

      // The inputs to the get_inittx_data function are the inputs to the transaction.
      // The output is a blob that can be send to the ledger device.
      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      // The output of the get_inittx_data can be send to the ledger.
      // The ledger will check this data and show the inputs on screen for verification.
      // If confirmed, the ledger also computes the randomness needed for :
      //     - The shielded spends
      //     - the shielded outputs
      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndReject('.', `${m.prefix.toLowerCase()}-ext-data-after-tx-reject`)

      const req = await reqinit

      console.log(req)

      // Try to extract data after a rejection of a transaction
      const req0 = await app.extractSpendData()
      console.log(req0)

      const req1 = await app.extractOutputData()
      console.log(req1)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('make a transaction unsupported transaction version', async function (m) {
    const sim = new Zemu(m.path)
    const bad_tx_version = 7
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      const tx_input_data = TX_INPUT_DATA[5]
      const {
        s_spend: [s_spend1, s_spend2],
        s_output: [s_out1, s_out2],
      } = tx_input_data
      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(Buffer.from(ledgerblob_initdata).byteLength)

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.navigateUntilText('', '', sim.startOptions.approveKeyword, true, false) // we don't take snapshots here
      await sim.deleteEvents()

      const req = await reqinit

      console.log(req)

      expect(req.txdata.length).toEqual(32)

      const hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      const h = hash.digest('hex')
      expect(req.txdata).toEqual(h)

      const req2 = await app.extractSpendData()
      console.log(req2)

      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      const spendj1 = {
        proofkey: req2.key,
        rcv: req2.rcv,
        alpha: req2.alpha,
        address: s_spend1.address,
        value: s_spend1.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      // The builder adds the spend to its state.
      const b1 = builder.add_sapling_spend(spendj1)
      console.log(b1)

      // We need to repeat the above process for the second spend.
      const req3 = await app.extractSpendData()
      console.log(req3)
      expect(req3.keyRaw).toEqual(expected_proofkeyRaw)

      const spendj2 = {
        proofkey: req3.key,
        rcv: req3.rcv,
        alpha: req3.alpha,
        address: s_spend2.address,
        value: s_spend2.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      const b2 = builder.add_sapling_spend(spendj2)
      console.log(b2)

      // At this point we added all spends.
      // We cannot get more spend data from the ledger.
      // We now start the shielded output process.

      // To add a shielded output to the builder, we need:
      //     - the randomness needed for the value commitment (rcv)
      //     - the randomness needed for the note commitment (rcm)
      //     - the randomness needed for the random encryption key (esk)
      // All this is retrieved from the ledger using a extractoutputdata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.
      const req4 = await app.extractOutputData()
      console.log(req4)

      // The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      // It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      // It furthermore uses the output address, value and memo from the UI.
      const outj1 = {
        rcv: req4.rcv,
        rseed: req4.rseed,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hashSeedRaw,
      }

      console.log(req4.hashSeedRaw)
      // The builder adds the shielded output to its state.
      const b3 = builder.add_sapling_output(outj1)
      console.log(b3)

      // This process needs to be repeated for the second output.
      // Note that this output address belongs to Alice.
      // There is no concept of a "change address" as all inputs and outputs need to be known in advance for the ledger verification on screen.
      // The UI needs to take care of this before initializing a transaction to the ledger.
      const req5 = await app.extractOutputData()
      console.log(req5)

      console.log(req5.hashSeedRaw)

      const outj2 = {
        rcv: req5.rcv,
        rseed: req5.rseed,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hashSeedRaw,
      }

      const b4 = builder.add_sapling_output(outj2)
      console.log(b4)

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, bad_tx_version)

      const req6 = await app.checkAndSign(ledgerblob_txdata, bad_tx_version)
    } finally {
      await sim.close()
    }
  })
})


