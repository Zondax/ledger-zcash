/** ******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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

import Zemu, { ButtonKind } from '@zondax/zemu'
import { defaultOptions, models } from './_config'
import ZCashApp from '@zondax/ledger-zcash'
import { get_inittx_data, OUTPUT_PATH, SPEND_PATH, ZcashBuilderBridge } from '@zondax/zcashtools'
import { fee_for, TX_INPUT_DATA } from './_vectors'
import crypto from 'crypto'
import { takeLastSnapshot } from './utils'
jest.setTimeout(60000)

const tx_version = 0x05

describe('tx methods', function () {
  test.concurrent.each(models)('txinit', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const tx_input_data = TX_INPUT_DATA[0]

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-txinit`)

      const req = await reqinit

      console.log(req)
      expect(req.txdataRaw.length).toEqual(32)
      expect(req.txdata.length).toEqual(64)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('PARTIAL1 - make a transaction with 2 spend 2 outputs', async function (m) {
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
      // const {
      //   s_spend: [s_spend1, s_spend2],
      //   s_output: [s_out1, s_out2],
      // } = tx_input_data

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
      await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit

      console.log(req)
      expect(req.txdataRaw.length).toEqual(32)
      expect(req.txdata.length).toEqual(64)

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
        address: tx_input_data.s_spend[0].address,
        value: tx_input_data.s_spend[0].value,
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
        address: tx_input_data.s_spend[1].address,
        value: tx_input_data.s_spend[1].value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      const b2 = builder.add_sapling_spend(spendj2)
      console.log(b2)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('PARTIAL2 - make a transaction with 2 spend 2 outputs', async function (m) {
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
      expect(req.txdata.length).toEqual(64)

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
      expect(b1).toBeTruthy()

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
      expect(b2).toBeTruthy()

      // All spends added. No more spend data can be retrieved from the ledger.
      // Start the shielded output process.

      // To add a shielded output to the builder, we need:
      // - the randomness needed for the value commitment (rcv)
      // - the randomness needed for the note commitment (rcm)
      // - the randomness needed for the random encryption key (esk)
      // All this is retrieved from the ledger using an extractoutputdata call with no inputs.
      // The ledger already knows how much data it needs to send after the inittx call.

      const req4 = await app.extractOutputData()
      console.log(req4)
      expect(req4.hashSeed?.length).toEqual(64)

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
        hash_seed: new Uint8Array(req4.hashSeedRaw!),
      }

      // The builder adds the shielded output to its state.
      const b3 = builder.add_sapling_output(outj1)
      expect(b3).toBeTruthy()

      // This process needs to be repeated for the second output.
      // Note that this output address belongs to Alice.
      // There is no concept of a "change address" as all inputs and outputs need to be known in advance for the ledger verification on screen.
      // The UI needs to take care of this before initializing a transaction to the ledger.

      const req5 = await app.extractOutputData()
      console.log(req5)
      // this field is optional and should be empty here
      expect(req5.hashSeed).toBeUndefined()

      const outj2 = {
        rcv: req5.rcv,
        rseed: req5.rseed,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: new Uint8Array(req5.hashSeedRaw!),
      }

      const b4 = builder.add_sapling_output(outj2)
      expect(b4).toBeTruthy()

      // All shielded outputs added to the builder.
      // All inputs the builder needs for this transaction are now added.
      // Let the builder build the transaction, including the ZK proofs.
      // The builder returns a txdata blob.
      // The ledger needs this blob to validate the correctness of the tx.

      console.log('Now call the builder....')

      const ledgerblob_txdata = Buffer.from(builder.build(SPEND_PATH, OUTPUT_PATH, tx_version))
      expect(ledgerblob_txdata).toBeDefined()

      // Now the ledger will validate the txdata blob.
      // For this, it uses the input from inittx to verify.
      // If all checks are ok, the ledger signs the transaction.
      // console.log(ledgerblob_txdata.slice(10 * 250 + 116))

      const req6 = await app.checkAndSign(ledgerblob_txdata, tx_version)
      expect(req6).toBeDefined()
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
        transparent_sigs: [] as string[],
        spend_sigs: [req7.signature, req8.signature],
      }

      const b5 = builder.add_signatures(signatures)
      expect(b5).toBeTruthy()

      await takeLastSnapshot(testname, last_index, sim)

      // The builder is now done and the transaction is complete.
      const b6 = builder.finalize()
      expect(b6).toBeDefined()

      console.log(b6)
    } finally {
      await sim.close()
    }
  })
})
