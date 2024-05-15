/** ******************************************************************************
 *  (c) 2020 Zondax AG
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

const crypto = require('crypto')
const tx_version = 0x05

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
}

jest.setTimeout(600000)

async function takeLastSnapshot(testname: string, index: number, sim: Zemu) {
  await sim.waitUntilScreenIs(sim.getMainMenuSnapshot())
  await sim.takeSnapshotAndOverwrite('.', testname, index)
  sim.compareSnapshots('.', testname, index)
}

describe('Nullifier', function() {
  test.concurrent.each(models)('get nullifier account 0x01', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const path = 0x01
      const pos = BigInt(0)
      const cmu = Buffer.from('df7e8d004bd4e32f2fb022efd5aa4bcdc7c89f919bbac9309d6e21ca83ce93ea', 'hex')

      const promise_resp = app.getNullifierSapling(path, pos, cmu)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.clickRight()
      await sim.clickRight()
      await sim.clickBoth()

      const resp = await promise_resp
      expect(resp.returnCode).toEqual(0x9000)

      const expected_nfRaw = '42cf7491d0b97afc77fb463054f6554ecad6dd79ce1c9e412058d9544cadef8f'

      if ('nfRaw' in resp) {
        const nfRaw = resp.nfRaw.toString('hex')
        console.log(nfRaw)
        expect(nfRaw).toEqual(expected_nfRaw)
      } else {
        fail('Expected property nfRaw is missing in the response.')
      }
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get nullifier account 0xFF', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const path = 0xFF
      const pos = BigInt(0)
      const cmu = Buffer.from('df7e8d004bd4e32f2fb022efd5aa4bcdc7c89f919bbac9309d6e21ca83ce93ea', 'hex')

      const promise_resp = app.getNullifierSapling(path, pos, cmu)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.clickRight()
      await sim.clickRight()
      await sim.clickBoth()

      const resp = await promise_resp
      expect(resp.returnCode).toEqual(0x9000)

      const expected_nfRaw = 'ca1466808b1d503eea8b1fad31e16379247f8bf9fbe2fcb046d28b82af2e1e7d'

      if ('nfRaw' in resp) {
        const nfRaw = resp.nfRaw.toString('hex')
        console.log(nfRaw)
        expect(nfRaw).toEqual(expected_nfRaw)
      } else {
        fail('Expected property nfRaw is missing in the response.')
      }
    } finally {
      await sim.close()
    }
  })
})

describe('Get keys', function () {
  test.concurrent.each(models)('get ivk', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const ivkreq = app.getIvkSapling(1000)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 60000)

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-ivk`)

      const ivk = await ivkreq
      console.log(ivk)
      expect(ivk.returnCode).toEqual(0x9000)

      const expected_ivkRaw = '6dfadf175921e6fbfa093c8f7c704a0bdb07328474f56c833dfcfa5301082d03'
      const expected_div = 'c69e979c6763c1b09238dc'

      const ivkRaw = ivk.ivkRaw.toString('hex')
      const default_div = ivk.defaultDiversifier.toString('hex')

      expect(ivkRaw).toEqual(expected_ivkRaw)
      expect(default_div).toEqual(expected_div)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get outgoing viewing key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const ovkreq = app.getOvkSapling(1000)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 60000)

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-ovk`)

      const ovk = await ovkreq
      console.log(ovk)
      expect(ovk.returnCode).toEqual(0x9000)

      const expected_ovkRaw = '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca'
      const ovkRaw = ovk.ovkRaw.toString('hex')
      expect(ovkRaw).toEqual(expected_ovkRaw)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('Get full viewing key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())
      const fvkreq = app.getFvkSapling(1000)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 60000)

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-fvk`)

      const fvk = await fvkreq

      console.log(fvk)
      expect(fvk.returnCode).toEqual(0x9000)

      const expected_akRaw = '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a'
      const akRaw = fvk.akRaw.toString('hex')
      expect(akRaw).toEqual(expected_akRaw)

      const expected_nkRaw = 'a93349ed31a96abd9b07fb04daaad69a51de16e4ac8dbcc7e001779668d08dc7'
      const nkRaw = fvk.nkRaw.toString('hex')
      expect(nkRaw).toEqual(expected_nkRaw)

      const expected_ovkRaw = '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca'
      const ovkRaw = fvk.ovkRaw.toString('hex')
      expect(ovkRaw).toEqual(expected_ovkRaw)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('Get nullifier', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const cm = Buffer.from([
        33, 201, 70, 152, 202, 50, 75, 76, 186, 206, 41, 29, 39, 171, 182, 138, 10, 175, 39, 55, 220, 69, 86, 84, 28, 127, 205, 232, 206,
        17, 221, 232,
      ])

      //const pos = Uint8Array.from([2578461368])
      const pos = BigInt(2578461368)
      const nfreq = app.getNullifierSapling(1000, pos, cm)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 60000)

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-nullifier`)
      const nf = await nfreq

      console.log(nf)
      expect(nf.returnCode).toEqual(0x9000)

      const expected_nf = Buffer.from([
        37, 241, 242, 207, 94, 44, 43, 195, 29, 7, 182, 111, 77, 84, 240, 144, 173, 137, 177, 152, 137, 63, 18, 173, 174, 68, 125, 223, 132,
        226, 20, 90,
      ])

      const nfRaw = nf.nfRaw
      expect(expected_nf).toEqual(nfRaw)
    } finally {
      await sim.close()
    }
  })
})

describe('Addresses and diversifiers', function () {
  test.concurrent.each(models)('get shielded address with div', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const path = 1000
      const div = Buffer.from('c69e979c6763c1b09238dc', 'hex')

      const addr = await app.getAddrDivSapling(path, div)
      console.log(addr)
      expect(addr.returnCode).toEqual(0x9000)

      const expected_addrRaw = 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667'
      const expected_addr = 'zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3'

      const addrRaw = addr.addressRaw.toString('hex')
      expect(addrRaw).toEqual(expected_addrRaw)
      expect(addr.address).toEqual(expected_addr)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show shielded address with div', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const path = 1000
      const div = Buffer.from('c69e979c6763c1b09238dc', 'hex')

      const addrreq = app.showAddrDiv(path, div)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 60000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show-shielded-addr`)
      const addr = await addrreq

      console.log(addr)
      expect(addr.returnCode).toEqual(0x9000)

      const expected_addrRaw = 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667'

      const addrRaw = addr.addressRaw.toString('hex')
      expect(addrRaw).toEqual(expected_addrRaw)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get div list with startindex', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const startindex = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

      const divlist = await app.getDivListSapling(1000, startindex)
      console.log(divlist)
      expect(divlist.returnCode).toEqual(0x9000)

      const first_div = 'c69e979c6763c1b09238dc'

      const first_divRaw = divlist.divlist[0]
      expect(first_div).toEqual(first_divRaw)
    } finally {
      await sim.close()
    }
  })
})

describe('End to end transactions', function () {
  test.each(models)('make a transaction with 2 spend 2 outputs', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      /*
       In this test, Alice wants to send 55000 ZEC to Bob.
       For this she needs two notes of 50000 ZEC sent to her address belonging to path: 1000.
       The inputs to the initialization is therefore two spend notes and two output notes.
       She takes a transaction fee according to ZIP-0317.
       All this info is gathered from the UI and put in the correct jsons.
        */

      const tx_input_data = TX_INPUT_DATA[0]
      const {
        s_spend: [s_spend1, s_spend2],
        s_output: [s_out1, s_out2],
      } = tx_input_data

      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      /*
       The inputs to the get_inittx_data function are the inputs to the transaction.
       The output is a blob that can be sent to the ledger device.
       */

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(Buffer.from(ledgerblob_initdata).byteLength)

      /*
  //     The output of the get_inittx_data can be sent to the ledger.
  //     The ledger will check this data and show the inputs on screen for verification.
  //     If confirmed, the ledger also computes the randomness needed for :
  //         - The shielded spends
  //         - the shielded outputs
  //      */

      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      const testname = `${m.prefix.toLowerCase()}-2-spend-2-out`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit

      console.log(req)
      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      /*
       Check the hash of the return
        */
      let hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      let h = hash.digest('hex')
      expect(req.txdata.toString('hex')).toEqual(h)

      /*
       Now we start building the transaction using the builder.
       /*

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
      expect(req2.returnCode).toEqual(0x9000)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      /*
       The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
       It furthermore uses the spend address and value from the UI.
       We also need the witness from the blockchain, which is now a fake/incorrect one.
        */

      const spendj1 = {
        proofkey: req2.keyRaw,
        rcv: req2.rcvRaw,
        alpha: req2.alphaRaw,
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
       We need to repeat the above process for the second spend.
        */

      const req3 = await app.extractSpendData()
      console.log(req3)
      expect(req3.returnCode).toEqual(0x9000)
      expect(req3.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)

      const spendj2 = {
        proofkey: req3.keyRaw,
        rcv: req3.rcvRaw,
        alpha: req3.alphaRaw,
        address: s_spend2.address,
        value: s_spend2.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      const b2 = builder.add_sapling_spend(spendj2)
      console.log(b2)

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

      const req4 = await app.extractoutputdata()
      console.log(req4)
      expect(req4.returnCode).toEqual(0x9000)

      /*
       The builder needs the data retrieved from the ledger (rcv, rcm, esk)
       It CAN send along an outgoing viewing key (OVK), can also be all zero's.
       It furthermore uses the output address, value and memo from the UI.
       */

      const outj1 = {
        rcv: req4.rcvRaw,
        rseed: req4.rseedRaw,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hashSeed: req4.hashSeed,
      }

      console.log(req4.hashSeed)
      /*
       The builder adds the shielded output to its state.
        */

      const b3 = builder.add_sapling_output(outj1)
      console.log(b3)

      /*
       This process needs to be repeated for the second output.
       Note that this output address belongs to Alice.
       There is no concept of a "change address" as all inputs and outputs need to be known in advance for the ledger verification on screen.
       The UI needs to take care of this before initializing a transaction to the ledger.
        */

      const req5 = await app.extractoutputdata()
      console.log(req5)
      expect(req5.returnCode).toEqual(0x9000)

      console.log(req5.hashSeed)

      const outj2 = {
        rcv: req5.rcvRaw,
        rseed: req5.rseedRaw,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hash_seed,
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
      //      console.log(ledgerblob_txdata.slice(10 * 250 + 116))

      const req6 = await app.checkAndSign(ledgerblob_txdata, tx_version)
      console.log(req6)
      expect(req6.returnCode).toEqual(0x9000)

      /*
       Check the hash of the return
       */

      hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_txdata))
      h = hash.digest('hex')
      expect(req6.signdata.toString('hex')).toEqual(h)

      /*
       The builder needs these signatures to add it to the transaction blob.
       We need to do this one by one.
       So we first gather all signatures we need.
        */

      const req7 = await app.extractSpendSig()
      console.log(req7)
      expect(req7.returnCode).toEqual(0x9000)

      const req8 = await app.extractSpendSig()
      console.log(req8)
      expect(req8.returnCode).toEqual(0x9000)

      /*
      At this point we gathered all signatures.
      We now add these signaturs to the builder.
      Note that for this transaction, we do not have any transparent signatures.
      */

      const signatures = {
        transparent_sigs: [],
        spend_sigs: [req7.sigRaw, req8.sigRaw],
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

  test.each(models)('make a tx with 1 transparent input 1 spend 2 shielded outputs', async function (m) {
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

      const tx_input_data = TX_INPUT_DATA[1]
      const {
        t_in: [tin1],
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

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      const testname = `${m.prefix.toLowerCase()}-1-tr-in-1-spend-2-sh-out`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit

      // const req = await app.inittx(ledgerblob_initdata);
      console.log(req)
      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      /*
      Check the hash of the return
      */
      let hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      let h = hash.digest('hex')
      expect(req.txdata.toString('hex')).toEqual(h)

      /*
      Now we start building the transaction using the builder.
      /*

      /*
      To add transparent inputs to the builder, we dont need fresh information from the ledger.
      The builder does need the secp256k1 public key belonging to the address.
       The builder also need outpoint from the blockchain.
       */

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      const bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

      /*
     To add a shielded spend to the builder, we need:
         - the proof generation key belonging to the spend address (proofkey)
         - the randomness needed for the value commitment (rcv)
         - the randomness needed for the random verification key (alpha)
     All this is retrieved from the ledger using a extractspenddata call with no inputs.
     The ledger already knows how much data it needs to send after the inittx call.
     */

      const req2 = await app.extractspenddata()
      console.log(req2)
      expect(req2.returnCode).toEqual(0x9000)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      /*
      The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      It furthermore uses the spend address and value from the UI.
       */

      const spendj1 = {
        proofkey: req2.keyRaw,
        rcv: req2.rcvRaw,
        alpha: req2.alphaRaw,
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

      const req4 = await app.extractoutputdata()
      console.log(req4)
      expect(req4.returnCode).toEqual(0x9000)

      /*
      The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      It furthermore uses the output address, value and memo from the UI.
      */

      const outj1 = {
        rcv: req4.rcvRaw,
        rseed: req4.rseedRaw,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hash_seed,
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

      const req5 = await app.extractoutputdata()
      console.log(req5)
      expect(req5.returnCode).toEqual(0x9000)

      const outj2 = {
        rcv: req5.rcvRaw,
        rseed: req5.rseedRaw,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hash_seed,
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

      const req6 = await app.checkandsign(ledgerblob_txdata, tx_version)
      console.log(req6)
      expect(req6.returnCode).toEqual(0x9000)

      /*
      Check the hash of the return
      */

      hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_txdata))
      h = hash.digest('hex')
      expect(req6.signdata.toString('hex')).toEqual(h)

      /*
      The builder needs the spend signatures to add it to the transaction blob.
      We need to do this one by one.
      So we first gather all signatures we need.
       */

      const req7 = await app.extractspendsig()
      console.log(req7)
      expect(req7.returnCode).toEqual(0x9000)

      /*
      The builder also needs the transparent signature for the transparent input.
       */

      const req9 = await app.extracttranssig()
      console.log(req9)
      expect(req9.returnCode).toEqual(0x9000)

      /*
      At this point we gathered all signatures.
      We now add these signaturs to the builder.
      Note that for this transaction, we do not have any transparent signatures.
       */

      const signatures = {
        transparent_sigs: [req9.sigRaw],
        spend_sigs: [req7.sigRaw],
      }

      console.log(signatures)

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

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      const testname = `${m.prefix.toLowerCase()}-1-tr-out-1-spend-2-sh-out`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit

      // const req = await app.inittx(ledgerblob_initdata);
      console.log(req)
      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      /*
      Check the hash of the return
      */
      let hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      let h = hash.digest('hex')
      expect(req.txdata.toString('hex')).toEqual(h)

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

      const req2 = await app.extractspenddata()
      console.log(req2)
      expect(req2.returnCode).toEqual(0x9000)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      /*
      The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      It furthermore uses the spend address and value from the UI.
       */

      const spendj1 = {
        proofkey: req2.keyRaw,
        rcv: req2.rcvRaw,
        alpha: req2.alphaRaw,
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

      const req4 = await app.extractoutputdata()
      console.log(req4)
      expect(req4.returnCode).toEqual(0x9000)

      /*
      The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      It furthermore uses the output address, value and memo from the UI.
      */

      const outj1 = {
        rcv: req4.rcvRaw,
        rseed: req4.rseedRaw,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hash_seed,
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

      const req5 = await app.extractoutputdata()
      console.log(req5)
      expect(req5.returnCode).toEqual(0x9000)

      const outj2 = {
        rcv: req5.rcvRaw,
        rseed: req5.rseedRaw,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hash_seed,
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

      const req6 = await app.checkandsign(ledgerblob_txdata, tx_version)
      console.log(req6)
      expect(req6.returnCode).toEqual(0x9000)

      /*
      Check the hash of the return
      */

      hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_txdata))
      h = hash.digest('hex')
      expect(req6.signdata.toString('hex')).toEqual(h)

      /*
      The builder needs the spend signatures to add it to the transaction blob.
      We need to do this one by one.
      So we first gather all signatures we need.
       */

      const req7 = await app.extractspendsig()
      console.log(req7)
      expect(req7.returnCode).toEqual(0x9000)

      /*
     At this point we gathered all signatures (only for shielded inputs as there are no transparent ones)
     We now add these signatures to the builder.
     Note that for this transaction, we do not have any transparent signatures.
      */

      const signatures = {
        transparent_sigs: [],
        spend_sigs: [req7.sigRaw],
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

      /*
      In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
      For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
      She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
      The inputs to the initialization is therefore:
      - one transparent input and one transparent output
      - one shielded spend notes and two shielded output notes.
      She takes a transaction fee according to ZIP-0317 and all leftovers is sent shielded to her own address.
      All this info is gathered from the UI and put in the correct jsons.
       */

      const tx_input_data = TX_INPUT_DATA[3]
      const {
        t_in: [tin1],
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

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      const testname = `${m.prefix.toLowerCase()}-1-tr-in-1-tr-out-1-spend-2-sh-out`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit

      // const req = await app.inittx(ledgerblob_initdata);
      console.log(req)
      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      /*
      Check the hash of the return
      */
      let hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      let h = hash.digest('hex')
      expect(req.txdata.toString('hex')).toEqual(h)

      /*
      Now we start building the transaction using the builder.
      /*

      /*
      To add transparent inputs to the builder, we don't need fresh information from the ledger.
      The builder does need the secp256k1 public key belonging to the address.
       The builder also need outpoint from the blockchain.
       */

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      const bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

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

      const req2 = await app.extractspenddata()
      console.log(req2)
      expect(req2.returnCode).toEqual(0x9000)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      /*
      The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      It furthermore uses the spend address and value from the UI.
       */

      const spendj1 = {
        proofkey: req2.keyRaw,
        rcv: req2.rcvRaw,
        alpha: req2.alphaRaw,
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

      const req4 = await app.extractoutputdata()
      console.log(req4)
      expect(req4.returnCode).toEqual(0x9000)

      /*
      The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      It furthermore uses the output address, value and memo from the UI.
      */

      const outj1 = {
        rcv: req4.rcvRaw,
        rseed: req4.rseedRaw,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hash_seed,
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

      const req5 = await app.extractoutputdata()
      console.log(req5)
      expect(req5.returnCode).toEqual(0x9000)

      const outj2 = {
        rcv: req5.rcvRaw,
        rseed: req5.rseedRaw,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hash_seed,
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

      const req6 = await app.checkandsign(ledgerblob_txdata, tx_version)
      console.log(req6)
      expect(req6.returnCode).toEqual(0x9000)

      /*
      Check the hash of the return
      */

      hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_txdata))
      h = hash.digest('hex')
      expect(req6.signdata.toString('hex')).toEqual(h)

      /*
      The builder needs the spend signatures to add it to the transaction blob.
      We need to do this one by one.
      So we first gather all signatures we need.
       */

      const req7 = await app.extractspendsig()
      console.log(req7)
      expect(req7.returnCode).toEqual(0x9000)

      /*
      The builder also needs the transparent signature for the transparent input.
       */

      const req9 = await app.extracttranssig()
      console.log(req9)
      expect(req9.returnCode).toEqual(0x9000)

      /*
      At this point we gathered all signatures.
      We now add these signatures to the builder.
      Note that for this transaction, we do not have any transparent signatures.
       */

      const signatures = {
        transparent_sigs: [req9.sigRaw],
        spend_sigs: [req7.sigRaw],
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

  test.each(models)('make a transaction with 2 transparent input 2 transparent output', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      /*
      In this test, Alice wants to send 10000 ZEC to Bob transparent and send the change back to herself.
       */

      const tx_input_data = TX_INPUT_DATA[4]
      const {
        t_in: [tin1],
        t_out: [tout1, tout2],
      } = tx_input_data
      const builder = new ZcashBuilderBridge(fee_for(tx_input_data))

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      const testname = `${m.prefix.toLowerCase()}-2-tr-in-2-tr-out`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit
      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      let hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      let h = hash.digest('hex')
      expect(req.txdata.toString('hex')).toEqual(h)

      /*
      Now we start building the transaction using the builder.
      */

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

      /*
      To add a transparent output, the builder does not need anything other than the input to the inittx.
       */

      const bt1 = builder.add_transparent_output(tout1)
      console.log(bt1)

      const bt2 = builder.add_transparent_output(tout2)
      console.log(bt2)

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, tx_version)

      const req6 = await app.checkandsign(ledgerblob_txdata, tx_version)
      console.log(req6)
      expect(req6.returnCode).toEqual(0x9000)

      hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_txdata))
      h = hash.digest('hex')
      expect(req6.signdata.toString('hex')).toEqual(h)

      const req9 = await app.extracttranssig()
      console.log(req9)
      expect(req9.returnCode).toEqual(0x9000)

      const req10 = await app.extracttranssig()
      console.log(req10)
      expect(req10.returnCode).toEqual(0x9000)

      /*
      At this point we gathered all signatures.
      We now add these signatures to the builder.
      Note that for this transaction, we do not have any transparent signatures.
       */

      const signatures = {
        transparent_sigs: [req9.sigRaw, req10.sigRaw],
        spend_sigs: [],
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

  test.each(models)('extracting signatures without checkandsign', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      console.log(SPEND_PATH)

      /*
      In this test, we try to extract signatures without having done the checks and signing.
       */
      const tx_input_data = TX_INPUT_DATA[5]

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      const testname = `${m.prefix.toLowerCase()}-ext-sig-without-checkandsign`
      const last_index = await sim.navigateUntilText('.', testname, sim.startOptions.approveKeyword)
      await sim.deleteEvents()

      const req = await reqinit
      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      const req2 = await app.extractspenddata()
      console.log(req2)
      expect(req2.returnCode).toEqual(0x9000)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      const req3 = await app.extractspenddata()
      console.log(req3)
      expect(req3.returnCode).toEqual(0x9000)
      expect(req3.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)

      const req4 = await app.extractoutputdata()
      console.log(req4)
      expect(req4.returnCode).toEqual(0x9000)

      const req5 = await app.extractoutputdata()
      console.log(req5)
      expect(req5.returnCode).toEqual(0x9000)

      const req7 = await app.extractspendsig()
      console.log(req7)
      expect(req7.returnCode).not.toEqual(0x9000)

      const req8 = await app.extracttranssig()
      console.log(req8)
      expect(req8.returnCode).not.toEqual(0x9000)

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

      const req = await app.extractspenddata()
      expect(req.returnCode).not.toEqual(0x9000)
      expect(req.proofkey).toEqual(undefined)
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

      /*
      In this test, we try to extract signatures without having done the checks and signing.
       */

      const tx_input_data = TX_INPUT_DATA[5]

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      console.log(ledgerblob_initdata)

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-ext-output-without-ext-spend-data`)

      const req = await reqinit

      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      const req4 = await app.extractoutputdata()
      console.log(req4)
      expect(req4.returnCode).not.toEqual(0x9000)
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

      const tx_input_data = TX_INPUT_DATA[3]
      const {
        t_in: [tin1],
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

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-ext-more-sigs-than-needed-for-tx`)

      const req = await reqinit
      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      /*
      Now we start building the transaction using the builder.
      /*

      /*
      To add transparent inputs to the builder, we don't need fresh information from the ledger.
      The builder does need the secp256k1 public key belonging to the address.
       The builder also need outpoint from the blockchain.
       */

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      const bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

      /*
      To add a transparent output, the builder does not need anything other than the input to the inittx.
       */

      const bt1 = builder.add_transparent_output(tout1)
      console.log(bt1)

      /*
     To add a shielded spend to the builder, we need:
         - the proof generation key belonging to the spend address (proofkey)
         - the randomness needed for the value commitment (rcv)
         - the randomness needed for the random verification key (alpha)
     All this is retrieved from the ledger using a extractspenddata call with no inputs.
     The ledger already knows how much data it needs to send after the inittx call.
     */

      const req2 = await app.extractspenddata()
      console.log(req2)
      expect(req2.returnCode).toEqual(0x9000)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      /*
      The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      It furthermore uses the spend address and value from the UI.
       */

      const spendj1 = {
        proofkey: req2.keyRaw,
        rcv: req2.rcvRaw,
        alpha: req2.alphaRaw,
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

      const req4 = await app.extractoutputdata()
      console.log(req4)
      expect(req4.returnCode).toEqual(0x9000)

      /*
      The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      It furthermore uses the output address, value and memo from the UI.
      */

      const outj1 = {
        rcv: req4.rcvRaw,
        rseed: req4.rseedRaw,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hash_seed,
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

      const req5 = await app.extractoutputdata()
      console.log(req5)
      expect(req5.returnCode).toEqual(0x9000)

      const outj2 = {
        rcv: req5.rcvRaw,
        rseed: req5.rseedRaw,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hash_seed,
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

      const req6 = await app.checkandsign(ledgerblob_txdata, tx_version)
      console.log(req6)
      expect(req6.returnCode).toEqual(0x9000)

      /*
      The builder needs the spend signatures to add it to the transaction blob.
      We need to do this one by one.
      So we first gather all signatures we need.
       */

      const req7 = await app.extractspendsig()
      console.log(req7)
      expect(req7.returnCode).toEqual(0x9000)

      /*
      The builder also needs the transparent signature for the transparent input.
       */

      const req9 = await app.extracttranssig()
      console.log(req9)
      expect(req9.returnCode).toEqual(0x9000)

      /*
      At this point we gathered all signatures.
      We now add these signaturs to the builder.
      Note that for this transaction, we do not have any transparent signatures.
       */

      /*
      Below are the failing extractions
       */

      const req10 = await app.extractspendsig()
      console.log(req10)
      expect(req10.returnCode).not.toEqual(0x9000)

      const req11 = await app.extracttranssig()
      console.log(req11)
      expect(req11.returnCode).not.toEqual(0x9000)
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

      /*
      In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
      For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
      She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
      The inputs to the initialization is therefore:
      - one transparent input and one transparent output
      - one shielded spend notes and two shielded output notes.
      She takes a transaction fee according to ZIP-0317 and all leftovers is sent shielded to her own address.
      All this info is gathered from the UI and put in the correct jsons.
       */

      const tx_input_data = TX_INPUT_DATA[3]
      const {
        t_in: [tin1],
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
      console.log(Buffer.from(ledgerblob_initdata).toString('hex'))

      /*
      The output of the get_inittx_data can be send to the ledger.
      The ledger will check this data and show the inputs on screen for verification.
      If confirmed, the ledger also computes the randomness needed for :
          - The shielded spends
          - the shielded outputs
       */

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      // check for error
      const events = await sim.getEvents()
      console.log(events)
      events.forEach((element: any) => {
        expect(element['text'].includes('ERROR')).toBeFalsy()
      })

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-not-using-ledger-rnd-for-tx`)

      const req = await reqinit
      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      /*
      Now we start building the transaction using the builder.
      /*

      /*
      To add transparent inputs to the builder, we dont need fresh information from the ledger.
      The builder does need the secp256k1 public key belonging to the address.
       The builder also need outpoint from the blockchain.
       */

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      const bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

      /*
      To add a transparent output, the builder does not need anything other than the input to the inittx.
       */

      const bt1 = builder.add_transparent_output(tout1)
      console.log(bt1)

      /*
     To add a shielded spend to the builder, we need:
         - the proof generation key belonging to the spend address (proofkey)
         - the randomness needed for the value commitment (rcv)
         - the randomness needed for the random verification key (alpha)
     All this is retrieved from the ledger using a extractspenddata call with no inputs.
     The ledger already knows how much data it needs to send after the inittx call.
     */

      const req2 = await app.extractspenddata()
      console.log(req2)
      expect(req2.returnCode).toEqual(0x9000)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      /*
      The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      It furthermore uses the spend address and value from the UI.
       */

      const spendj1 = {
        proofkey: req2.keyRaw,
        rcv: req2.rcvRaw,
        alpha: req2.alphaRaw,
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

      const req4 = await app.extractoutputdata()
      console.log(req4)
      expect(req4.returnCode).toEqual(0x9000)

      /*
      The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      It furthermore uses the output address, value and memo from the UI.
      */

      const outj1 = {
        rcv: req4.rcvRaw,
        rseed: req4.rseedRaw,
        ovk: null,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hash_seed,
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

      const req5 = await app.extractoutputdata()
      console.log(req5)
      expect(req5.returnCode).toEqual(0x9000)

      /*
      Here we use the wrong rseed!!
       */

      const outj2 = {
        rcv: req5.rcvRaw,
        rseed: req5.rcvRaw,
        ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hash_seed,
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

      const req6 = await app.checkandsign(ledgerblob_txdata, tx_version)
      console.log(req6)
      expect(req6.returnCode).not.toEqual(0x9000)
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

      /*
      In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
      For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
      She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
      The inputs to the initialization is therefore:
      - one transparent input and one transparent output
      - one shielded spend notes and two shielded output notes.
      She takes a transaction fee according to ZIP-0317 and all leftovers is sent shielded to her own address.
      All this info is gathered from the UI and put in the correct jsons.
       */

      const tx_input_data = TX_INPUT_DATA[3]
      const {
        t_in: [tin1],
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

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-builder-addr-diff-to-inittx-addr`)

      const req = await reqinit
      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      /*
      Now we start building the transaction using the builder.
      /*

      /*
      To add transparent inputs to the builder, we dont need fresh information from the ledger.
      The builder does need the secp256k1 public key belonging to the address.
       The builder also need outpoint from the blockchain.
       */

      const t_data = {
        outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
        pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
        address: tin1.address,
        value: tin1.value,
      }

      const bt0 = builder.add_transparent_input(t_data)
      console.log(bt0)

      /*
      To add a transparent output, the builder does not need anything other than the input to the inittx.
       */

      const bt1 = builder.add_transparent_output(tout1)
      console.log(bt1)

      /*
     To add a shielded spend to the builder, we need:
         - the proof generation key belonging to the spend address (proofkey)
         - the randomness needed for the value commitment (rcv)
         - the randomness needed for the random verification key (alpha)
     All this is retrieved from the ledger using a extractspenddata call with no inputs.
     The ledger already knows how much data it needs to send after the inittx call.
     */

      const req2 = await app.extractspenddata()
      console.log(req2)
      expect(req2.returnCode).toEqual(0x9000)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      /*
      The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
      It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      It furthermore uses the spend address and value from the UI.
       */

      const spendj1 = {
        proofkey: req2.keyRaw,
        rcv: req2.rcvRaw,
        alpha: req2.alphaRaw,
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

      const req4 = await app.extractoutputdata()
      console.log(req4)
      expect(req4.returnCode).toEqual(0x9000)

      /*
      The builder needs the data retrieved from the ledger (rcv, rcm, esk)
      It CAN send along an outgoing viewing key (OVK), can also be all zero's.
      It furthermore uses the output address, value and memo from the UI.
      */

      const outj1 = {
        rcv: req4.rcvRaw,
        rseed: req4.rseedRaw,
        ovk: null,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hash_seed: req4.hash_seed,
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

      const req5 = await app.extractoutputdata()
      console.log(req5)
      expect(req5.returnCode).toEqual(0x9000)

      /*
      Here we use the wrong address and send the change funds to Bob instead.
       */

      const outj2 = {
        rcv: req5.rcvRaw,
        rseed: req5.rseedRaw,
        ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
        address: s_out1.address,
        value: s_out2.value,
        memo: '0000',
        hash_seed: req5.hash_seed,
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

      const req6 = await app.checkandsign(ledgerblob_txdata, tx_version)
      console.log(req6)
      expect(req6.returnCode).not.toEqual(0x9000)
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

      const reqinit = app.inittx(ledgerblob_initdata)

      const req = await reqinit

      console.log(req)
      expect(req.returnCode).not.toEqual(0x9000)
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

      /*
      In this test, Alice wants to send 55000 ZEC to Bob.
      For this she needs two notes of 50000 ZEC sent to her address belonging to path: 1000.
      The inputs to the initialization is therefore two spend notes and two output notes.
      All this info is gathered from the UI and put in the correct jsons.
       */

      const tx_input_data = TX_INPUT_DATA[5]

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

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndReject('.', `${m.prefix.toLowerCase()}-ext-data-after-tx-reject`)

      const req = await reqinit

      console.log(req)
      expect(req.returnCode).not.toEqual(0x9000)

      /*
      Try to extract data after a rejection of a transaction
       */

      const req0 = await app.extractspenddata()
      console.log(req0)
      expect(req0.returnCode).not.toEqual(0x9000)

      const req1 = await app.extractoutputdata()
      console.log(req1)
      expect(req1.returnCode).not.toEqual(0x9000)
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

      const reqinit = app.inittx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.navigateUntilText('', '', sim.startOptions.approveKeyword, true, false) // we don't take snapshots here
      await sim.deleteEvents()

      const req = await reqinit

      console.log(req)
      expect(req.returnCode).toEqual(0x9000)
      expect(req.txdata.byteLength).toEqual(32)

      const hash = crypto.createHash('sha256')
      hash.update(Buffer.from(ledgerblob_initdata))
      const h = hash.digest('hex')
      expect(req.txdata.toString('hex')).toEqual(h)

      const req2 = await app.extractspenddata()
      console.log(req2)
      expect(req2.returnCode).toEqual(0x9000)
      const expected_proofkeyRaw =
        '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'
      expect(req2.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)
      expect(req2.rcvRaw).not.toEqual(req2.alphaRaw)

      const spendj1 = {
        proofkey: req2.keyRaw,
        rcv: req2.rcvRaw,
        alpha: req2.alphaRaw,
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
       We need to repeat the above process for the second spend.
        */

      const req3 = await app.extractspenddata()
      console.log(req3)
      expect(req3.returnCode).toEqual(0x9000)
      expect(req3.keyRaw.toString('hex')).toEqual(expected_proofkeyRaw)

      const spendj2 = {
        proofkey: req3.keyRaw,
        rcv: req3.rcvRaw,
        alpha: req3.alphaRaw,
        address: s_spend2.address,
        value: s_spend2.value,
        witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
        rseed: '0000000000000000000000000000000000000000000000000000000000000000',
      }

      const b2 = builder.add_sapling_spend(spendj2)
      console.log(b2)

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

      const req4 = await app.extractoutputdata()
      console.log(req4)
      expect(req4.returnCode).toEqual(0x9000)

      /*
       The builder needs the data retrieved from the ledger (rcv, rcm, esk)
       It CAN send along an outgoing viewing key (OVK), can also be all zero's.
       It furthermore uses the output address, value and memo from the UI.
       */

      const outj1 = {
        rcv: req4.rcvRaw,
        rseed: req4.rseedRaw,
        ovk: s_out1.ovk,
        address: s_out1.address,
        value: s_out1.value,
        memo: '0000',
        hashSeed: req4.hashSeed,
      }

      console.log(req4.hashSeed)
      /*
       The builder adds the shielded output to its state.
        */

      const b3 = builder.add_sapling_output(outj1)
      console.log(b3)

      /*
       This process needs to be repeated for the second output.
       Note that this output address belongs to Alice.
       There is no concept of a "change address" as all inputs and outputs need to be known in advance for the ledger verification on screen.
       The UI needs to take care of this before initializing a transaction to the ledger.
        */

      const req5 = await app.extractoutputdata()
      console.log(req5)
      expect(req5.returnCode).toEqual(0x9000)

      console.log(req5.hash_seed)

      const outj2 = {
        rcv: req5.rcvRaw,
        rseed: req5.rseedRaw,
        ovk: s_out2.ovk,
        address: s_out2.address,
        value: s_out2.value,
        memo: '0000',
        hashSeed: req5.hashSeed,
      }

      const b4 = builder.add_sapling_output(outj2)
      console.log(b4)

      const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH, bad_tx_version)

      const req6 = await app.checkAndSign(ledgerblob_txdata, bad_tx_version)
      console.log(req6)
      expect(req6.returnCode).not.toEqual(0x9000)
    } finally {
      await sim.close()
    }
  })
})
