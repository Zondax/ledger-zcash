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

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
}

jest.setTimeout(600000)

describe('Nullifier', function() {
  test.concurrent.each(models)('get nullifier account 0x01', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 0x01 + 0x80000000
      const pos = BigInt(0)
      const cmu = Buffer.from('df7e8d004bd4e32f2fb022efd5aa4bcdc7c89f919bbac9309d6e21ca83ce93ea', 'hex')

      const promise_resp = app.getNullifierSapling(zip32Account, pos, cmu)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_nullifier-0x1`)

      const resp = await promise_resp

      const expected_nfRaw = '42cf7491d0b97afc77fb463054f6554ecad6dd79ce1c9e412058d9544cadef8f'
      const nfRaw = resp.nfRaw?.toString('hex')
      console.log(nfRaw)
      expect(nfRaw).toEqual(expected_nfRaw)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get nullifier account 0xFF', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const path = 0xFF + 0x80000000
      const pos = BigInt(0)
      const cmu = Buffer.from('df7e8d004bd4e32f2fb022efd5aa4bcdc7c89f919bbac9309d6e21ca83ce93ea', 'hex')

      const promise_resp = app.getNullifierSapling(path, pos, cmu)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_nullifier-0xFF`)

      const resp = await promise_resp

      const expected_nfRaw = 'ca1466808b1d503eea8b1fad31e16379247f8bf9fbe2fcb046d28b82af2e1e7d'
      const nfRaw = resp.nfRaw?.toString('hex')
      console.log(nfRaw)
      expect(nfRaw).toEqual(expected_nfRaw)
    } finally {
      await sim.close()
    }
  })
})

describe('Get keys', function () {
  test.concurrent.each(models)('get ivk', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000 + 0x80000000
      const ivkreq = app.getIvkSapling(zip32Account)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-ivk`)

      const ivk = await ivkreq
      console.log(ivk)

      const expected_ivkRaw = 'd660cd8b883afbcc0c145d0bf4241d3b26fff391b0ad3389e39f717995202801'
      const expected_div = '71635f26c1b4a2332abeb7'

      const ivkRaw = ivk.ivkRaw?.toString('hex')
      const default_div = ivk.defaultDiversifier?.toString('hex')

      expect(ivkRaw).toEqual(expected_ivkRaw)
      expect(default_div).toEqual(expected_div)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get outgoing viewing key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000 + 0x80000000
      const ovkreq = app.getOvkSapling( zip32Account)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-ovk`)

      const ovk = await ovkreq
      console.log(ovk)

      const expected_ovkRaw = '199be731acfa8bf5d525eade16451edf6e818f27db0164ff1f428bd8bf432f69'
      const ovkRaw = ovk.ovkRaw?.toString('hex')
      expect(ovkRaw).toEqual(expected_ovkRaw)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('Get full viewing key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000 + 0x80000000
      const fvkreq = app.getFvkSapling(zip32Account)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-fvk`)

      const fvk = await fvkreq

      console.log(fvk)

      const expected_akRaw = '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a'
      const akRaw = fvk.akRaw?.toString('hex')
      expect(akRaw).toEqual(expected_akRaw)

      const expected_nkRaw = 'a93349ed31a96abd9b07fb04daaad69a51de16e4ac8dbcc7e001779668d08dc7'
      const nkRaw = fvk.nkRaw?.toString('hex')
      expect(nkRaw).toEqual(expected_nkRaw)

      const expected_ovkRaw = '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca'
      const ovkRaw = fvk.ovkRaw?.toString('hex')
      expect(ovkRaw).toEqual(expected_ovkRaw)
    } finally {
      await sim.close()
    }
  })
})
