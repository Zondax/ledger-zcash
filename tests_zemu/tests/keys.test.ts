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

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
}

jest.setTimeout(600000)

describe('Nullifier', function () {
  test.each(models)('get nullifier account 0x01', async function (m) {
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

      const expected_nfRaw = '3840188b5e05bced04ec715af62db7da39c06d643971a6748ee020c845427b95'
      const nfRaw = resp.nfRaw?.toString('hex')
      console.log(nfRaw)
      expect(nfRaw).toEqual(expected_nfRaw)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('get nullifier account 0xFF', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const path = 0xff + 0x80000000
      const pos = BigInt(0)
      const cmu = Buffer.from('df7e8d004bd4e32f2fb022efd5aa4bcdc7c89f919bbac9309d6e21ca83ce93ea', 'hex')

      const promise_resp = app.getNullifierSapling(path, pos, cmu)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_nullifier-0xFF`)

      const resp = await promise_resp

      const expected_nfRaw = '3840188b5e05bced04ec715af62db7da39c06d643971a6748ee020c845427b95'
      const nfRaw = resp.nfRaw?.toString('hex')
      console.log(nfRaw)
      expect(nfRaw).toEqual(expected_nfRaw)
    } finally {
      await sim.close()
    }
  })
})

describe('Get keys', function () {
  test.each(models)('get ivk', async function (m) {
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

      const expected_ivkRaw = '6dfadf175921e6fbfa093c8f7c704a0bdb07328474f56c833dfcfa5301082d03'
      const expected_div = 'c69e979c6763c1b09238dc'

      const ivkRaw = ivk.ivkRaw?.toString('hex')
      const default_div = ivk.defaultDiversifier?.toString('hex')

      expect(ivkRaw).toEqual(expected_ivkRaw)
      expect(default_div).toEqual(expected_div)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('get ovk', async function (m) {
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
      const ovkreq = app.getOvkSapling(zip32Account)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-ovk`)

      const ovk = await ovkreq
      console.log(ovk)

      const expected_ovkRaw = '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca'
      const ovkRaw = ovk.ovkRaw?.toString('hex')
      expect(ovkRaw).toEqual(expected_ovkRaw)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('Get fvk', async function (m) {
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

describe('Diversifiers', function () {
  test.each(models)('Div list with startindex', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000 + 0x80000000
      const startDiversifier = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
      const divlistReq = app.getDiversifierList(zip32Account, startDiversifier)

      const divlist = await divlistReq
      console.log(divlist)

      const expected_divs = [
        'c69e979c6763c1b09238dc',
        'ce702cb48ef2491d0b0745',
        '10bb6a9c26aaffa4526573',
        '9d50c5db5ff76a82cd742f',
        '4adef20e22b65c533cf584',
        '534acf5c55d62f35770b04',
      ]

      const errors: string[] = []

      expect(divlist.diversifiers.length).toEqual(expected_divs.length)

      divlist.diversifiers.forEach((diversifier, index) => {
        const divRaw = diversifier.toString('hex')
        if (divRaw !== expected_divs[index]) {
          errors.push(`Mismatch at index ${index}: expected ${expected_divs[index]}, got ${divRaw}`)
        }
      })

      if (errors.length > 0) {
        throw new Error(`Diversifier mismatches:\n${errors.join('\n')}`)
      }
    } finally {
      await sim.close()
    }
  })
})
