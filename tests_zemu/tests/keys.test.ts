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

import Zemu, { ButtonKind, DEFAULT_START_OPTIONS, isTouchDevice } from '@zondax/zemu'
import ZCashApp from '@zondax/ledger-zcash'
import { APP_SEED, defaultOptions as commonOpts, models } from './_config'

jest.setTimeout(600000)
const defaultOptions = (model: any, is_address = false) => {
  let opts = commonOpts(model, is_address)
  return opts
}

describe('Nullifier', function () {
  describe('Non Expert', function () {
    test.concurrent.each(models)('get nullifier account 0x01', async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({
          ...defaultOptions(m, true),
          approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
          approveAction: ButtonKind.ApproveTapButton,
        })

        const app = new ZCashApp(sim.getTransport())

        const zip32Account = 0x01 + 0x80000000
        const pos = BigInt(0)
        const cmu = Buffer.from('df7e8d004bd4e32f2fb022efd5aa4bcdc7c89f919bbac9309d6e21ca83ce93ea', 'hex')

        const promise_resp = app.getNullifierSapling(zip32Account, pos, cmu)
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_nullifier-0x1`)

        let resp = await promise_resp

        const expected_nfRaw = '42cf7491d0b97afc77fb463054f6554ecad6dd79ce1c9e412058d9544cadef8f'
        let nfRaw = resp.nfRaw?.toString('hex')
        console.log(nfRaw)
        expect(nfRaw).toEqual(expected_nfRaw)

        resp = await app.getNullifierSapling(zip32Account, pos, cmu)
        nfRaw = resp.nfRaw?.toString('hex')
        console.log(nfRaw)
        expect(nfRaw).toEqual(expected_nfRaw)
      } finally {
        await sim.close()
      }
    })

    test.concurrent.each(models)('get_nullifier_account_0xFF', async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({
          ...defaultOptions(m, true),
          approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
          approveAction: ButtonKind.ApproveTapButton
        })

        const app = new ZCashApp(sim.getTransport())

        const path = 0xff + 0x80000000
        const pos = BigInt(0)
        const cmu = Buffer.from('df7e8d004bd4e32f2fb022efd5aa4bcdc7c89f919bbac9309d6e21ca83ce93ea', 'hex')

        const promise_resp = app.getNullifierSapling(path, pos, cmu)
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_nullifier-0xFF`)

        let resp = await promise_resp

        const expected_nfRaw = 'ca1466808b1d503eea8b1fad31e16379247f8bf9fbe2fcb046d28b82af2e1e7d'
        let nfRaw = resp.nfRaw?.toString('hex')
        console.log(nfRaw)
        expect(nfRaw).toEqual(expected_nfRaw)

        resp = await app.getNullifierSapling(path, pos, cmu)
        nfRaw = resp.nfRaw?.toString('hex')
        console.log(nfRaw)
        expect(nfRaw).toEqual(expected_nfRaw)
      } finally {
        await sim.close()
      }
    })
  })


  describe('Expert', function () {
    test.concurrent.each(models)('get nullifier account 0x01', async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({
          ...defaultOptions(m, true),
          approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
          approveAction: ButtonKind.ApproveTapButton,
        })

        await sim.toggleExpertMode()

        const app = new ZCashApp(sim.getTransport())

        const zip32Account = 0x01 + 0x80000000
        const pos = BigInt(0)
        const cmu = Buffer.from('df7e8d004bd4e32f2fb022efd5aa4bcdc7c89f919bbac9309d6e21ca83ce93ea', 'hex')

        const promise_resp = app.getNullifierSapling(zip32Account, pos, cmu)
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_nullifier-0x1-expert`)

        const resp = await promise_resp

        const expected_nfRaw = '42cf7491d0b97afc77fb463054f6554ecad6dd79ce1c9e412058d9544cadef8f'
        const nfRaw = resp.nfRaw?.toString('hex')
        console.log(nfRaw)
        expect(nfRaw).toEqual(expected_nfRaw)
      } finally {
        await sim.close()
      }
    })

    test.concurrent.each(models)('get_nullifier_account_0xFF', async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({
          ...defaultOptions(m, true),
          approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
          approveAction: ButtonKind.ApproveTapButton
        })

        await sim.toggleExpertMode()

        const app = new ZCashApp(sim.getTransport())

        const path = 0xff + 0x80000000
        const pos = BigInt(0)
        const cmu = Buffer.from('df7e8d004bd4e32f2fb022efd5aa4bcdc7c89f919bbac9309d6e21ca83ce93ea', 'hex')

        const promise_resp = app.getNullifierSapling(path, pos, cmu)
        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_nullifier-0xFF-expert`)

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
})



describe('Get_keys', function () {
  describe('Non expert', function () {
    test.concurrent.each(models)('get ivk', async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({
          ...defaultOptions(m, true),
          approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
          approveAction: ButtonKind.ApproveTapButton
        })

        const app = new ZCashApp(sim.getTransport())

        const zip32Account = 1000 + 0x80000000
        const ivkreq = app.getIvkSapling(zip32Account)

        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-ivk`)

        let ivk = await ivkreq
        console.log(ivk)

        const expected_ivkRaw = 'd660cd8b883afbcc0c145d0bf4241d3b26fff391b0ad3389e39f717995202801'
        const expected_div = '71635f26c1b4a2332abeb7'

        let ivkRaw = ivk.ivkRaw?.toString('hex')
        let default_div = ivk.defaultDiversifier?.toString('hex')

        expect(ivkRaw).toEqual(expected_ivkRaw)
        expect(default_div).toEqual(expected_div)


        ivk = await app.getIvkSapling(zip32Account)

        ivkRaw = ivk.ivkRaw?.toString('hex')
        default_div = ivk.defaultDiversifier?.toString('hex')

        expect(ivkRaw).toEqual(expected_ivkRaw)
        expect(default_div).toEqual(expected_div)
      } finally {
        await sim.close()
      }
    })

    test.concurrent.each(models)('get ovk', async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({
          ...defaultOptions(m, true),
          approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
          approveAction: ButtonKind.ApproveTapButton
        })

        const app = new ZCashApp(sim.getTransport())

        const zip32Account = 1000 + 0x80000000
        const ovkreq = app.getOvkSapling(zip32Account)

        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-ovk`)

        let ovk = await ovkreq
        console.log(ovk)

        const expected_ovkRaw = '199be731acfa8bf5d525eade16451edf6e818f27db0164ff1f428bd8bf432f69'
        let ovkRaw = ovk.ovkRaw?.toString('hex')
        expect(ovkRaw).toEqual(expected_ovkRaw)

        ovk = await app.getOvkSapling(zip32Account)

        ovkRaw = ovk.ovkRaw?.toString('hex')
        expect(ovkRaw).toEqual(expected_ovkRaw)
      } finally {
        await sim.close()
      }
    })

    test.concurrent.each(models)('Get fvk', async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({
          ...defaultOptions(m, true),
          approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
          approveAction: ButtonKind.ApproveTapButton
        })

        const app = new ZCashApp(sim.getTransport())

        const zip32Account = 1000 + 0x80000000
        let fvkreq = app.getFvkSapling(zip32Account)

        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-fvk`)

        let fvk = await fvkreq

        console.log(fvk)

        const expected_akRaw = '0bbb1d4bfe70a4f4fc762e2f980ab7c600a060c28410ccd03972931fe310f2a5'
        let akRaw = fvk.akRaw?.toString('hex')
        expect(akRaw).toEqual(expected_akRaw)

        const expected_nkRaw = '9f552de44e5c38db16de3165aaa4627e352e00b6863dd627cc58df02a39deec7'
        let nkRaw = fvk.nkRaw?.toString('hex')
        expect(nkRaw).toEqual(expected_nkRaw)

        const expected_ovkRaw = '199be731acfa8bf5d525eade16451edf6e818f27db0164ff1f428bd8bf432f69'
        let ovkRaw = fvk.ovkRaw?.toString('hex')
        expect(ovkRaw).toEqual(expected_ovkRaw)

        console.log(fvk)

        fvk = await app.getFvkSapling(zip32Account)

        akRaw = fvk.akRaw?.toString('hex')
        expect(akRaw).toEqual(expected_akRaw)

        nkRaw = fvk.nkRaw?.toString('hex')
        expect(nkRaw).toEqual(expected_nkRaw)

        ovkRaw = fvk.ovkRaw?.toString('hex')
        expect(ovkRaw).toEqual(expected_ovkRaw)
      } finally {
        await sim.close()
      }
    })
  })


  describe('Expert', function () {
    test.concurrent.each(models)('get ivk', async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({
          ...defaultOptions(m, true),
          approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
          approveAction: ButtonKind.ApproveTapButton
        })

        await sim.toggleExpertMode()

        const app = new ZCashApp(sim.getTransport())

        const zip32Account = 1000 + 0x80000000
        const ivkreq = app.getIvkSapling(zip32Account)

        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-ivk-expert`)

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

    test.concurrent.each(models)('get ovk', async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({
          ...defaultOptions(m, true),
          approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
          approveAction: ButtonKind.ApproveTapButton
        })

        await sim.toggleExpertMode()

        const app = new ZCashApp(sim.getTransport())

        const zip32Account = 1000 + 0x80000000
        const ovkreq = app.getOvkSapling(zip32Account)

        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-ovk-expert`)

        const ovk = await ovkreq
        console.log(ovk)

        const expected_ovkRaw = '199be731acfa8bf5d525eade16451edf6e818f27db0164ff1f428bd8bf432f69'
        const ovkRaw = ovk.ovkRaw?.toString('hex')
        expect(ovkRaw).toEqual(expected_ovkRaw)
      } finally {
        await sim.close()
      }
    })

    test.concurrent.each(models)('Get fvk', async function (m) {
      const sim = new Zemu(m.path)
      try {
        await sim.start({
          ...defaultOptions(m, true),
          approveKeyword: isTouchDevice(m.name) ? 'Approve' : '',
          approveAction: ButtonKind.ApproveTapButton
        })

        await sim.toggleExpertMode()

        const app = new ZCashApp(sim.getTransport())

        const zip32Account = 1000 + 0x80000000
        const fvkreq = app.getFvkSapling(zip32Account)

        await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
        await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-get-fvk-expert`)

        const fvk = await fvkreq

        console.log(fvk)

        const expected_akRaw = '0bbb1d4bfe70a4f4fc762e2f980ab7c600a060c28410ccd03972931fe310f2a5'
        const akRaw = fvk.akRaw?.toString('hex')
        expect(akRaw).toEqual(expected_akRaw)

        const expected_nkRaw = '9f552de44e5c38db16de3165aaa4627e352e00b6863dd627cc58df02a39deec7'
        const nkRaw = fvk.nkRaw?.toString('hex')
        expect(nkRaw).toEqual(expected_nkRaw)

        const expected_ovkRaw = '199be731acfa8bf5d525eade16451edf6e818f27db0164ff1f428bd8bf432f69'
        const ovkRaw = fvk.ovkRaw?.toString('hex')
        expect(ovkRaw).toEqual(expected_ovkRaw)
      } finally {
        await sim.close()
      }
    })
  })

})



describe('Diversifiers', function () {
  test.concurrent.each(models)('Div list with startindex', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000 + 0x80000000
      const startDiversifier = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
      const divlistReq = app.getDiversifierList(zip32Account, startDiversifier)

      const divlist = await divlistReq
      console.log(divlist)

      const expected_divs = [
        '71635f26c1b4a2332abeb7',
        '20fafaf8b4b763dbad872b',
        '443e2f4876099656cac254',
        'a42f8cd37e16759fcd921d',
        '6dbd485ed3703834c6e396',
        '702c42bb6dcda999dfff06',
        'a67d8286346f3bb341c691',
        '1fba2909f96a575c9208ac',
        '349ced82af892988de95a7',
        'ce8c5c7eacb06e7b7f6091',
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
