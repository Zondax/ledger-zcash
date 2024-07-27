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
import { defaultOptions as commonOpts, models } from './_config'
import ZCashApp from '@zondax/ledger-zcash'

jest.setTimeout(60000)
const defaultOptions = (model: any, is_address = false) => {
  let opts = commonOpts(model, is_address)
  return opts
}

describe('Addresses', function () {
  test.concurrent.each(models)('get_unshielded_address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new ZCashApp(sim.getTransport())
      const expectedAddrRaw = '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e'
      const expectedAddr = 't1KHG39uhsssPkYcAXkzZ5Bk2w1rnFukZvx'

      const addr = await app.getAddressTransparent(`m/44'/133'/5'/0/0`, false)
      console.log(addr)

      expect(addr?.addressRaw.toString('hex')).toEqual(expectedAddrRaw)
      expect(addr?.address).toEqual(expectedAddr)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show_unshielded_address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m, true))
      const app = new ZCashApp(sim.getTransport())

      const expectedAddrRaw = '026f27818e7426a10773226b3553d0afe50a3697bd02652f1b57d67bf648577d11'
      const expectedAddr = 't1PYLcQqpxou9Eak4nroMNGKYoxT4HPdHqJ'

      const addrReq = app.getAddressTransparent(`m/44'/133'/5'/0/1`)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address_unshielded`)

      const addr = await addrReq
      expect(addr?.addressRaw.toString('hex')).toEqual(expectedAddrRaw)
      expect(addr?.address).toEqual(expectedAddr)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get_shielded_address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m, true))
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000 + 0x80000000
      const addr = await app.getAddressSapling(zip32Account, false)

      const expected_addrRaw = '71635f26c1b4a2332abeb70b1249e61ed4e40b1cc114c1ef994dcf304e2e5945748e879660550443161cda'
      const expected_addr = 'zs1w9347fkpkj3rx247ku93yj0xrm2wgzcucy2vrmuefh8nqn3wt9zhfr58jes92pzrzcwd5rrjn0g'

      expect(addr?.addressRaw.toString('hex')).toEqual(expected_addrRaw)
      expect(addr?.address).toEqual(expected_addr)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get invalid shielded address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m))
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000
      await expect(app.getAddressSapling(zip32Account, false)).rejects.toThrow()
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show shielded address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m, true))
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000 + 0x80000000
      const addrRequest = app.getAddressSapling(zip32Account)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 600000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address_shielded`)

      const addr = await addrRequest

      const expected_addrRaw = '71635f26c1b4a2332abeb70b1249e61ed4e40b1cc114c1ef994dcf304e2e5945748e879660550443161cda'
      const expected_addr = 'zs1w9347fkpkj3rx247ku93yj0xrm2wgzcucy2vrmuefh8nqn3wt9zhfr58jes92pzrzcwd5rrjn0g'

      expect(addr?.addressRaw.toString('hex')).toEqual(expected_addrRaw)
      expect(addr?.address).toEqual(expected_addr)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show_shielded_address_with_div', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start(defaultOptions(m, true))
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000 + 0x80000000
      const div = Buffer.from('71635f26c1b4a2332abeb7', 'hex')

      const addrRequest = app.getAddressSamplingFromDiversifier(zip32Account, div)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 600000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address_shielded_with_div`)

      const addr = await addrRequest

      const expected_addrRaw = '71635f26c1b4a2332abeb70b1249e61ed4e40b1cc114c1ef994dcf304e2e5945748e879660550443161cda'
      const expected_addr = 'zs1w9347fkpkj3rx247ku93yj0xrm2wgzcucy2vrmuefh8nqn3wt9zhfr58jes92pzrzcwd5rrjn0g'

      expect(addr?.addressRaw.toString('hex')).toEqual(expected_addrRaw)
      expect(addr?.address).toEqual(expected_addr)
    } finally {
      await sim.close()
    }
  })
})
