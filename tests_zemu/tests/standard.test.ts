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

import Zemu, { ButtonKind, zondaxMainmenuNavigation } from '@zondax/zemu'
import { defaultOptions, models } from './_config'
import ZCashApp from '@zondax/ledger-zcash'

jest.setTimeout(60000)

describe('Standard', function() {
  test.concurrent.each(models)('can start and stop container', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('main menu', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const nav = zondaxMainmenuNavigation(m.name, [1, 0, 0, 4, -5])
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, nav.schedule)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get app version', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())
      const resp = await app.getVersion()

      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('testMode')
      expect(resp).toHaveProperty('major')
      expect(resp).toHaveProperty('minor')
      expect(resp).toHaveProperty('patch')
    } finally {
      await sim.close()
    }
  })
})

describe('Addresses', function() {
  test.concurrent.each(models)('get unshielded address', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const addr = await app.getAddressAndPubKey('m/44\'/133\'/5\'/0/0', true)
      console.log(addr)

      const expectedAddrRaw = '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e'
      const expectedAddr = 't1KHG39uhsssPkYcAXkzZ5Bk2w1rnFukZvx'
      expect(addr.returnCode).toEqual(0x9000)
      if ('addressRaw' in addr && 'address' in addr) {
        expect(addr.addressRaw.toString('hex')).toEqual(expectedAddrRaw)
        expect(addr.address).toEqual(expectedAddr)
      } else {
        fail('Expected properties addressRaw and address are missing in the response.')
      }
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show unshielded address', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const addrRequest = app.showAddressAndPubKey('m/44\'/133\'/5\'/0/1', true)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address_unshielded`)

      const addr = await addrRequest
      console.log(addr)
      expect(addr.returnCode).toEqual(0x9000)

      const expected_addrRaw = '026f27818e7426a10773226b3553d0afe50a3697bd02652f1b57d67bf648577d11'
      const expected_addr = 't1PYLcQqpxou9Eak4nroMNGKYoxT4HPdHqJ'

      if ('addressRaw' in addr && 'address' in addr) {
        const addrRaw = addr.addressRaw.toString('hex')
        expect(addrRaw).toEqual(expected_addrRaw)
        expect(addr.address).toEqual(expected_addr)
      } else {
        fail('Expected properties addressRaw and address are missing in the response.')
      }
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get shielded address', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const addr = await app.getAddressAndPubKey(1000)

      console.log(addr)
      expect(addr.returnCode).toEqual(0x9000)

      const expected_addrRaw = '71635f26c1b4a2332abeb70b1249e61ed4e40b1cc114c1ef994dcf304e2e5945748e879660550443161cda'
      const expected_addr = 'zs1w9347fkpkj3rx247ku93yj0xrm2wgzcucy2vrmuefh8nqn3wt9zhfr58jes92pzrzcwd5rrjn0g'

      if ('addressRaw' in addr && 'address' in addr) {
        const addrRaw = addr.addressRaw.toString('hex')
        expect(addrRaw).toEqual(expected_addrRaw)
        expect(addr.address).toEqual(expected_addr)
      } else {
        fail('Expected properties addressRaw and address are missing in the response.')
      }
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show shielded address', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const addrRequest = app.showAddressAndPubKey(1000)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 600000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address_shielded`)

      const addr = await addrRequest
      console.log(addr)
      expect(addr.returnCode).toEqual(0x9000)

      const expected_addrRaw = '71635f26c1b4a2332abeb70b1249e61ed4e40b1cc114c1ef994dcf304e2e5945748e879660550443161cda'
      const expected_addr = 'zs1w9347fkpkj3rx247ku93yj0xrm2wgzcucy2vrmuefh8nqn3wt9zhfr58jes92pzrzcwd5rrjn0g'

      if ('addressRaw' in addr && 'address' in addr) {
        const addrRaw = addr.addressRaw.toString('hex')
        expect(addrRaw).toEqual(expected_addrRaw)
        expect(addr.address).toEqual(expected_addr)
      } else {
        fail('Expected properties addressRaw and address are missing in the response.')
      }
    } finally {
      await sim.close()
    }
  })
})
