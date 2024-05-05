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
import { defaultOptions, models } from './common'
import ZCashApp from '@zondax/ledger-zcash'

jest.setTimeout(60000)

describe('Standard', function () {
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const nav = zondaxMainmenuNavigation(m.name, [1, 0, 0, 4, -5])
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, nav.schedule)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get app version', async function (m) {
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

describe('Addresses', function () {
  test.concurrent.each(models)('get unshielded address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const addr = await app.getAddressAndPubKey("m/44'/133'/5'/0/0", true)
      console.log(addr)

      const expectedAddrRaw = '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e'
      const expectedAddr = 't1KHG39uhsssPkYcAXkzZ5Bk2w1rnFukZvx'
      expect(addr.returnCode).toEqual(0x9000)
      if ('addressRaw' in addr && 'address' in addr) {
        expect(addr.addressRaw.toString('hex')).toEqual(expectedAddrRaw)
        expect(addr.address).toEqual(expectedAddr)
      } else {
        fail("Expected properties addressRaw and address are missing in the response.")
      }
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show unshielded address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const addrRequest = app.showAddressAndPubKey("m/44'/133'/5'/0/1", true)
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
        fail("Expected properties addressRaw and address are missing in the response.")
      }
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get shielded address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const addr = await app.getAddressAndPubKey(1000)

      console.log(addr)
      expect(addr.returnCode).toEqual(0x9000)

      const expected_addrRaw = 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667'
      const expected_addr = 'zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3'

      if ('addressRaw' in addr && 'address' in addr) {
        const addrRaw = addr.addressRaw.toString('hex')
        expect(addrRaw).toEqual(expected_addrRaw)
        expect(addr.address).toEqual(expected_addr)
      } else {
        fail("Expected properties addressRaw and address are missing in the response.")
      }
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show shielded address', async function (m) {
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

      const expected_addrRaw = 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667'
      const expected_addr = 'zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3'

      if ('addressRaw' in addr && 'address' in addr) {
        const addrRaw = addr.addressRaw.toString('hex')
        expect(addrRaw).toEqual(expected_addrRaw)
        expect(addr.address).toEqual(expected_addr)
      } else {
        fail("Expected properties addressRaw and address are missing in the response.")
      }
    } finally {
      await sim.close()
    }
  })
})

describe('Nullifier', function () {
  test.concurrent.each(models)('get nullifier', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const path = 0xFF;
      const pos = Buffer.alloc(8);
      const cmu = Buffer.from("df7e8d004bd4e32f2fb022efd5aa4bcdc7c89f919bbac9309d6e21ca83ce93ea", "hex");

      const promise_resp = app.getNullifier(path, pos, cmu);
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.clickRight()
      await sim.clickRight()
      await sim.clickBoth()

      const resp = await promise_resp
      expect(resp.returnCode).toEqual(0x9000)

      const expected_nfRaw = '3840188b5e05bced04ec715af62db7da39c06d643971a6748ee020c845427b95'

      if ('nfRaw' in resp) {
        const nfRaw = resp.nfRaw.toString('hex')
        console.log(nfRaw)
        expect(nfRaw).toEqual(expected_nfRaw)
      } else {
        fail("Expected property nfRaw is missing in the response.")
      }
    } finally {
      await sim.close()
    }
  })
})
