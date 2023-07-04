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

import Zemu, { ButtonKind, DEFAULT_START_OPTIONS, zondaxMainmenuNavigation } from '@zondax/zemu'
import { APP_SEED, models } from './common'
import ZCashApp from '@zondax/ledger-zcash'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
}

jest.setTimeout(600000)

describe('Standard', function () {
  test.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      const mainmenuNavigation = zondaxMainmenuNavigation(m.name)
      await sim.start({ ...defaultOptions, model: m.name })
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, mainmenuNavigation.schedule)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('get app version', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())
      const resp = await app.getVersion()

      console.log(resp)

      expect(resp.return_code).toEqual(0x9000)
      expect(resp.error_message).toEqual('No errors')
      expect(resp).toHaveProperty('test_mode')
      expect(resp).toHaveProperty('major')
      expect(resp).toHaveProperty('minor')
      expect(resp).toHaveProperty('patch')
    } finally {
      await sim.close()
    }
  })
})

describe('Addresses', function () {
  test.each(models)('get unshielded address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const addr = await app.getAddressAndPubKey("m/44'/133'/5'/0/0", true)
      console.log(addr)
      expect(addr.return_code).toEqual(0x9000)

      const expected_addr_raw = '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e'
      const expected_addr = 't1KHG39uhsssPkYcAXkzZ5Bk2w1rnFukZvx'

      const addr_raw = addr.address_raw.toString('hex')
      expect(addr_raw).toEqual(expected_addr_raw)
      expect(addr.address).toEqual(expected_addr)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('show unshielded address', async function (m) {
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
      expect(addr.return_code).toEqual(0x9000)

      const expected_addr_raw = '026f27818e7426a10773226b3553d0afe50a3697bd02652f1b57d67bf648577d11'
      const expected_addr = 't1PYLcQqpxou9Eak4nroMNGKYoxT4HPdHqJ'

      const addr_raw = addr.address_raw.toString('hex')
      expect(addr_raw).toEqual(expected_addr_raw)
      expect(addr.address).toEqual(expected_addr)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('get shielded address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const addr = await app.getAddressAndPubKey(1000)

      console.log(addr)
      expect(addr.return_code).toEqual(0x9000)

      const expected_addr_raw = 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667'
      const expected_addr = 'zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3'

      const addr_raw = addr.address_raw.toString('hex')
      expect(addr_raw).toEqual(expected_addr_raw)
      expect(addr.address).toEqual(expected_addr)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('show shielded address', async function (m) {
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
      expect(addr.return_code).toEqual(0x9000)

      const expected_addr_raw = 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667'
      const expected_addr = 'zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3'

      const addr_raw = addr.address_raw.toString('hex')
      expect(addr_raw).toEqual(expected_addr_raw)
      expect(addr.address).toEqual(expected_addr)
    } finally {
      await sim.close()
    }
  })
})
