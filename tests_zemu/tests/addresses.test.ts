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

jest.setTimeout(60000)

describe('Addresses', function() {
  test.concurrent.each(models)('get unshielded address', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
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

  test.concurrent.each(models)('get shielded address', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000 + 0x80000000;
      const addr = await app.getAddressSapling(zip32Account, false)

      const expected_addrRaw = '71635f26c1b4a2332abeb70b1249e61ed4e40b1cc114c1ef994dcf304e2e5945748e879660550443161cda'
      const expected_addr = 'zs1w9347fkpkj3rx247ku93yj0xrm2wgzcucy2vrmuefh8nqn3wt9zhfr58jes92pzrzcwd5rrjn0g'

      expect(addr?.addressRaw.toString('hex')).toEqual(expected_addrRaw)
      expect(addr?.address).toEqual(expected_addr)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get invalid shielded address', async function(m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new ZCashApp(sim.getTransport())

      const zip32Account = 1000;
      await expect(app.getAddressSapling(zip32Account, false)).rejects.toThrow()

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

      const zip32Account = 1000 + 0x80000000;
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
