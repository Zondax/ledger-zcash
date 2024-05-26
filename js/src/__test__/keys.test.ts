/******************************************************************************
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
 *****************************************************************************/

/* eslint-disable no-console */
import { MockTransport } from '@ledgerhq/hw-transport-mocker'

import { SAPLING_AK_LEN, SAPLING_DIV_LEN, SAPLING_IVK_LEN, SAPLING_NK_LEN, SAPLING_OVK_LEN } from '../consts'
import ZCashApp from '../index'

describe('ZCashApp', () => {
  describe('getNullifier', () => {
    it('should correctly handle the getNullifier command', async () => {
      const mockResponse = Buffer.concat([
        Buffer.alloc(32), // empty nullifier
        Buffer.from([0x90, 0x00]), // Status word (SW) for success
      ])
      const transport = new MockTransport(mockResponse)
      const app = new ZCashApp(transport)

      const zip32Account = 0x01
      const pos: bigint = BigInt(12345)
      const cm = Buffer.alloc(32)

      const response = await app.getNullifierSapling(zip32Account, pos, cm)

      expect(response.nfRaw).toEqual(Buffer.alloc(32))
    })

    it('should throw an error if the device returns an error status', async () => {
      const errorResponse = Buffer.from([0x69, 0x85]) // Example error SW
      const transport = new MockTransport(errorResponse)
      const app = new ZCashApp(transport)

      const zip32Account = 0x01
      const pos: bigint = BigInt(12345)
      const cm = Buffer.alloc(32)

      await expect(app.getNullifierSapling(zip32Account, pos, cm)).rejects.toThrow()
    })
  })

  describe('getIvkSapling', () => {
    it('should correctly handle the getIvkSapling command', async () => {
      const mockResponse = Buffer.concat([
        Buffer.alloc(SAPLING_IVK_LEN + SAPLING_DIV_LEN), // empty ivk + div
        Buffer.from([0x90, 0x00]), // Status word (SW) for success
      ])
      const transport = new MockTransport(mockResponse)
      const app = new ZCashApp(transport)

      const zip32Account = 0x01
      const response = await app.getIvkSapling(zip32Account)

      expect(response.ivkRaw).toEqual(Buffer.alloc(SAPLING_IVK_LEN))
    })
  })

  describe('getOvkSapling', () => {
    it('should correctly handle the getOvkSapling command', async () => {
      const mockResponse = Buffer.concat([
        Buffer.alloc(SAPLING_OVK_LEN), // empty ovk
        Buffer.from([0x90, 0x00]), // Status word (SW) for success
      ])
      const transport = new MockTransport(mockResponse)
      const app = new ZCashApp(transport)

      const zip32Account = 0x01
      const response = await app.getOvkSapling(zip32Account)

      expect(response.ovkRaw).toEqual(Buffer.alloc(SAPLING_OVK_LEN))
    })
  })

  describe('getFvkSapling', () => {
    it('should correctly handle the getFvkSapling command', async () => {
      const mockResponse = Buffer.concat([
        Buffer.alloc(SAPLING_AK_LEN + SAPLING_NK_LEN + SAPLING_OVK_LEN), // empty fvk
        Buffer.from([0x90, 0x00]), // Status word (SW) for success
      ])
      const transport = new MockTransport(mockResponse)
      const app = new ZCashApp(transport)

      const zip32Account = 0x01
      const response = await app.getFvkSapling(zip32Account)

      expect(response.akRaw).toEqual(Buffer.alloc(SAPLING_AK_LEN))
      expect(response.nkRaw).toEqual(Buffer.alloc(SAPLING_NK_LEN))
      expect(response.ovkRaw).toEqual(Buffer.alloc(SAPLING_OVK_LEN))
    })
  })

  describe('getDiversifierList', () => {
    it('should correctly handle the getDiversifierList command', async () => {
      const mockResponse = Buffer.concat([
        Buffer.alloc(11 * 20).fill(0x01),
        Buffer.from([0x90, 0x00]), // Status word (SW) for success
      ])
      const transport = new MockTransport(mockResponse)
      const app = new ZCashApp(transport)

      const zip32Account = 0x01
      const startingDiversifier = Buffer.alloc(11)
      const response = await app.getDiversifierList(zip32Account, startingDiversifier)

      expect(response.diversifiers.length).toBeGreaterThan(0)
    })
  })
})
