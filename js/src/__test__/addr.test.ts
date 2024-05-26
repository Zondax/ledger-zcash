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

import { SAPLING_ADDR_LEN, SAPLING_DIV_LEN } from '../consts'
import ZCashApp from '../index'

describe('ZCashApp', () => {
  describe('getAddressSamplingFromDiversifier', () => {
    it('should correctly handle the getAddrDiv command', async () => {
      const mockResponse = Buffer.concat([
        Buffer.alloc(SAPLING_ADDR_LEN), // empty address
        Buffer.from([0x90, 0x00]), // Status word (SW) for success
      ])
      const transport = new MockTransport(mockResponse)
      const app = new ZCashApp(transport)

      const zip32Account = 0x01
      const div = Buffer.alloc(SAPLING_DIV_LEN)
      const response = await app.getAddressSamplingFromDiversifier(zip32Account, div)

      expect(response.addressRaw).toEqual(Buffer.alloc(SAPLING_ADDR_LEN))
    })
  })

  describe('getAddressSapling', () => {
    it('should correctly handle the getAddressSapling command', async () => {
      const mockResponse = Buffer.concat([
        Buffer.alloc(SAPLING_ADDR_LEN), // empty address
        Buffer.from([0x90, 0x00]), // Status word (SW) for success
      ])
      const transport = new MockTransport(mockResponse)
      const app = new ZCashApp(transport)

      const zip32Account = 0x01
      const response = await app.getAddressSapling(zip32Account)

      expect(response.addressRaw).toEqual(Buffer.alloc(SAPLING_ADDR_LEN))
    })
  })
})
