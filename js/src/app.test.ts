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

import { CLA, INS, P1_VALUES, SAPLING_NF_LEN } from './consts'
import ZCashApp from './index'

describe('ZCashApp', () => {
  describe('getNullifier', () => {
    it('should correctly handle the getNullifier command', async () => {
      const mockResponse = Buffer.concat([
        Buffer.from([0x01, 0x02, 0x03, 0x04]), // Example nullifier data
        Buffer.from([0x90, 0x00]), // Status word (SW) for success
      ])
      const transport = new MockTransport(mockResponse)
      const app = new ZCashApp(transport)

      const zip32Account = 0x01
      const pos = Buffer.from([0x00, 0x01, 0x02, 0x03])
      const cm = Buffer.from([0x04, 0x05, 0x06, 0x07])

      const response = await app.getNullifier(zip32Account, pos, cm)

      expect(response.nfRaw).toEqual('01020304')
      expect(transport.send).toHaveBeenCalledWith(CLA, INS.GET_NF_SAPLING, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, expect.any(Buffer), [
        0x9000,
      ])
    })

    it('should throw an error if the device returns an error status', async () => {
      const errorResponse = Buffer.from([0x69, 0x85]) // Example error SW
      const transport = new MockTransport(errorResponse)
      const app = new ZCashApp(transport)

      const zip32Account = 0x01
      const pos = Buffer.from([0x00, 0x01, 0x02, 0x03])
      const cm = Buffer.from([0x04, 0x05, 0x06, 0x07])

      await expect(app.getNullifier(zip32Account, pos, cm)).rejects.toThrow()
    })
  })
})
