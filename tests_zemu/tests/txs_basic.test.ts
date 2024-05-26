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
import { get_inittx_data } from '@zondax/zcashtools'
import { TX_INPUT_DATA } from './_vectors'
jest.setTimeout(60000)

describe('tx methods', function () {
  test.concurrent.each(models)('txinit', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...defaultOptions,
        model: m.name,
        approveKeyword: m.name === 'stax' ? 'QR' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new ZCashApp(sim.getTransport())

      const tx_input_data = TX_INPUT_DATA[0]
      const {
        s_spend: [s_spend1, s_spend2],
        s_output: [s_out1, s_out2],
      } = tx_input_data

      const ledgerblob_initdata = get_inittx_data(tx_input_data)
      const reqinit = app.initNewTx(ledgerblob_initdata)

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-txinit`)

      const req = await reqinit

      console.log(req)
      expect(req.txdata.byteLength).toEqual(32)
    } finally {
      await sim.close()
    }
  })
})
