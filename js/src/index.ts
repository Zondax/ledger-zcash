/** ******************************************************************************
 *  (c) 2019 Zondax AG
 *  (c) 2016-2017 Ledger
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
import GenericApp, { INSGeneric, LedgerError, Transport, processErrorResponse, processResponse } from '@zondax/ledger-js'
import { serializePath } from '@zondax/ledger-js/dist/bip32'

import {
  CHUNK_SIZE,
  CLA,
  ERROR_CODE,
  INS,
  P1_VALUES,
  SAPLING_ADDR_LEN,
  SAPLING_AK_LEN,
  SAPLING_DIV_LEN,
  SAPLING_IVK_LEN,
  SAPLING_NF_LEN,
  SAPLING_NK_LEN,
  SAPLING_OVK_LEN,
  TRANSPARENT_PK_LEN,
} from './consts'
import { AddressResponse, DiversifierListResponse, IvkResponse, NullifierResponse } from './types'
import { prepareChunks, saplingPrepareChunks, saplingSendChunkv1, signSendChunkv1 } from './utils'

export default class ZCashApp extends GenericApp {
  constructor(transport: Transport) {
    super(transport, {
      cla: 0x85,
      ins: { ...INS } as INSGeneric,
      p1Values: {
        ONLY_RETRIEVE: 0x00,
        SHOW_ADDRESS_IN_DEVICE: 0x01,
      },
      acceptedPathLengths: [5],
      chunkSize: CHUNK_SIZE,
    })

    if (!this.transport) {
      throw new Error('Transport has not been defined')
    }
  }

  async getAddressTransparent(path: any): Promise<AddressResponse> {
    try {
      const sentToDevice = serializePath(path)

      const responseBuffer = await this.transport.send(CLA, INS.GET_ADDR_SECP256K1, P1_VALUES.ONLY_RETRIEVE, 0, sentToDevice)
      const response = processResponse(responseBuffer)

      // FIXME: probably incorrect.. and this should be pk
      const addressRaw = response.readBytes(TRANSPARENT_PK_LEN)
      const address = response.readBytes(response.length()).toString()

      return {
        address,
        addressRaw,
      }
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async getAddressSapling(zip32Account: number): Promise<AddressResponse> {
    const sentToDevice = Buffer.alloc(4)
    sentToDevice.writeUInt32LE(zip32Account, 0)

    try {
      const responseBuffer = await this.transport.send(CLA, INS.GET_ADDR_SAPLING, P1_VALUES.ONLY_RETRIEVE, 0, sentToDevice)
      const response = processResponse(responseBuffer)

      const addressRaw = response.readBytes(SAPLING_ADDR_LEN)
      const address = response.readBytes(response.length()).toString()

      return {
        address,
        addressRaw: addressRaw,
      }
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async getIvk(zip32Account: any): Promise<IvkResponse> {
    const sentToDevice = Buffer.alloc(4)
    sentToDevice.writeUInt32LE(zip32Account, 0)

    try {
      const responseBuffer = await this.transport.send(CLA, INS.GET_IVK_SAPLING, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, sentToDevice, [
        0x9000,
      ])
      const response = processResponse(responseBuffer)

      const ivkRaw = response.readBytes(SAPLING_IVK_LEN)
      const defaultDiv = response.readBytes(SAPLING_DIV_LEN)

      return {
        ivkRaw,
        defaultDiv,
      }
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async getOvk(zip32Account: any) {
    const sentToDevice = Buffer.alloc(4)
    sentToDevice.writeUInt32LE(zip32Account, 0)

    try {
      const responseBuffer = await this.transport.send(CLA, INS.GET_OVK_SAPLING, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, sentToDevice, [
        0x9000,
      ])
      const response = processResponse(responseBuffer)

      const ovkRaw = response.readBytes(SAPLING_OVK_LEN)

      return {
        ovkRaw,
      }
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async getFvk(zip32Account: any) {
    const sentToDevice = Buffer.alloc(4)
    sentToDevice.writeUInt32LE(zip32Account, 0)

    try {
      const responseBuffer = await this.transport.send(CLA, INS.GET_OVK_SAPLING, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, sentToDevice, [
        0x9000,
      ])
      const response = processResponse(responseBuffer)

      const akRaw = response.readBytes(SAPLING_AK_LEN)
      const nkRaw = response.readBytes(SAPLING_NK_LEN)
      const ovkRaw = response.readBytes(SAPLING_OVK_LEN)

      return {
        akRaw,
        nkRaw,
        ovkRaw,
      }
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  ////////////////////////////////////

  async getDiversifierList(path: any, index: any): Promise<DiversifierListResponse> {
    const sentToDevice = Buffer.alloc(4)
    sentToDevice.writeUInt32LE(path, 0)

    try {
      const responseBuffer = await this.transport.send(
        CLA,
        INS.GET_DIV_LIST,
        P1_VALUES.ONLY_RETRIEVE,
        0,
        Buffer.concat([sentToDevice, index])
      )
      const response = processResponse(responseBuffer)

      const diversifiers: Buffer[] = []
      while (response.length() >= 11) {
        const div = response.readBytes(11)
        if (div.toString('hex') !== '0000000000000000000000') {
          diversifiers.push(div)
        }
      }

      return { diversifiers } as DiversifierListResponse
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  // FIXME: What is this used for?
  async getAddrDiv(path: any, div: any) {
    const buf = Buffer.alloc(4)
    buf.writeUInt32LE(path, 0)
    return this.transport
      .send(CLA, INS.GET_ADDR_SAPLING_DIV, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.concat([buf, div]), [0x9000])
      .then(function (response: any): AddressResponse {
        let partialResponse = response

        const errorCodeData = partialResponse.slice(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

        const addressRaw = Buffer.from(partialResponse.slice(0, SAPLING_ADDR_LEN))
        partialResponse = partialResponse.slice(SAPLING_ADDR_LEN)

        const address = Buffer.from(partialResponse.slice(0, -2)).toString()

        return {
          address,
          addressRaw: addressRaw,
        }
      }, processErrorResponse)
  }

  // FIXME: What is this used for?
  async showAddrDiv(path: any, div: any) {
    const buf = Buffer.alloc(4)
    buf.writeUInt32LE(path, 0)
    return this.transport
      .send(CLA, INS.GET_ADDR_SAPLING_DIV, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, Buffer.concat([buf, div]), [0x9000])
      .then(function (response: any): AddressResponse {
        let partialResponse = response

        const errorCodeData = partialResponse.slice(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

        const addressRaw = Buffer.from(partialResponse.slice(0, SAPLING_ADDR_LEN))
        partialResponse = partialResponse.slice(SAPLING_ADDR_LEN)

        const address = Buffer.from(partialResponse.slice(0, -2)).toString()

        return {
          address,
          addressRaw: addressRaw,
        }
      }, processErrorResponse)
  }

  ////////////////////////////////////

  async getNullifier(zip32Account: any, pos: any, cm: any): Promise<NullifierResponse> {
    const sentToDevice = Buffer.alloc(4)
    sentToDevice.writeUInt32LE(zip32Account, 0)

    try {
      const responseBuffer = await this.transport.send(
        CLA,
        INS.GET_NF_SAPLING,
        P1_VALUES.ONLY_RETRIEVE,
        0,
        Buffer.concat([sentToDevice, pos, cm])
      )
      const response = processResponse(responseBuffer)

      const nfraw = Buffer.from(response.readBytes(SAPLING_NF_LEN))

      return { nfRaw: nfraw } as NullifierResponse
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  ////////////////////////////////////

  async initNewTx(message: any) {
    return this.saplingGetChunks(message).then(chunks => {
      return this.saplingSendChunk(INS.INIT_TX, 1, chunks.length, chunks[0], 0x00, [LedgerError.NoErrors]).then(async response => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          txdata: null,
        }

        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.saplingSendChunk(INS.INIT_TX, 1 + i, chunks.length, chunks[i], 0x00)
          if (result.returnCode !== ERROR_CODE.NoError) {
            break
          }
        }

        return {
          returnCode: result.returnCode,
          errorMessage: result.errorMessage,
          // ///
          txdata: result.txdata,
        }
      }, processErrorResponse)
    }, processErrorResponse)
  }

  async extractSpendSignature() {
    return this.transport.send(CLA, INS.EXTRACT_SPEND_SIGNATURE, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000]).then(function (
      response: any
    ) {
      const partialResponse = response

      const errorCodeData = partialResponse.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      const sigraw = Buffer.from(partialResponse.slice(0, 64))

      return {
        signatureRaw: sigraw.toString('hex'),
      }
    }, processErrorResponse)
  }

  async extractTransparentSig() {
    return this.transport.send(CLA, INS.EXTRACT_TRANS_SIGNATURE, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000]).then(function (
      response: any
    ) {
      const partialResponse = response

      const errorCodeData = partialResponse.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      const sigraw = Buffer.from(partialResponse.slice(0, 64))

      return {
        signatureRaw: sigraw.toString('hex'),
      }
    }, processErrorResponse)
  }

  async extractOutputData() {
    return this.transport.send(CLA, INS.EXTRACT_OUTPUT_DATA, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000]).then(function (
      response: any
    ) {
      const partialResponse = response

      const errorCodeData = partialResponse.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      const rcv = Buffer.from(partialResponse.slice(0, 32))
      const rseed = Buffer.from(partialResponse.slice(32, 64))
      let hashseed
      if (partialResponse.byteLength === 96 + 2) {
        hashseed = Buffer.from(partialResponse.slice(64, 96)).toString('hex')
      } else {
        hashseed = null
      }

      return {
        rcvRaw: rcv.toString('hex'),
        rseedRaw: rseed.toString('hex'),
        hashSeed: hashseed,
      }
    }, processErrorResponse)
  }

  async extractSpendData() {
    return this.transport.send(CLA, INS.EXTRACT_SPEND_DATA, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000]).then(function (
      response: any
    ) {
      const partialResponse = response

      const errorCodeData = partialResponse.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      const keyraw = Buffer.from(partialResponse.slice(0, 64))
      const rcv = Buffer.from(partialResponse.slice(64, 96))
      const alpha = Buffer.from(partialResponse.slice(96, 128))

      return {
        keyRaw: keyraw.toString('hex'),
        rcvRaw: rcv.toString('hex'),
        alphaRaw: alpha.toString('hex'),
      }
    }, processErrorResponse)
  }

  async showAddressAndPubKey(path: any, unshielded = false) {
    if (!unshielded) {
      const buf = Buffer.alloc(4)
      buf.writeUInt32LE(path, 0)
      return this.transport.send(CLA, INS.GET_ADDR_SAPLING, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, buf, [0x9000]).then(function (
        response: any
      ): AddressResponse {
        let partialResponse = response

        const errorCodeData = partialResponse.slice(-2)
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

        const addressRaw = Buffer.from(partialResponse.slice(0, SAPLING_ADDR_LEN))
        partialResponse = partialResponse.slice(SAPLING_ADDR_LEN)

        const address = Buffer.from(partialResponse.slice(0, -2)).toString()

        return {
          address,
          addressRaw: addressRaw,
        }
      }, processErrorResponse)
    }
    const serializedPath = this.serializePath(path)
    return this.transport.send(CLA, INS.GET_ADDR_SECP256K1, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, serializedPath, [0x9000]).then(function (
      response: any
    ): AddressResponse {
      let partialResponse = response

      const errorCodeData = partialResponse.slice(-2)
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1]

      const addressRaw = Buffer.from(partialResponse.slice(0, TRANSPARENT_PK_LEN))
      partialResponse = partialResponse.slice(TRANSPARENT_PK_LEN)

      const address = Buffer.from(partialResponse.slice(0, -2)).toString()

      return {
        address,
        addressRaw: addressRaw,
      }
    }, processErrorResponse)
  }

  async signSendChunk(chunkIdx: any, chunkNum: any, chunk: any) {
    return signSendChunkv1(this, chunkIdx, chunkNum, chunk)
  }

  async saplingGetChunks(message: any) {
    return saplingPrepareChunks(message)
  }

  async checkSpendsGetChunks(path: any, message: any) {
    return prepareChunks(serializePath(path), message)
  }

  async saplingSendChunk(version: any, chunkIdx: any, chunkNum: any, chunk: any, p2: any, acceptErrors?: any) {
    return saplingSendChunkv1(this, version, chunkIdx, chunkNum, chunk, p2, acceptErrors)
  }

  async checkAndSign(message: any, txVersion: any) {
    return this.saplingGetChunks(message).then(chunks => {
      return this.saplingSendChunk(INS.CHECK_AND_SIGN, 1, chunks.length, chunks[0], txVersion).then(async response => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          signdata: null,
        }

        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.saplingSendChunk(INS.CHECK_AND_SIGN, 1 + i, chunks.length, chunks[i], txVersion)
          if (result.returnCode !== ERROR_CODE.NoError) {
            break
          }
        }

        return {
          returnCode: result.returnCode,
          errorMessage: result.errorMessage,
          // ///
          signdata: result.signdata,
        }
      }, processErrorResponse)
    }, processErrorResponse)
  }
}
