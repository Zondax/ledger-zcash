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
import GenericApp, { INSGeneric, LedgerError, ResponsePayload, Transport, processErrorResponse, processResponse } from '@zondax/ledger-js'
import { serializePath } from '@zondax/ledger-js/dist/bip32'
import { ResponseError } from '@zondax/ledger-js/dist/responseError'

import {
  CHUNK_SIZE,
  CLA,
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
import {
  AddressResponse,
  DiversifierListResponse,
  ExtractSpendResponse,
  FvkResponse,
  InitTxResponse,
  IvkResponse,
  NullifierResponse,
  OutputDataResponse,
  OvkResponse,
  SignResponse,
  SpendSignatureResponse,
  TransaparentSignatureResponse,
} from './types'
import { signSendChunkv1 } from './utils'

export default class ZCashApp extends GenericApp {
  constructor(transport: Transport) {
    super(transport, {
      cla: CLA,
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

  ////////////////////////////////////////////
  ////////////////////////////////////////////
  ////////////////////////////////////////////

  async getAddressTransparent(path: string, showInScreen = true): Promise<AddressResponse> {
    try {
      const sentToDevice = serializePath(path)

      const p1 = showInScreen ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE
      const responseBuffer = await this.transport.send(CLA, INS.GET_ADDR_SECP256K1, p1, 0, sentToDevice)
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

  async getAddressSapling(zip32Account: number, showInScreen = true): Promise<AddressResponse> {
    const sentToDevice = Buffer.alloc(4)
    sentToDevice.writeUInt32LE(zip32Account, 0)

    try {
      const p1 = showInScreen ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE
      const responseBuffer = await this.transport.send(CLA, INS.GET_ADDR_SAPLING, p1, 0, sentToDevice)
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

  async getAddressSamplingFromDiversifier(zip32Account: number, diversifier: Buffer, showInScreen = true): Promise<AddressResponse> {
    if (diversifier?.length !== 11) {
      throw new ResponseError(LedgerError.IncorrectData, 'diversifier Buffer must be exactly 11 bytes')
    }

    const sentToDevice = Buffer.alloc(4 + 11)
    sentToDevice.writeUInt32LE(zip32Account, 0)
    diversifier.copy(sentToDevice, 4)

    try {
      const p1 = showInScreen ? P1_VALUES.SHOW_ADDRESS_IN_DEVICE : P1_VALUES.ONLY_RETRIEVE
      const responseBuffer = await this.transport.send(CLA, INS.GET_ADDR_SAPLING_DIV, p1, 0, sentToDevice)
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

  ////////////////////////////////////////////
  ////////////////////////////////////////////

  async getIvkSapling(zip32Account: number): Promise<IvkResponse> {
    const sentToDevice = Buffer.alloc(4)
    sentToDevice.writeUInt32LE(zip32Account, 0)

    try {
      const responseBuffer = await this.transport.send(CLA, INS.GET_IVK_SAPLING, 0, 0, sentToDevice, [0x9000])
      const response = processResponse(responseBuffer)

      const ivkRaw = response.readBytes(SAPLING_IVK_LEN)
      const defaultDiversifier = response.readBytes(SAPLING_DIV_LEN)

      return {
        ivkRaw,
        defaultDiversifier: defaultDiversifier,
      }
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async getOvkSapling(zip32Account: number): Promise<OvkResponse> {
    const sentToDevice = Buffer.alloc(4)
    sentToDevice.writeUInt32LE(zip32Account, 0)

    try {
      const responseBuffer = await this.transport.send(CLA, INS.GET_OVK_SAPLING, 0, 0, sentToDevice, [0x9000])
      const response = processResponse(responseBuffer)

      const ovkRaw = response.readBytes(SAPLING_OVK_LEN)

      return {
        ovkRaw,
      }
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async getFvkSapling(zip32Account: number): Promise<FvkResponse> {
    const sentToDevice = Buffer.alloc(4)
    sentToDevice.writeUInt32LE(zip32Account, 0)

    try {
      const responseBuffer = await this.transport.send(CLA, INS.GET_FVK_SAPLING, 0, 0, sentToDevice, [0x9000])
      const response = processResponse(responseBuffer)

      console.log(response.length())

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

  async getDiversifierList(zip32Account: number, startingDiversifier: Buffer): Promise<DiversifierListResponse> {
    if (startingDiversifier?.length !== 11) {
      throw new ResponseError(LedgerError.IncorrectData, 'startingDiversifier Buffer must be exactly 11 bytes')
    }

    const sentToDevice = Buffer.alloc(4 + 11)
    sentToDevice.writeUInt32LE(zip32Account, 0)
    startingDiversifier.copy(sentToDevice, 4)

    try {
      const responseBuffer = await this.transport.send(CLA, INS.GET_DIV_LIST, 0, 0, sentToDevice)
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

  async getNullifierSapling(zip32Account: number, notePosition: bigint, ncm: Buffer): Promise<NullifierResponse> {
    if (ncm.length !== 32) {
      throw new ResponseError(LedgerError.IncorrectData, 'ncm Buffer must be exactly 32 bytes')
    }

    const sentToDevice = Buffer.alloc(4 + 8 + 32)
    sentToDevice.writeUInt32LE(zip32Account, 0)
    sentToDevice.writeBigUInt64LE(notePosition, 4)
    ncm.copy(sentToDevice, 12)

    try {
      const responseBuffer = await this.transport.send(
        CLA,
        INS.GET_NF_SAPLING,
        0, // ignored
        0,
        sentToDevice
      )
      const response = processResponse(responseBuffer)

      const nfraw = Buffer.from(response.readBytes(SAPLING_NF_LEN))

      return { nfRaw: nfraw } as NullifierResponse
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  ////////////////////////////////////
  ////////////////////////////////////
  ////////////////////////////////////
  ////////////////////////////////////
  ////////////////////////////////////

  async initNewTx(message: any): Promise<InitTxResponse> {
    try {
      const chunks = this.messageToChunks(message)

      // Add empty chunk to trigger the init/reset
      chunks.unshift(Buffer.alloc(0))

      let result: ResponsePayload | undefined
      for (const [idx, chunk] of chunks.entries()) {
        result = await this.sendGenericChunk(INS.INIT_TX, 0x00, idx + 1, chunks.length, chunk)
      }

      if (result) {
        return {
          txdataRaw: result.getCompleteBuffer(),
          txdata: result.getCompleteBuffer().toString('hex'),
        }
      }

      throw new ResponseError(LedgerError.UnknownError, 'Unknown error')
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async extractSpendSignature(): Promise<SpendSignatureResponse> {
    try {
      const empty = Buffer.alloc(0)
      const responseBuffer = await this.transport.send(CLA, INS.EXTRACT_SPEND_SIGNATURE, P1_VALUES.ONLY_RETRIEVE, 0, empty, [0x9000])
      const response = processResponse(responseBuffer)

      return {
        signatureRaw: response.getCompleteBuffer(),
        signature: response.getCompleteBuffer().toString('hex'),
      } as SpendSignatureResponse
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async extractTransparentSig(): Promise<TransaparentSignatureResponse> {
    try {
      const empty = Buffer.alloc(0)
      const responseBuffer = await this.transport.send(CLA, INS.EXTRACT_TRANS_SIGNATURE, P1_VALUES.ONLY_RETRIEVE, 0, empty, [0x9000])
      const response = processResponse(responseBuffer)

      return {
        signatureRaw: response.getCompleteBuffer(),
        signature: response.getCompleteBuffer().toString('hex'),
      } as TransaparentSignatureResponse
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async extractOutputData(): Promise<OutputDataResponse> {
    try {
      const empty = Buffer.alloc(0)
      const responseBuffer = await this.transport.send(CLA, INS.EXTRACT_OUTPUT_DATA, P1_VALUES.ONLY_RETRIEVE, 0, empty, [0x9000])
      const response = processResponse(responseBuffer)

      const rcv = response.readBytes(32)
      const rseed = response.readBytes(32)
      const hashseed = response.getAvailableBuffer()

      return {
        rcvRaw: rcv,
        rseedRaw: rseed,
        hashSeedRaw: hashseed,
        rcv: rcv.toString('hex'),
        rseed: rseed.toString('hex'),
        hashSeed: hashseed.toString('hex'),
      } as OutputDataResponse
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async extractSpendData(): Promise<ExtractSpendResponse> {
    try {
      const empty = Buffer.alloc(0)
      const responseBuffer = await this.transport.send(CLA, INS.EXTRACT_SPEND_DATA, P1_VALUES.ONLY_RETRIEVE, 0, empty, [0x9000])
      const response = processResponse(responseBuffer)

      const key = response.readBytes(64)
      const rcv = response.readBytes(32)
      const alpha = response.readBytes(32)

      return {
        key: key.toString('hex'),
        rcv: rcv.toString('hex'),
        alpha: alpha.toString('hex'),

        keyRaw: key,
        rcvRaw: rcv,
        alphaRaw: alpha,
      } as ExtractSpendResponse
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  async checkAndSign(message: any, txVersion: any): Promise<SignResponse> {
    try {
      const chunks = this.messageToChunks(message)

      // Add empty chunk to trigger the init/reset
      chunks.unshift(Buffer.alloc(0))

      let result: ResponsePayload | undefined
      for (const [idx, chunk] of chunks.entries()) {
        result = await this.sendGenericChunk(INS.CHECK_AND_SIGN, txVersion, idx + 1, chunks.length, chunk)
      }

      if (result) {
        return {
          signdataRaw: result.getCompleteBuffer(),
          signdata: result.getCompleteBuffer().toString('hex'),
        }
      }

      throw new ResponseError(LedgerError.UnknownError, 'Unknown error')
    } catch (error) {
      throw processErrorResponse(error)
    }
  }

  ///////////////////////////////////////
  ///////////////////////////////////////
  ///////////////////////////////////////
  ///////////////////////////////////////
  ///////////////////////////////////////

  async signSendChunk(chunkIdx: any, chunkNum: any, chunk: any) {
    return signSendChunkv1(this, chunkIdx, chunkNum, chunk)
  }

  async checkSpendsGetChunks(path: any, message: any) {
    return this.prepareChunks(path, message)
  }
}
