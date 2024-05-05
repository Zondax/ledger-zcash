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

import GenericApp, { INSGeneric, LedgerError, ResponseBase, Transport, errorCodeToString, processErrorResponse } from "@zondax/ledger-js";
import {
  CHUNK_SIZE,
  CLA,
  ERROR_CODE,
  INS,
  P1_VALUES,
  PKLEN,
  SAPLING_ADDR_LEN,
  SAPLING_AK_LEN,
  SAPLING_DIV_LEN,
  SAPLING_IVK_LEN,
  SAPLING_NF_LEN,
  SAPLING_NK_LEN,
  SAPLING_OVK_LEN,
} from "./common";

import { saplingSendChunkv1, signSendChunkv1 } from "./helper";

type AddressResponse = ResponseBase & (
  ResponseBase['returnCode'] extends LedgerError.NoErrors ? {
    address: string;
    addressRaw: Buffer;
  } : {}
);

function processGetUnshieldedAddrResponse(response: any): AddressResponse {
  let partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const addressRaw = Buffer.from(partialResponse.slice(0, PKLEN));
  partialResponse = partialResponse.slice(PKLEN);

  const address = Buffer.from(partialResponse.slice(0, -2)).toString();

  return {
    address,
    addressRaw: addressRaw,
    returnCode: LedgerError.NoErrors,
    errorMessage: errorCodeToString(returnCode),
  };
}

function processDivListResponse(response: any) {
  const partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const divlist = [];
  const data = partialResponse.slice(0, 220);
  if (response.length > 2) {
    let i;
    let div;
    for (i = 0; i < 20; i += 1) {
      div = data.slice(i * 11, (i + 1) * 11).toString("hex");
      if (div !== "0000000000000000000000") {
        divlist.push(div);
      }
    }
  }

  return {
    divlist,
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

function processNullifierResponse(response: any) {
  const partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const nfraw = Buffer.from(partialResponse.slice(0, SAPLING_NF_LEN));

  return {
    nfRaw: nfraw,
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

function processIVKResponse(response: any) {
  let partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const ivkraw = Buffer.from(partialResponse.slice(0, SAPLING_IVK_LEN));
  // "advance" buffer

  partialResponse = partialResponse.slice(SAPLING_IVK_LEN);
  const defaultdiv = Buffer.from(partialResponse.slice(0, SAPLING_DIV_LEN));

  return {
    ivkRaw: ivkraw,
    default_div: defaultdiv,
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

function processOVKResponse(response: any) {
  const partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const ovkraw = Buffer.from(partialResponse.slice(0, SAPLING_OVK_LEN));

  return {
    ovkRaw: ovkraw,
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

function processFVKResponse(response: any) {
  let partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const akraw = Buffer.from(partialResponse.slice(0, SAPLING_AK_LEN));
  partialResponse = partialResponse.slice(SAPLING_AK_LEN);

  const nkraw = Buffer.from(partialResponse.slice(0, SAPLING_NK_LEN));
  partialResponse = partialResponse.slice(SAPLING_NK_LEN);

  const ovkraw = Buffer.from(partialResponse.slice(0, SAPLING_OVK_LEN));

  return {
    akRaw: akraw,
    nkRaw: nkraw,
    ovkRaw: ovkraw,
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

function processOutputResponse(response: any) {
  const partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const rcv = Buffer.from(partialResponse.slice(0, 32));
  const rseed = Buffer.from(partialResponse.slice(32, 64));
  let hashseed;
  if (partialResponse.byteLength === 96 + 2) {
    hashseed = Buffer.from(partialResponse.slice(64, 96)).toString("hex");
  } else {
    hashseed = null;
  }

  return {
    rcvRaw: rcv.toString("hex"),
    rseedRaw: rseed.toString("hex"),
    hashSeed: hashseed,
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

function processSpendResponse(response: any) {
  const partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const keyraw = Buffer.from(partialResponse.slice(0, 64));
  const rcv = Buffer.from(partialResponse.slice(64, 96));
  const alpha = Buffer.from(partialResponse.slice(96, 128));

  return {
    keyRaw: keyraw.toString("hex"),
    rcvRaw: rcv.toString("hex"),
    alphaRaw: alpha.toString("hex"),
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

function processSIGResponse(response: any) {
  const partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const sigraw = Buffer.from(partialResponse.slice(0, 64));

  return {
    signatureRaw: sigraw.toString("hex"),
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

function processTRANSIGResponse(response: any) {
  const partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const sigraw = Buffer.from(partialResponse.slice(0, 64));

  return {
    signatureRaw: sigraw.toString("hex"),
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

function processGetShieldedAddrResponse(response: any) : AddressResponse {
  let partialResponse = response;

  const errorCodeData = partialResponse.slice(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const addressRaw = Buffer.from(partialResponse.slice(0, SAPLING_ADDR_LEN));
  partialResponse = partialResponse.slice(SAPLING_ADDR_LEN);

  const address = Buffer.from(partialResponse.slice(0, -2)).toString();

  return {
    address,
    addressRaw: addressRaw,
    returnCode: returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}

export default class ZCashApp extends GenericApp {
  constructor(transport: Transport) {
    super(transport, {
      cla: 0xb0,
      ins: { ...INS } as INSGeneric,
      p1Values: {
        ONLY_RETRIEVE: 0x00,
        SHOW_ADDRESS_IN_DEVICE: 0x01,
      },
      acceptedPathLengths: [5],
      chunkSize: CHUNK_SIZE,
    });

    if (!this.transport) {
      throw new Error("Transport has not been defined");
    }
  }

  static saplingprepareChunks(message: any) {
    const chunks = [];
    chunks.push(Buffer.from([]));
    const buffer = Buffer.from(message);
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE;
      if (i > buffer.length) {
        end = buffer.length;
      }
      chunks.push(buffer.subarray(i, end));
    }

    return chunks;
  }

  static prepareChunks(serializedPathBuffer: any, message: any) {
    const chunks = [];

    // First chunk (only path)
    chunks.push(serializedPathBuffer);

    const messageBuffer = Buffer.from(message);

    const buffer = Buffer.concat([messageBuffer]);
    for (let i = 0; i < buffer.length; i += CHUNK_SIZE) {
      let end = i + CHUNK_SIZE;
      if (i > buffer.length) {
        end = buffer.length;
      }
      chunks.push(buffer.subarray(i, end));
    }

    return chunks;
  }

  async signGetChunks(path: any, message: any) {
    return ZCashApp.prepareChunks(this.serializePath(path), message);
  }

  
  /**
   * Retrieves the address and public key for a given path.
   * If `unshielded` is false, it retrieves a shielded address and public key.
   * 
   * @param path - The derivation path for the address.
   * @param unshielded - Flag to indicate if an unshielded address should be retrieved.
   * @returns A promise that resolves to an object containing the address and raw address buffer, along with standard response details.
   */
  async getAddressAndPubKey(path: any, unshielded = false): Promise<ResponseBase | AddressResponse> {
    if (!unshielded) {
      const buf = Buffer.alloc(4);
      buf.writeUInt32LE(path, 0);
      return this.transport
        .send(CLA, INS.GET_ADDR_SAPLING, P1_VALUES.ONLY_RETRIEVE, 0, buf, [0x9000])
        .then(processGetShieldedAddrResponse, processErrorResponse);
    }
    const serializedPath = this.serializePath(path);
    return this.transport
      .send(CLA, INS.GET_ADDR_SECP256K1, P1_VALUES.ONLY_RETRIEVE, 0, serializedPath, [0x9000])
      .then(processGetUnshieldedAddrResponse, processErrorResponse);
  }

  async getivk(path: any) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
      .send(CLA, INS.GET_IVK_SAPLING, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, buf, [0x9000])
      .then(processIVKResponse, processErrorResponse);
  }

  async getovk(path: any) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
      .send(CLA, INS.GET_OVK_SAPLING, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, buf, [0x9000])
      .then(processOVKResponse, processErrorResponse);
  }

  async getNullifier(path: any, pos: any, cm: any) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
      .send(CLA, INS.GET_NF_SAPLING, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, Buffer.concat([buf, pos, cm]), [0x9000])
      .then(processNullifierResponse, processErrorResponse);
  }

  async getFVK(path: any) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
      .send(CLA, INS.GET_FVK_SAPLING, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, buf, [0x9000])
      .then(processFVKResponse, processErrorResponse);
  }

  async extractSpendSignature() {
    return this.transport
      .send(CLA, INS.EXTRACT_SPEND_SIGNATURE, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000])
      .then(processSIGResponse, processErrorResponse);
  }

  async extracttranssig() {
    return this.transport
      .send(CLA, INS.EXTRACT_TRANS_SIGNATURE, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000])
      .then(processTRANSIGResponse, processErrorResponse);
  }

  async extractoutputdata() {
    return this.transport
      .send(CLA, INS.EXTRACT_OUTPUT_DATA, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000])
      .then(processOutputResponse, processErrorResponse);
  }

  async extractSpendData() {
    return this.transport
      .send(CLA, INS.EXTRACT_SPEND_DATA, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.from([]), [0x9000])
      .then(processSpendResponse, processErrorResponse);
  }

  async getDivList(path: any, index: any) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
      .send(CLA, INS.GET_DIV_LIST, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.concat([buf, index]), [0x9000])
      .then(processDivListResponse, processErrorResponse);
  }

  async getAddrDiv(path: any, div: any) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
      .send(CLA, INS.GET_ADDR_SAPLING_DIV, P1_VALUES.ONLY_RETRIEVE, 0, Buffer.concat([buf, div]), [0x9000])
      .then(processGetShieldedAddrResponse, processErrorResponse);
  }

  async showAddrDiv(path: any, div: any) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32LE(path, 0);
    return this.transport
      .send(CLA, INS.GET_ADDR_SAPLING_DIV, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, Buffer.concat([buf, div]), [0x9000])
      .then(processGetShieldedAddrResponse, processErrorResponse);
  }

  async showAddressAndPubKey(path: any, unshielded = false) {
    if (!unshielded) {
      const buf = Buffer.alloc(4);
      buf.writeUInt32LE(path, 0);
      return this.transport
        .send(CLA, INS.GET_ADDR_SAPLING, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, buf, [0x9000])
        .then(processGetShieldedAddrResponse, processErrorResponse);
    }
    const serializedPath = this.serializePath(path);
    return this.transport
      .send(CLA, INS.GET_ADDR_SECP256K1, P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, serializedPath, [0x9000])
      .then(processGetUnshieldedAddrResponse, processErrorResponse);
  }

  async signSendChunk(chunkIdx: any, chunkNum: any, chunk: any) {
    return signSendChunkv1(this, chunkIdx, chunkNum, chunk);
  }

  async saplingGetChunks(message: any) {
    return ZCashApp.saplingprepareChunks(message);
  }

  async checkSpendsGetChunks(path: any, message: any) {
    return ZCashApp.prepareChunks(this.serializePath(path), message);
  }

  async saplingSendChunk(version: any, chunkIdx: any, chunkNum: any, chunk: any, p2: any, acceptErrors?: any) {
    return saplingSendChunkv1(this, version, chunkIdx, chunkNum, chunk, p2, acceptErrors);
  }

  async checkAndSign(message: any, txVersion: any) {
    return this.saplingGetChunks(message).then((chunks) => {
      return this.saplingSendChunk(INS.CHECK_AND_SIGN, 1, chunks.length, chunks[0], txVersion, ).then(async (response) => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
          signdata: null,
        };

        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.saplingSendChunk(INS.CHECK_AND_SIGN, 1 + i, chunks.length, chunks[i], txVersion);
          if (result.returnCode !== ERROR_CODE.NoError) {
            break;
          }
        }

        return {
          returnCode: result.returnCode,
          errorMessage: result.errorMessage,
          // ///
          signdata: result.signdata,
        };
      }, processErrorResponse);
    }, processErrorResponse);
  }

  async initNewTx(message: any) {
    return this.saplingGetChunks(message).then((chunks) => {
      return this.saplingSendChunk(INS.INIT_TX, 1, chunks.length, chunks[0], 0x00, [LedgerError.NoErrors]).then(
        async (response) => {
          let result = {
            returnCode: response.returnCode,
            errorMessage: response.errorMessage,
            txdata: null,
          };

          for (let i = 1; i < chunks.length; i += 1) {
            // eslint-disable-next-line no-await-in-loop
            result = await this.saplingSendChunk(INS.INIT_TX, 1 + i, chunks.length, chunks[i], 0x00);
            if (result.returnCode !== ERROR_CODE.NoError) {
              break;
            }
          }

          return {
            returnCode: result.returnCode,
            errorMessage: result.errorMessage,
            // ///
            txdata: result.txdata,
          };
        },
        processErrorResponse,
      );
    }, processErrorResponse);
  }
}
