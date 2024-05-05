import { PAYLOAD_TYPE, errorCodeToString, processErrorResponse } from "@zondax/ledger-js";
import { CLA, INS, P2_VALUES } from "./common";

export async function signSendChunkv1(app: any, chunkIdx: number, chunkNum: number, chunk: Buffer) {
  let payloadType = PAYLOAD_TYPE.ADD;
  if (chunkIdx === 1) {
    payloadType = PAYLOAD_TYPE.INIT;
  }
  if (chunkIdx === chunkNum) {
    payloadType = PAYLOAD_TYPE.LAST;
  }
  return app.transport
    .send(CLA, INS.SIGN_SECP256K1, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80])
    .then((response: any) => {
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
      let errorMessage = errorCodeToString(returnCode);

      if (returnCode === 0x6a80 || returnCode === 0x6984) {
        errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
      }

      let signatureCompact = null;
      let signatureDER = null;
      if (response.length > 2) {
        signatureCompact = response.slice(0, 65);
        signatureDER = response.slice(65, response.length - 2);
      }

      return {
        signature_compact: signatureCompact,
        signature_der: signatureDER,
        returnCode: returnCode,
        errorMessage: errorMessage,
      };
    }, processErrorResponse);
}

export async function saplingSendChunkv1(app: any, version: number, chunkIdx: number, chunkNum: number, chunk: Buffer, p2: number, _acceptErrors?: any) {
  let payloadType = PAYLOAD_TYPE.ADD;
  if (chunkIdx === 1) {
    payloadType = PAYLOAD_TYPE.INIT;
  }
  if (chunkIdx === chunkNum) {
    payloadType = PAYLOAD_TYPE.LAST;
  }
  let transactionVersion = 0x00;
  if (p2 === 4) {
    transactionVersion = P2_VALUES.TX_VERSION_SAPLING;
  }
  if (p2 === 5) {
    transactionVersion = P2_VALUES.TX_VERSION_NU5;
  }
  if (version === INS.INIT_TX) {
    return app.transport.send(CLA, INS.INIT_TX, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80]).then((response: any) => {
      const errorCodeData = response.slice(-2);
      const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
      let errorMessage = errorCodeToString(returnCode);

      if (returnCode === 0x6a80 || returnCode === 0x6984 || returnCode === 0x6f10) {
        errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
      }

      let txdata = null;
      if (response.length > 2) {
        txdata = response.slice(0, 32); // fixme?
      }

      return {
        txdata,
        returnCode: returnCode,
        errorMessage: errorMessage,
      };
    }, processErrorResponse);
  }
  if (version === INS.CHECK_AND_SIGN) {
    return app.transport
      .send(CLA, INS.CHECK_AND_SIGN, payloadType, transactionVersion, chunk, [0x9000, 0x6984, 0x6a80])
      .then((response: any) => {
        const errorCodeData = response.slice(-2);
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
        let errorMessage = errorCodeToString(returnCode);

        if (returnCode === 0x6a80 || returnCode === 0x6984 || returnCode === 0x6f10) {
          errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
        }

        let signdata = null;
        if (response.length > 2) {
          signdata = response.slice(0, 32); // fixme?
        }

        return {
          signdata,
          returnCode: returnCode,
          errorMessage: errorMessage,
        };
      }, processErrorResponse);
  }
  return undefined;
}
