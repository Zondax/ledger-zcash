import {CLA, errorCodeToString, INS, PAYLOAD_TYPE, processErrorResponse, SAPLING_ADDR_LEN} from "./common";

const HARDENED = 0x80000000;

export function serializePathv1(path) {
  if (typeof path !== "string") {
    throw new Error("Path should be a string (e.g \"m/44'/461'/5'/0/3\")");
  }

  if (!path.startsWith("m")) {
    throw new Error('Path should start with "m" (e.g "m/44\'/461\'/5\'/0/3")');
  }

  const pathArray = path.split("/");

  if (pathArray.length !== 6) {
    throw new Error("Invalid path. (e.g \"m/44'/461'/5'/0/3\")");
  }

  const buf = Buffer.alloc(20);

  for (let i = 1; i < pathArray.length; i += 1) {
    let value = 0;
    let child = pathArray[i];
    if (child.endsWith("'")) {
      value += HARDENED;
      child = child.slice(0, -1);
    }

    const childNumber = Number(child);

    if (Number.isNaN(childNumber)) {
      throw new Error(`Invalid path : ${child} is not a number. (e.g "m/44'/461'/5'/0/3")`);
    }

    if (childNumber >= HARDENED) {
      throw new Error("Incorrect child value (bigger or equal to 0x80000000)");
    }

    value += childNumber;

    buf.writeUInt32LE(value, 4 * (i - 1));
  }

  return buf;
}

export async function signSendChunkv1(app, chunkIdx, chunkNum, chunk) {
  let payloadType = PAYLOAD_TYPE.ADD;
  if (chunkIdx === 1) {
    payloadType = PAYLOAD_TYPE.INIT;
  }
  if (chunkIdx === chunkNum) {
    payloadType = PAYLOAD_TYPE.LAST;
  }
  return app.transport
    .send(CLA, INS.SIGN_SECP256K1, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80])
    .then((response) => {
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
        return_code: returnCode,
        error_message: errorMessage,
      };
    }, processErrorResponse);
}

export async function saplingSendChunkv1(app, version, chunkIdx, chunkNum, chunk) {
  let payloadType = PAYLOAD_TYPE.ADD;
  if (chunkIdx === 1) {
    payloadType = PAYLOAD_TYPE.INIT;
  }
  if (chunkIdx === chunkNum) {
    payloadType = PAYLOAD_TYPE.LAST;
  }
  if (version === INS.INIT_TX){
      return app.transport
          .send(CLA, INS.INIT_TX, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80])
          .then((response) => {
              const errorCodeData = response.slice(-2);
              const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
              let errorMessage = errorCodeToString(returnCode);

              if (returnCode === 0x6a80 || returnCode === 0x6984 || returnCode === 0x6f10) {
                  errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
              }

              let txdata = null;
              if (response.length > 2) {
                  txdata = response.slice(0, 32); //fixme?
              }

              return {
                  txdata: txdata,
                  return_code: returnCode,
                  error_message: errorMessage,
              };
          }, processErrorResponse);
  }else if (version === INS.CHECKANDSIGN){
    return app.transport
        .send(CLA, INS.CHECKANDSIGN, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80])
        .then((response) => {
            const errorCodeData = response.slice(-2);
            const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
            let errorMessage = errorCodeToString(returnCode);

            if (returnCode === 0x6a80 || returnCode === 0x6984 || returnCode === 0x6f10) {
                errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
            }

            let signdata = null;
            if (response.length > 2) {
                signdata = response.slice(0, 32); //fixme?
            }

            return {
                signdata: signdata,
                return_code: returnCode,
                error_message: errorMessage,
            };
        }, processErrorResponse);
    }else if (version === INS.GET_ADDR_SAPLING_DIV){
      return app.transport
          .send(CLA, INS.GET_ADDR_SAPLING_DIV, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80])
          .then((response) => {
              const errorCodeData = response.slice(-2);
              const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
              let errorMessage = errorCodeToString(returnCode);

              if (returnCode === 0x6a80 || returnCode === 0x6984 || returnCode === 0x6f10) {
                  errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
              }

              let addressRaw = null;
              let address = null;
              if (response.length > 2) {
                  addressRaw = response.slice(0, SAPLING_ADDR_LEN);
                  address = response.slice(SAPLING_ADDR_LEN, -2);
              }

              return {
                  address_raw: addressRaw,
                  address: address,
                  return_code: returnCode,
                  error_message: errorMessage,
              };
          }, processErrorResponse);
  }
  else if (version === INS.GET_DIV_LIST){
      return app.transport
          .send(CLA, INS.GET_DIV_LIST, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80])
          .then((response) => {
              const errorCodeData = response.slice(-2);
              const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
              let errorMessage = errorCodeToString(returnCode);

              if (returnCode === 0x6a80 || returnCode === 0x6984 || returnCode === 0x6f10) {
                  errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
              }

              let divlist = [];
              if (response.length > 2) {
                  var i;
                  var div;
                  for (i = 0; i < 20; i++) {
                      div = response.slice(i * 11, (i + 1) * 11).toString('hex');
                      if (div != "0000000000000000000000") {
                          divlist.push(div);
                      }
                  }
              }

              return {
                  divlist: divlist,
                  return_code: returnCode,
                  error_message: errorMessage,
              };
          }, processErrorResponse);
  }else if (version === INS.KEY_EXCHANGE){
      return app.transport
          .send(CLA, INS.KEY_EXCHANGE, payloadType, 0, chunk, [0x9000, 0x6984, 0x6a80])
          .then((response) => {
              const errorCodeData = response.slice(-2);
              const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
              let errorMessage = errorCodeToString(returnCode);

              if (returnCode === 0x6a80 || returnCode === 0x6984 || returnCode === 0x6f10) {
                  errorMessage = `${errorMessage} : ${response.slice(0, response.length - 2).toString("ascii")}`;
              }

              var pubkey = null
              if (response.length > 2) {
                  pubkey = response.slice(0,32);
              }

              return {
                  pubkey: pubkey,
                  return_code: returnCode,
                  error_message: errorMessage,
              };
          }, processErrorResponse);
  }
}
