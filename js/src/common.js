export const CLA = 0x85;
export const CHUNK_SIZE = 250;
export const APP_KEY = "ZCH";

export const INS = {
  GET_VERSION: 0x00,

  GET_ADDR_SECP256K1: 0x01,
  SIGN_SECP256K1: 0x02,
  GET_DIV_LIST: 0x09,
  GET_ADDR_SAPLING_DIV: 0x10,
  GET_ADDR_SAPLING: 0x11,
  SIGN_SAPLING: 0x12,
  GET_IVK_SAPLING: 0xf0,
  GET_OVK_SAPLING: 0xf1,

  INIT_TX: 0xa0,
  KEY_EXCHANGE: 0xaa,
  EXTRACT_SPEND_DATA: 0xa1,
  EXTRACT_OUTPUT_DATA: 0xa2,
  CHECKANDSIGN: 0xa3,
  EXTRACTSPENDSIG: 0xa4,
  EXTRACTTRANSSIG: 0xa5,
};

export const PAYLOAD_TYPE = {
  INIT: 0x00,
  ADD: 0x01,
  LAST: 0x02,
};

export const P1_VALUES = {
  ONLY_RETRIEVE: 0x00,
  SHOW_ADDRESS_IN_DEVICE: 0x01,
};

export const ERROR_CODE = {
  NoError: 0x9000,
};

export const PKLEN = 33;
export const SAPLING_ADDR_LEN = 43;
export const SAPLING_IVK_LEN = 32;
export const SAPLING_OVK_LEN = 32;
export const SAPLING_PGK_LEN = 64;
export const SAPLING_SPENDDATA_LEN = 128;
export const SAPLING_OUTPUTDATA_LEN = 96;
export const SAPLING_RND_LEN = 192;//fixme
export const SAPLING_SIGN_LEN = 64;

const ERROR_DESCRIPTION = {
  1: "U2F: Unknown",
  2: "U2F: Bad request",
  3: "U2F: Configuration unsupported",
  4: "U2F: Device Ineligible",
  5: "U2F: Timeout",
  14: "Timeout",
  0x9000: "No errors",
  0x9001: "Device is busy",
  0x6802: "Error deriving keys",
  0x6400: "Execution Error",
  0x6700: "Wrong Length",
  0x6982: "Empty Buffer",
  0x6983: "Output buffer too small",
  0x6984: "Data is invalid",
  0x6985: "Conditions not satisfied",
  0x6986: "Transaction rejected",
  0x6988: "Data too long",
  0x6989: "Failed to extract transaction",
  0x6990: "Failed to hash message buffer",
  0x6991: "Transaction extraction incomplete",
  0x6992: "Prevout check failed",
  0x6993: "Sequence check failed",
  0x6994: "Hash of outputs check failed",
  0x6995: "Joinsplit check failed",
  0x6996: "Spend check failed",
  0x6997: "Outputs content check failed",
  0x6998: "Check of encryption failed",
  0x6999: "Check/sign transparent failed",
  0x69a0: "Failed to sign spends",
  0x6a80: "Bad key handle",
  0x6b00: "Invalid P1/P2",
  0x6d00: "Instruction not supported",
  0x6e00: "App does not seem to be open",
  0x6f00: "Unknown error",
  0x6f01: "Sign/verify error",
  0x6f10: "check spends error",
  0x6fa0: "wrong order of ledger instructions sapling",
  0x6fa1: "more spendinfo to be extracted",
  0x6fa2: "more outputinfo to be extracted",
  0x6fb1: "already extracted all spendinfo",
  0x6fb2: "already extracted all outputinfo",
  0x6fc1: "check spends error: data not correct",
  0x6fc2: "check output error: data not correct",
  0x6fff: "this operation is not supported",
};

export function errorCodeToString(statusCode) {
  if (statusCode in ERROR_DESCRIPTION) return ERROR_DESCRIPTION[statusCode];
  return `Unknown Status Code: ${statusCode}`;
}

function isDict(v) {
  return typeof v === "object" && v !== null && !(v instanceof Array) && !(v instanceof Date);
}

export function processErrorResponse(response) {
  if (response) {
    if (isDict(response)) {
      if (Object.prototype.hasOwnProperty.call(response, "statusCode")) {
        return {
          return_code: response.statusCode,
          error_message: errorCodeToString(response.statusCode),
        };
      }

      if (
        Object.prototype.hasOwnProperty.call(response, "return_code") &&
        Object.prototype.hasOwnProperty.call(response, "error_message")
      ) {
        return response;
      }
    }
    return {
      return_code: 0xffff,
      error_message: response.toString(),
    };
  }

  return {
    return_code: 0xffff,
    error_message: response.toString(),
  };
}

export async function getVersion(transport) {
  return transport.send(CLA, INS.GET_VERSION, 0, 0).then(response => {
    const errorCodeData = response.slice(-2);
    const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

    let targetId = 0;
    if (response.length >= 9) {
      /* eslint-disable no-bitwise */
      targetId = (response[5] << 24) + (response[6] << 16) + (response[7] << 8) + (response[8] << 0);
      /* eslint-enable no-bitwise */
    }

    return {
      return_code: returnCode,
      error_message: errorCodeToString(returnCode),
      // ///
      test_mode: response[0] !== 0,
      major: response[1],
      minor: response[2],
      patch: response[3],
      device_locked: response[4] === 1,
      target_id: targetId.toString(16),
    };
  }, processErrorResponse);
}
