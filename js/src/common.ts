export const CLA = 0x85;
export const CHUNK_SIZE = 250;

export const INS = {
  GET_VERSION: 0x00,

  GET_ADDR_SECP256K1: 0x01,
  SIGN_SECP256K1: 0x02,
  SIGN_SAPLING: 0x12,

  GET_DIV_LIST: 0x09,
  GET_ADDR_SAPLING_DIV: 0x10,
  GET_ADDR_SAPLING: 0x11,
  GET_IVK_SAPLING: 0xf0,
  GET_OVK_SAPLING: 0xf1,
  GET_NF_SAPLING: 0xf2,
  GET_FVK_SAPLING: 0xf3,

  INIT_TX: 0xa0,
  KEY_EXCHANGE: 0xaa,
  EXTRACT_SPEND_DATA: 0xa1,
  EXTRACT_OUTPUT_DATA: 0xa2,
  CHECK_AND_SIGN: 0xa3,
  EXTRACT_SPEND_SIGNATURE: 0xa4,
  EXTRACT_TRANS_SIGNATURE: 0xa5,
};


export const P1_VALUES = {
  ONLY_RETRIEVE: 0x00,
  SHOW_ADDRESS_IN_DEVICE: 0x01,
};

export const P2_VALUES = {
  TX_VERSION_SAPLING: 0x04,
  TX_VERSION_NU5: 0x05,
};

export const ERROR_CODE = {
  NoError: 0x9000,
};

export const PKLEN = 33;
export const SAPLING_ADDR_LEN = 43;
export const SAPLING_DIV_LEN = 11;
export const SAPLING_IVK_LEN = 32;
export const SAPLING_OVK_LEN = 32;
export const SAPLING_NF_LEN = 32;
export const SAPLING_AK_LEN = 32;
export const SAPLING_NK_LEN = 32;
export const SAPLING_PGK_LEN = 64;
export const SAPLING_SPENDDATA_LEN = 128;
export const SAPLING_OUTPUTDATA_LEN = 96;
export const SAPLING_RND_LEN = 192; // fixme
export const SAPLING_SIGN_LEN = 64;
