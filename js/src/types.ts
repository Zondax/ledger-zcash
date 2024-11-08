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

export type AddressResponse = {
  address: string
  addressRaw: Buffer
}

export type IvkResponse = {
  ivkRaw: Buffer
  defaultDiversifier: Buffer
}

export type OvkResponse = {
  ovkRaw: Buffer
}

export type FvkResponse = {
  akRaw: Buffer
  nkRaw: Buffer
  ovkRaw: Buffer
}

export type DfvkResponse = {
  akRaw: Buffer
  nkRaw: Buffer
  ovkRaw: Buffer
  dkRaw: Buffer
}

export type UfvkResponse = {
  sapling: {
    akRaw: Buffer
    nkRaw: Buffer
    ovkRaw: Buffer
    dkRaw: Buffer
  },
  transparent: {
    pkRaw: Buffer
  },
  orchard: {} | null
}

export type DiversifierListResponse = {
  diversifiers: Buffer[]
}

export type NullifierResponse = {
  nfRaw: Buffer
}

export type InitTxResponse = {
  txdataRaw: Buffer
  txdata: string
}

export type SpendSignatureResponse = {
  signatureRaw: Buffer
  signature: string
}

export type TransaparentSignatureResponse = {
  signatureRaw: Buffer
  signature: string
}

export type OutputDataResponse = {
  rcvRaw: Buffer
  rseedRaw: Buffer
  rcv: string
  rseed: string

  hashSeedRaw?: Buffer
  hashSeed?: string
}

export type ExtractSpendResponse = {
  keyRaw: Buffer
  rcvRaw: Buffer
  alphaRaw: Buffer

  key: string
  rcv: string
  alpha: string
}

export type SignResponse = {
  signdataRaw: Buffer
  signdata: string
}
