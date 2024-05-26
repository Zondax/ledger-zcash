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

export type DiversifierListResponse = {
  diversifiers: Buffer[]
}

export type NullifierResponse = {
  nfRaw: Buffer
}

export type InitTxResponse = {
  txdata: Buffer
}

export type SpendSignatureResponse = {
  signatureRaw: string
}

export type TransaparentSignatureResponse = {
  signatureRaw: string
}

export type OutputDataResponse = {
  rcvRaw: string
  rseedRaw: string
  hashSeedRaw: string
}

export type ExtractSpendResponse = {
  keyRaw: string
  rcvRaw: string
  alphaRaw: string
}

export type SignResponse = {
  signdata: Buffer
}
