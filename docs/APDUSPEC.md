# Zcash App

>> We will soon move this document to Vuepress

We provide two APIs:

- Zondax API: New API that provides support for shielded and unshielded transactions
- Ledger Live Legacy API: Provides backwards compatible support for Ledger Live

## General Structure

The general structure of commands and responses is as follows:

| Field   | Type     | Content                | Note |
| :------ | :------- | :--------------------- | ---- |
| CLA     | byte (1) | Application Identifier | 0xE0 | # TODO: Confirm this value |
| INS     | byte (1) | Instruction ID         |      |
| P1      | byte (1) | Parameter 1            |      |
| P2      | byte (1) | Parameter 2            |      |
| L       | byte (1) | Bytes in payload       |      |
| PAYLOAD | byte (L) | Payload                |      |

#### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

#### Return codes

| Return code | Description             |
| ----------- | ----------------------- |
| 0x6400      | Execution Error         |
| 0x6982      | Empty buffer            |
| 0x6983      | Output buffer too small |
| 0x6986      | Command not allowed     |
| 0x6D00      | INS not supported       |
| 0x6E00      | CLA not supported       |
| 0x6F00      | Unknown                 |
| 0x9000      | Success                 |

## New API

### GET_VERSION

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0x85     |
| INS   | byte (1) | Instruction ID         | 0x00     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field   | Type     | Content          | Note                            |
| ------- | -------- | ---------------- | ------------------------------- |
| TEST    | byte (1) | Test Mode        | 0xFF means test mode is enabled |
| MAJOR   | byte (1) | Version Major    |                                 |
| MINOR   | byte (1) | Version Minor    |                                 |
| PATCH   | byte (1) | Version Patch    |                                 |
| LOCKED  | byte (1) | Device is locked |                                 |
| SW1-SW2 | byte (2) | Return code      | see list of return codes        |

### INS_GET_ADDR_SECP256K1

#### Command

| Field   | Type     | Content                   | Expected   |
| ------- | -------- | ------------------------- | ---------- |
| CLA     | byte (1) | Application Identifier    | 0x85       |
| INS     | byte (1) | Instruction ID            | 0x01       |
| P1      | byte (1) | Request User confirmation | No = 0     |
| P2      | byte (1) | Parameter 2               | ignored    |
| L       | byte (1) | Bytes in payload          | (depends)  |
| Path[0] | byte (4) | Derivation Path Data      | 0x8000002c |
| Path[1] | byte (4) | Derivation Path Data      | 0x80000085 |
| Path[2] | byte (4) | Derivation Path Data      | ?          |
| Path[3] | byte (4) | Derivation Path Data      | ?          |
| Path[4] | byte (4) | Derivation Path Data      | ?          |

#### Response

| Field          | Type      | Content              | Note                     |
| -------------- | --------- | -------------------- | ------------------------ |
| PK             | byte (65) | Public Key           |                          |
| ADDR_RAW_LEN   | byte (1)  | ADDR_RAW Length      |                          |
| ADDR_RAW       | byte (??) | Address as Raw Bytes |                          |
| ADDR_HUMAN_LEN | byte (1)  | ADDR_HUMAN Len       |                          |
| ADDR_HUMAN     | byte (??) | Address as String    |                          |
| SW1-SW2        | byte (2)  | Return code          | see list of return codes |

---

### INS_GET_ADDR_SAPLING

Returns or shows a shielded address (z-address)

#### Command

| Field   | Type     | Content                   | Expected   |
| ------- | -------- | ------------------------- | ---------- |
| CLA     | byte (1) | Application Identifier    | 0x85       |
| INS     | byte (1) | Instruction ID            | 0x11       |
| P1      | byte (1) | Request User confirmation | No = 0     |
| P2      | byte (1) | Parameter 2               | ignored    |
| L       | byte (1) | Bytes in payload          | (depends)  |
| Path[0] | byte (4) | Derivation Path Data      | 0x8000002c |
| Path[1] | byte (4) | Derivation Path Data      | 0x80000085 |
| Path[2] | byte (4) | Derivation Path Data      | ignored    |
| Path[3] | byte (4) | Derivation Path Data      | ignored          |
| Path[4] | byte (4) | Derivation Path Data      | ZIP32-path          |

#### Response

| Field          | Type      | Content           | Note                     |
| -------------- | --------- | ----------------- | ------------------------ |
| ADDR_RAW       | byte (43) | Raw address      |                          |
| ADDR_BECH32   | byte (variable)  | Bech32 encoding of address   |                          |                  |
| SW1-SW2        | byte (2)  | Return code       | see list of return codes |

---

### INS_GET_IVK_SAPLING

Returns a sapling incoming viewing key

#### Command

| Field   | Type     | Content                   | Expected   |
| ------- | -------- | ------------------------- | ---------- |
| CLA     | byte (1) | Application Identifier    | 0x85       |
| INS     | byte (1) | Instruction ID            | 0xf0       |
| P1      | byte (1) | Request User confirmation | No = 0     |
| P2      | byte (1) | Parameter 2               | ignored    |
| L       | byte (1) | Bytes in payload          | (depends)  |
| Path[0] | byte (4) | Derivation Path Data      | 0x8000002c |
| Path[1] | byte (4) | Derivation Path Data      | 0x80000085 |
| Path[2] | byte (4) | Derivation Path Data      | ignored    |
| Path[3] | byte (4) | Derivation Path Data      | ignored          |
| Path[4] | byte (4) | Derivation Path Data      | ZIP32-path          |

#### Response

| Field          | Type      | Content           | Note                     |
| -------------- | --------- | ----------------- | ------------------------ |
| IVK_RAW       | byte (32) | Raw IVK          |                          |                |                  |
| SW1-SW2        | byte (2)  | Return code       | see list of return codes |

---


### INS_GET_OVK_SAPLING

Returns a sapling outgoing viewing key

#### Command

| Field   | Type     | Content                   | Expected   |
| ------- | -------- | ------------------------- | ---------- |
| CLA     | byte (1) | Application Identifier    | 0x85       |
| INS     | byte (1) | Instruction ID            | 0xf4       |
| P1      | byte (1) | Request User confirmation | No = 0     |
| P2      | byte (1) | Parameter 2               | ignored    |
| L       | byte (1) | Bytes in payload          | (depends)  |
| Path[0] | byte (4) | Derivation Path Data      | 0x8000002c |
| Path[1] | byte (4) | Derivation Path Data      | 0x80000085 |
| Path[2] | byte (4) | Derivation Path Data      | ignored    |
| Path[3] | byte (4) | Derivation Path Data      | ignored          |
| Path[4] | byte (4) | Derivation Path Data      | ZIP32-path          |

#### Response

| Field          | Type      | Content           | Note                     |
| -------------- | --------- | ----------------- | ------------------------ |
| OVK_RAW       | byte (32) | Raw OVK          |                          |                |                  |
| SW1-SW2        | byte (2)  | Return code       | see list of return codes |

---

### INS_SIGN_SECP256K1

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0xE0      |
| INS   | byte (1) | Instruction ID         | 0x02      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks contain data chunks that are described below

_First Packet_

| Field   | Type     | Content              | Expected   |
| ------- | -------- | -------------------- | ---------- |
| Path[0] | byte (4) | Derivation Path Data | 0x8000002c |
| Path[1] | byte (4) | Derivation Path Data | 0x80000085 |
| Path[2] | byte (4) | Derivation Path Data | ?          |
| Path[3] | byte (4) | Derivation Path Data | ?          |
| Path[4] | byte (4) | Derivation Path Data | ?          |

_Other Chunks/Packets_

| Field | Type     | Content | Expected |
| ----- | -------- | ------- | -------- |
| Data  | bytes... | Message |          |

Data is defined as:

| Field   | Type    | Content      | Expected |
| ------- | ------- | ------------ | -------- |
| Message | bytes.. | Data to sign |          |

#### Response

| Field       | Type            | Content     | Note                     |
| ----------- | --------------- | ----------- | ------------------------ |
| secp256k1 R | byte (32)       | Signature   |                          |
| secp256k1 S | byte (32)       | Signature   |                          |
| secp256k1 V | byte (1)        | Signature   |                          |
| SIG         | byte (variable) | Signature   | DER format               |
| SW1-SW2     | byte (2)        | Return code | see list of return codes |

---

### INS_SIGN_SAPLING

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0xE0      |
| INS   | byte (1) | Instruction ID         | 0x12      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks contain data chunks that are described below

_First Packet_

| Field   | Type     | Content              | Expected   |
| ------- | -------- | -------------------- | ---------- |
| Path[0] | byte (4) | Derivation Path Data | 0x8000002c |
| Path[1] | byte (4) | Derivation Path Data | 0x80000085 |
| Path[2] | byte (4) | Derivation Path Data | ?          |
| Path[3] | byte (4) | Derivation Path Data | ?          |
| Path[4] | byte (4) | Derivation Path Data | ?          |

_Other Chunks/Packets_

| Field | Type     | Content | Expected |
| ----- | -------- | ------- | -------- |
| Data  | bytes... | Message |          |

Data is defined as:

| Field   | Type    | Content      | Expected |
| ------- | ------- | ------------ | -------- |
| Message | bytes.. | Data to sign |          |

#### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ??      | byte (?) | Signature   |                          |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

---

## Legacy API

> The legacy API should only be used by legacy applications that integrated with the older BTC-based Ledger app that only supported unshielded addresses

[Reference Legacy API](https://github.com/LedgerHQ/ledger-app-btc/blob/master/doc/btc.asc#wallet-usage-apdus)

### Get Wallet Public Key

> Check if necessary for Ledger Live backwards compatibility

#### Command

| Field | Type     | Content                | Expected                                                                                 |
| ----- | -------- | ---------------------- | ---------------------------------------------------------------------------------------- |
| CLA   | byte (1) | Application Identifier | 0xE0                                                                                     |
| INS   | byte (1) | Instruction ID         | 0x40                                                                                     |
| P1    | byte (1) | Parameter 1            | 0 = do not display address<br/> 1 = display address <br/> 2 = display validation token   |
| P2    | byte (1) | Parameter 2            | 0 = legacy address <br/> 1 = P2SH-P2WPKH address <br/> 2 = Bech32 encoded P2WPKH address |
| L     | byte (1) | Bytes in payload       | 0                                                                                        |

_Payload_

| Field     | Type     | Content               | Expected                                                |
| --------- | -------- | --------------------- | ------------------------------------------------------- |
| PATH_LEN  | byte (1) | Number of derivations | [1..10]                                                 |
| PATH[0]   | byte (4) | Derivation Path Data  | 0x8000002c                                              |
| ...       | ...      |                       |                                                         |
| PATH[N]   | byte (4) | Derivation Path Data  |                                                         |
| VAL_TOKEN | byte (4) | Derivation Path Data  | Optional <br/>hexadecimal validation token (big endian) |

#### Response

| Field       | Type      | Content                 | Note                     |
| ----------- | --------- | ----------------------- | ------------------------ |
| PUBKEY_LEN  | byte (1)  | Public key length       |                          |
| PUBKEY      | var       | Uncompressed Public key |                          |
| ADDRESS_LEN | byte (1)  | Version Minor           |                          |
| ADDRESS     | byte (1)  | Version Patch           |                          |
| LOCKED      | byte (1)  | Device is locked        |                          |
| CHAIN_CODE  | byte (32) | BIP32 chain code        |                          |
| SW1-SW2     | byte (2)  | Return code             | see list of return codes |

### Get Trusted Input

> Check if necessary for Ledger Live backwards compatibility

Extracts Trusted Input (encrypted transaction hash, output index, output amount) from a bitcoin transaction.
Scripts can be sent over several APDUs. (64 bits varints are rejected)

| Field | Type     | Content                | Expected                                       |
| ----- | -------- | ---------------------- | ---------------------------------------------- |
| CLA   | byte (1) | Application Identifier | 0xE0                                           |
| INS   | byte (1) | Instruction ID         | 0x42                                           |
| P1    | byte (1) | Parameter 1            | 0 = first tx block<br/> 0x80 = other tx blocks |
| P2    | byte (1) | Parameter 2            |                                                |
| L     | byte (1) | Bytes in payload       | 0                                              |

_Payload_(first block)

| Field       | Type     | Content                 | Expected |
| ----------- | -------- | ----------------------- | -------- |
| INPUT_INDEX | byte (4) | Input index - Bigendian |          |
| TX_CHUNK    | var      | transaction chunk       |          |

_Payload_(other blocks)

| Field    | Type | Content           | Expected |
| -------- | ---- | ----------------- | -------- |
| TX_CHUNK | var  | transaction chunk |          |

#### Response

| Field         | Type      | Content           | Note |
| ------------- | --------- | ----------------- | ---- |
| TRUSTED_INPUT | byte (56) | Public key length |      |

### Untrusted Hash Transaction Input Start

> Check if necessary for Ledger Live backwards compatibility

Based on [Reference Legacy API](https://github.com/LedgerHQ/ledger-app-btc/blob/master/doc/btc.asc#wallet-usage-apdus).

TO BE COMPLETED ONCE IT IS IMPLEMENTED IN THIS APP

### Untrusted Hash Sign

> Check if necessary for Ledger Live backwards compatibility

Based on [Reference Legacy API](https://github.com/LedgerHQ/ledger-app-btc/blob/master/doc/btc.asc#wallet-usage-apdus).

TO BE COMPLETED ONCE IT IS IMPLEMENTED IN THIS APP

### Untrusted Hash Transaction Input Finalize Full

> Check if necessary for Ledger Live backwards compatibility

Based on [Reference Legacy API](https://github.com/LedgerHQ/ledger-app-btc/blob/master/doc/btc.asc#wallet-usage-apdus).

TO BE COMPLETED ONCE IT IS IMPLEMENTED IN THIS APP

### Get Random

> This should be always available

Based on [Reference Legacy API](https://github.com/LedgerHQ/ledger-app-btc/blob/master/doc/btc.asc#wallet-usage-apdus).

TO BE COMPLETED ONCE IT IS IMPLEMENTED IN THIS APP

### Get Firmware Version

> This should be always available

Based on [Reference Legacy API](https://github.com/LedgerHQ/ledger-app-btc/blob/master/doc/btc.asc#wallet-usage-apdus).

TO BE COMPLETED ONCE IT IS IMPLEMENTED IN THIS APP

### Get Coin Version

> This should be always available

Based on [Reference Legacy API](https://github.com/LedgerHQ/ledger-app-btc/blob/master/doc/btc.asc#wallet-usage-apdus).

TO BE COMPLETED ONCE IT IS IMPLEMENTED IN THIS APP
