# Zcash App

- Zondax API: New API that provides support for shielded and unshielded transactions

## General Structure

The general structure of commands and responses is as follows:

| Field   | Type     | Content                | Note |
| ------  | -------  | ---------------------  |------|
| CLA     | byte (1) | Application Identifier | 0x85 |
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

Returns or shows a shielded address with default diversifier (z-address)

#### Command

| Field   | Type     | Content                   | Expected   |
| ------- | -------- | ------------------------- | ---------- |
| CLA     | byte (1) | Application Identifier    | 0x85       |
| INS     | byte (1) | Instruction ID            | 0x11       |
| P1      | byte (1) | Request User confirmation | No = 0     |
| P2      | byte (1) | Parameter 2               | ignored    |
| L       | byte (1) | Bytes in payload          | (depends)  |
| ZIP32-path | byte (4) | Derivation Path Data      | u32 Little-Endian |

#### Response

| Field       | Type            | Content                    | Note                     |
| ----------- | --------------- | -------------------------- | ------------------------ |
| ADDR_RAW    | byte (43)       | Raw address                |                          |
| ADDR_BECH32 | byte (variable) | Bech32 encoding of address |                          |
| SW1-SW2     | byte (2)        | Return code                | see list of return codes |

---

### INS_GET_ADDR_SAPLING_DIV

Returns a shielded address using a specific diversifier

#### Command

| Field   | Type     | Content                   | Expected   |
| ------- | -------- | ------------------------- | ---------- |
| CLA     | byte (1) | Application Identifier    | 0x85       |
| INS     | byte (1) | Instruction ID            | 0x10       |
| P1      | byte (1) | Request User confirmation | No = 0     |
| P2      | byte (1) | Parameter 2               | ignored    |
| L       | byte (1) | Bytes in payload          | (depends)  |
| ZIP32-path | byte (4) | Derivation Path Data      | u32 Little-Endian |
| DIV | byte (11) | Diversifier     | 11-bytes  |

#### Response

| Field       | Type            | Content                    | Note                     |
| ----------- | --------------- | -------------------------- | ------------------------ |
| ADDR_RAW    | byte (43)       | Raw address                |                          |
| ADDR_BECH32 | byte (variable) | Bech32 encoding of address |                          |
| SW1-SW2     | byte (2)        | Return code                | see list of return codes |

---

### INS_GET_DIV_LIST

On input of a 11-byte starting index, get all valid diversifiers in the 20 indexes after (including starting index). If
a diversifier was not valid, zero-bytes are returned (so always 220 bytes are returned).

#### Command

| Field   | Type     | Content                   | Expected   |
| ------- | -------- | ------------------------- | ---------- |
| CLA     | byte (1) | Application Identifier    | 0x85       |
| INS     | byte (1) | Instruction ID            | 0x09       |
| P1      | byte (1) | Request User confirmation | ignored (no)    |
| P2      | byte (1) | Parameter 2               | ignored    |
| L       | byte (1) | Bytes in payload          | (depends)  |
| ZIP32-path | byte (4) | Derivation Path Data      | u32 Little-Endian |
| DIV | byte (11) | Starting index search     | 11-bytes  |

#### Response

| Field        | Type       | Content                  | Note                     |
| ------------ | ---------- | ------------------------ | ------------------------ |
| DIV_LIST_RAW | byte (220) | List of raw diversifiers | 11-bytes each            |
| SW1-SW2      | byte (2)   | Return code              | see list of return codes |

---

### INS_GET_IVK_SAPLING

Returns a sapling incoming viewing key. Forced user confirmation (So P1 needs to be 0x01).

#### Command

| Field   | Type     | Content                   | Expected   |
| ------- | -------- | ------------------------- | ---------- |
| CLA     | byte (1) | Application Identifier    | 0x85       |
| INS     | byte (1) | Instruction ID            | 0xf0       |
| P1      | byte (1) | Request User confirmation | 1  |
| P2      | byte (1) | Parameter 2               | ignored    |
| L       | byte (1) | Bytes in payload          | (depends)  |
| ZIP32-path | byte (4) | Derivation Path Data      | u32 Little-Endian |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| IVK_RAW | byte (32) | Raw IVK     |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### INS_GET_OVK_SAPLING

Returns a sapling outgoing viewing key. Forced user confirmation (So P1 needs to be 0x01).

#### Command

| Field   | Type     | Content                   | Expected   |
| ------- | -------- | ------------------------- | ---------- |
| CLA     | byte (1) | Application Identifier    | 0x85       |
| INS     | byte (1) | Instruction ID            | 0xf1     |
| P1      | byte (1) | Request User confirmation | 1 |
| P2      | byte (1) | Parameter 2               | ignored    |
| L       | byte (1) | Bytes in payload          | (depends)  |
| ZIP32-path | byte (4) | Derivation Path Data      | u32 Little-Endian |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| OVK_RAW | byte (32) | Raw OVK     |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### INS_GET_NF_SAPLING

Returns a sapling nullifier. TODO: Forced user confirmation (So P1 needs to be 0x01).

#### Command

| Field      | Type     | Content                    | Expected          |
|------------| -------- |----------------------------|-------------------|
| CLA        | byte (1) | Application Identifier     | 0x85              |
| INS        | byte (1) | Instruction ID             | 0xf2              |
| P1         | byte (1) | Request User confirmation  | 1                 |
| P2         | byte (1) | Parameter 2                | ignored           |
| L          | byte (1) | Bytes in payload           | (depends)         |
| ZIP32-path | byte (4) | Derivation Path Data       | u32 Little-Endian |
| POSITION   | byte (8) | Note position              | uint64            |
| CM         | byte(32) | Note commitment Data       | 32-bytes          |

#### Response

| Field   | Type      | Content     | Note                     |
|---------| --------- |-------------| ------------------------ |
| NF_RAW  | byte (32) | Raw NF      |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

---

### INS_INIT_TX_SAPLING

Initiates a transaction for sapling. The init_message should have the following format:

| Type            | Content                                  | Expected              |
| --------------- | ---------------------------------------- | --------------------- |
| byte (1)        | t_in_len: number of transparent inputs   | 0x00 - 0x05           |
| byte (1)        | t_out_len: number of transparent outputs | 0x00 - 0x05           |
| byte (1)        | s_in_len: number of shielded spends      | 0x00 - 0x05           |
| byte (1)        | s_out_len: number of shielded outputs    | 0x00 - 0x05           |
| byte (variable) | transparent input data = [t_in]          | t_in_len \* 54 bytes  |
| byte (variable) | transparent output data = [t_out]        | t_out_len \* 34 bytes |
| byte (variable) | shielded spend data = [s_spend]          | s_in_len \* 55 bytes  |
| byte (variable) | shielded output data = [s_out]           | s_out_len \* 84 bytes |

where

t_in :

| Type      | Content                     | Expected        |
| --------- | --------------------------- | --------------- |
| byte (20) | Derivation path data        | 5 times 4 bytes |
| byte (26) | Script of transparent input |                 |
| byte (8)  | transparent input value     | u64             |

t_out :

| Type      | Content                      | Expected |
| --------- | ---------------------------- | -------- |
| byte (26) | Script of transparent output |          |
| byte (8)  | transparent output value     | u64      |

s_spend:

| Type      | Content                    | Expected |
| --------- | -------------------------- | -------- |
| byte (4)  | ZIP32-path (hardened only) | u32      |
| byte (43) | Shielded spend address     |          |
| byte (8)  | Shielded spend value       | u64      |

s_output:

| Type      | Content                   | Expected                  |
| --------- | ------------------------- | ------------------------- |
| byte (43) | Shielded output address   |                           |
| byte (8)  | Shielded output value     | u64                       |
| byte (1)  | Shielded output memo type | 0xf6 for default memo     |
| byte (32) | Shielded output OVK       | 32 zero-bytes for non-OVK |

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0xE0      |
| INS   | byte (1) | Instruction ID         | 0xa0      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks contain data chunks that are described below

_First Packet_

| Field   | Type     | Content              | Expected |
| ------- | -------- | -------------------- | -------- |

_Other Chunks/Packets_

| Field | Type     | Content | Expected |
| ----- | -------- | ------- | -------- |
| Data  | bytes... | Message |          |

Data is defined as:

| Field   | Type    | Content                             | Expected |
| ------- | ------- | ----------------------------------- | -------- |
| Message | bytes.. | init_message bytes as defined above |          |

#### Response

| Field   | Type      | Content              | Note                     |
| ------- | --------- | -------------------- | ------------------------ |
| hash    | byte (32) | Hash of init_message | SHA256-hash              |
| SW1-SW2 | byte (2)  | Return code          | see list of return codes |

---

### INS_GET_SPENDINFO

Returns a proof generating key (PGK) and randomness (rcv and alpha) for a sapling spend.

- This command requires you already called the INS_INIT_TX_SAPLING.
- This command requires that it is needed to extract spendinfo.

#### Command

| Field   | Type     | Content                   | Expected  |
| ------- | -------- | ------------------------- | --------- |
| CLA     | byte (1) | Application Identifier    | 0x85      |
| INS     | byte (1) | Instruction ID            | 0xa1      |
| P1      | byte (1) | Request User confirmation | No = 0    |
| P2      | byte (1) | Parameter 2               | ignored   |
| L       | byte (1) | Bytes in payload          | 0 (empty) |

#### Response

| Field     | Type      | Content     | Note                                |
| --------- | --------- | ----------- | ----------------------------------- |
| PGK_RAW   | byte (64) | Raw PGK     | 32 byte representations for ak, nsk |
| rcv_RAW   | byte (32) | Raw rcv     |                                     |
| alpha_RAW | byte (32) | Raw alpha   |                                     |
| SW1-SW2   | byte (2)  | Return code | see list of return codes            |

---

### INS_GET_OUTPUTINFO

Returns randomness (rcv and rseed (after ZIP202) and optional Hash_Seed) for a sapling output.

- This command requires you already called the INS_INIT_TX_SAPLING.
- This command requires you already called the correct number of INS_GET_SPENDINFO.
- This command requires that it is needed to extract outputinfo.

#### Command

| Field   | Type     | Content                   | Expected  |
| ------- | -------- | ------------------------- | --------- |
| CLA     | byte (1) | Application Identifier    | 0x85      |
| INS     | byte (1) | Instruction ID            | 0xa2      |
| P1      | byte (1) | Request User confirmation | No = 0    |
| P2      | byte (1) | Parameter 2               | ignored   |
| L       | byte (1) | Bytes in payload          | 0 (empty) |

#### Response

| Field     | Type      | Content     | Note                     |
| --------- | --------- | ----------- | ------------------------ |
| rcv_RAW   | byte (32) | Raw rcv     |                          |
| rseed_RAW | byte (32) | Raw rseed   |                          |
| hash_seed | byte (32) | Raw hash_seed| Only returned if OVK=None for this output |
| SW1-SW2   | byte (2)  | Return code | see list of return codes |

---

### INS_CHECKANDSIGN_TX_SAPLING

Checks the transaction data and signs if it is correct with the corresponding keys.

- This command requires you already called the INS_INIT_TX_SAPLING.
- This command requires you already called the correct number of INS_GET_SPENDINFO.
- This command requires you already called the correct number of INS_GET_OUTPUTINFO.

The transaction_blob should have the following format:

| Type            | Content                       | Expected               |
| --------------- | ----------------------------- | ---------------------- |
| byte (variable) | transparent data to check     | t_in_len \* 74 bytes   |
| byte (variable) | previous spend data to check  | s_in_len\* 40 bytes    |
| byte (variable) | new spend data to check       | s_in_len \* 320 bytes  |
| byte (variable) | shielded output data to check | s_out_len \* 948 bytes |

where

transparent data to check :
(Some of the below data is already sent in the inittx command, but sending it again is easier for checking purposes)

| Type      | Content         | Expected |
| --------- | --------------- | -------- |
| byte (36) | Prevout point   |          |
| byte (26) | Script          |          |
| byte (8)  | Value           | u64      |
| byte (4)  | Sequence number |          |

previous spend data to check :

| Type      | Content                     | Expected |
| --------- | --------------------------- | -------- |
| byte (32) | Rseed of the spent note     |          |
| byte (8)  | Note position of spent note | u64      |

new spend data to check:
NOTE: the values below should have used randomness from INS_GET_SPENDINFO if applicable

| Type       | Content   | Expected                                          |
| ---------- | --------- | ------------------------------------------------- |
| byte (32)  | spend cv  | should have used rcv from ledger                  |
| byte (32)  | Anchor    |                                                   |
| byte (32)  | Nullifier | should have used old note Rseed and note position |
| byte (32)  | Rk        | should have used alpha from ledger                |
| byte (192) | zkproof   |                                                   |

shielded output data to check:

| Type       | Content         | Expected                            |
| ---------- | --------------- | ----------------------------------- |
| byte (32)  | output cv       | should have used rcv from ledger    |
| byte (32)  | note commitment | should have used rseed from ledger  |
| byte (32)  | ephemeral key   | should have used rseed from ledger  |
| byte (580) | enc_ciphertext  | ledger checks correct memo-type too |
| byte (80)  | out_ciphertext  |                                     |
| byte (192) | zkproof         |                                     |

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0xE0      |
| INS   | byte (1) | Instruction ID         | 0xa3      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | not used  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

All other packets/chunks contain data chunks that are described below

_First Packet_

| Field   | Type     | Content              | Expected |
| ------- | -------- | -------------------- | -------- |

_Other Chunks/Packets_

| Field | Type     | Content | Expected |
| ----- | -------- | ------- | -------- |
| Data  | bytes... | Message |          |

Data is defined as:

| Field   | Type    | Content                                 | Expected |
| ------- | ------- | --------------------------------------- | -------- |
| Message | bytes.. | transaction_blob bytes as defined above |          |

#### Response

| Field   | Type      | Content                  | Note                     |
| ------- | --------- | ------------------------ | ------------------------ |
| hash    | byte (32) | Hash of transaction_blob | SHA256                   |
| SW1-SW2 | byte (2)  | Return code              | see list of return codes |

---

### INS_GET_TRANSPARENT_SIGNATURE

Returns a SECP256K1 signature for a sapling transparent input.

- This command requires that you already called INS_CHECKANDSIGN_SAPLING.

It gives the signatures in order of the transaction.
Returns error if all signatures are retrieved.

#### Command

| Field   | Type     | Content                   | Expected  |
| ------- | -------- | ------------------------- | --------- |
| CLA     | byte (1) | Application Identifier    | 0x85      |
| INS     | byte (1) | Instruction ID            | 0xa5      |
| P1      | byte (1) | Request User confirmation | No = 0    |
| P2      | byte (1) | Parameter 2               | ignored   |
| L       | byte (1) | Bytes in payload          | 0 (empty) |

#### Response

| Field     | Type      | Content       | Note                     |
| --------- | --------- | ------------- | ------------------------ |
| SECP256K1 | byte (64) | R/S signature |                          |
| SW1-SW2   | byte (2)  | Return code   | see list of return codes |

---

### INS_GET_SPEND_SIGNATURE

Returns a spend signature for a sapling shielded spend input.

- This command requires that you already called INS_CHECKANDSIGN_SAPLING.

#### Command

| Field   | Type     | Content                   | Expected  |
| ------- | -------- | ------------------------- | --------- |
| CLA     | byte (1) | Application Identifier    | 0x85      |
| INS     | byte (1) | Instruction ID            | 0xa4      |
| P1      | byte (1) | Request User confirmation | No = 0    |
| P2      | byte (1) | Parameter 2               | ignored   |
| L       | byte (1) | Bytes in payload          | 0 (empty) |

#### Response

| Field               | Type      | Content       | Note                     |
| ------------------- | --------- | ------------- | ------------------------ |
| RedJubjub signature | byte (64) | R/S signature |                          |
| SW1-SW2             | byte (2)  | Return code   | see list of return codes |

---

### INS_SIGN_SECP256K1

**THIS COMMAND HAS BEEN DEPRECATED**

---

### INS_SIGN_SAPLING

**THIS COMMAND HAS BEEN DEPRECATED**
