#include <inttypes.h>
#include <zxmacros.h>
#include <zxformat.h>
#include "os.h"
#include "constants.h"
#include "cx.h"
#include "nvdata.h"
#include "sighash.h"
#include "index_sapling.h"

// TxId transparent level 2 node personalization
#define ZCASH_PREVOUTS_HASH_PERSONALIZATION "ZTxIdPrevoutHash"
#define ZCASH_SEQUENCE_HASH_PERSONALIZATION "ZTxIdSequencHash"
#define ZCASH_OUTPUTS_HASH_PERSONALIZATION "ZTxIdOutputsHash"

// TxId sapling level 2 node personalization
#define ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION "ZTxIdSSpendsHash"
#define ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION "ZTxIdSSpendCHash"
#define ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION "ZTxIdSSpendNHash"

#define ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION "ZTxIdSOutputHash"
#define ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION "ZTxIdSOutC__Hash"
#define ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION "ZTxIdSOutM__Hash"
#define ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION "ZTxIdSOutN__Hash"


void hasher(cx_blake2b_t* ctx, const uint8_t *personal)
{
    cx_blake2b_init2(&ctx, 256, NULL, 0, (uint8_t *) personal, 16);
}

void nu5_transparent_prevouts_hash(const uint8_t *input, uint8_t *output) {
    const uint8_t n = t_inlist_len();
    cx_blake2b_t ctx;
    hasher(&ctx, (uint8_t *) ZCASH_PREVOUTS_HASH_PERSONALIZATION);

    if (n == 0) {
        cx_hash(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE);
        return;
    }

    const uint8_t *data = input + INDEX_TIN_PREVOUT;
    for (uint8_t i = 0; i < n - 1; i++, data += T_IN_TX_LEN) {
        cx_hash(&ctx.header, 0, data, PREVOUT_SIZE, NULL, 0);
    }
    cx_hash(&ctx.header, CX_LAST, data, PREVOUT_SIZE, output, HASH_SIZE);
}

void nu5_transparent_sequence_hash(const uint8_t *input, uint8_t *output) {
    const uint8_t n = t_inlist_len();

    cx_blake2b_t ctx;
    hasher(&ctx, (uint8_t *) ZCASH_SEQUENCE_HASH_PERSONALIZATION);

    if (n == 0) {
        cx_hash(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE);
        return;
    }

    const uint8_t *data = input + INDEX_TIN_SEQ;
    for (uint8_t i = 0; i < n - 1; i++, data += T_IN_TX_LEN) {
        cx_hash(&ctx.header, 0, data, SEQUENCE_SIZE, NULL, 0);
    }
    cx_hash(&ctx.header, CX_LAST, data, SEQUENCE_SIZE, output, HASH_SIZE);
}

/// Sequentially append the full serialized value of each transparent output
/// to a hash personalized by ZCASH_OUTPUTS_HASH_PERSONALIZATION.
/// In the case that no outputs are provided, this produces a default
/// hash from just the personalization string.
void nu5_transparent_outputs_hash(uint8_t *output) {
    const uint8_t n = t_outlist_len();

    cx_blake2b_t ctx;
    hasher(&ctx, (uint8_t *) ZCASH_OUTPUTS_HASH_PERSONALIZATION);

    if (n == 0) {
        cx_hash(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE);
        return;
    }

    uint8_t data[T_OUTPUT_SIZE];
    uint8_t i = 0;
    for (; i < n - 1; i++) {
        t_output_item_t *item = t_outlist_retrieve_item(i);
        MEMCPY(data, (uint8_t * ) & (item->value), 8);
        MEMCPY(data + 8, item->address, SCRIPT_SIZE);
        cx_hash(&ctx.header, 0, data, sizeof(data), NULL, 0);
    }
    t_output_item_t *item = t_outlist_retrieve_item(i);
    MEMCPY(data, (uint8_t * ) & (item->value), 8);
    MEMCPY(data + 8, item->address, SCRIPT_SIZE);
    cx_hash(&ctx.header, CX_LAST, data, sizeof(data), output, HASH_SIZE);
}


/// Implements [ZIP 244 section T.3a](https://zips.z.cash/zip-0244#t-3a-sapling-spends-digest)
///
/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * \[nullifier*\] - personalized with ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION
/// * \[(cv, anchor, rk, zkproof)*\] - personalized with ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
void nu5_hash_sapling_spends(uint8_t *input, uint8_t *output)
{
    const uint8_t n = spendlist_len();

    cx_blake2b_t ctx;
    hasher(&ctx, (uint8_t *) ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);

    if (n == 0) {
        cx_hash(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE);
        return;
    }
    cx_blake2b_t ch_ctx;
    hasher(&ch_ctx, (uint8_t *) ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION);

    cx_blake2b_t nh_ctx;
    hasher(&nh_ctx, (uint8_t *) ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION);

    const uint8_t *nullifier_data = input + INDEX_SPEND_NF;

    const uint8_t *cv_data = input + INDEX_SPEND_VALUECMT;
    const uint8_t *anchor_data = input + INDEX_SPEND_ANCHOR;
    const uint8_t *rk_data = input + INDEX_SPEND_RK;
    for (uint8_t i = 0; i < n - 1; i++,
            nullifier_data  += SPEND_TX_LEN,
            cv_data         += SPEND_TX_LEN,
            anchor_data     += SPEND_TX_LEN,
            rk_data         += SPEND_TX_LEN )
    {
        // build the hash of nullifiers separately for compact blocks.
        cx_hash(&ch_ctx.header, 0, nullifier_data, NULLIFIER_SIZE, NULL, 0);

        cx_hash(&nh_ctx.header, 0, cv_data, VALUE_COMMITMENT_SIZE, NULL, 0);
        cx_hash(&nh_ctx.header, 0, anchor_data, VALUE_COMMITMENT_SIZE, NULL, 0);
        cx_hash(&nh_ctx.header, 0, rk_data, RK_SIZE, NULL, 0);
    }

    const uint8_t *ch_out;
    cx_hash(&ch_ctx.header, CX_LAST, nullifier_data, NULLIFIER_SIZE, ch_out, HASH_SIZE);

    const uint8_t *nh_out;
    cx_hash(&nh_ctx.header, 0, cv_data, VALUE_COMMITMENT_SIZE, NULL, 0);
    cx_hash(&nh_ctx.header, 0, anchor_data, VALUE_COMMITMENT_SIZE, NULL, 0);
    cx_hash(&nh_ctx.header, CX_LAST, rk_data, RK_SIZE, nh_out, HASH_SIZE);

    cx_hash(&ctx.header, 0, ch_out, HASH_SIZE, NULL, 0);
    cx_hash(&ctx.header, CX_LAST, nh_out, HASH_SIZE, output, HASH_SIZE);
}

/// Implements [ZIP 244 section T.3b](https://zips.z.cash/zip-0244#t-3b-sapling-outputs-digest)
///
/// Write disjoint parts of each Sapling shielded output as 3 separate hashes:
/// * \[(cmu, epk, enc_ciphertext\[..52\])*\] personalized with ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized with ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION
/// * \[(cv, enc_ciphertext\[564..\], out_ciphertext, zkproof)*\] personalized with ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized with ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION
void nu5_hash_sapling_outputs(uint8_t *input, uint8_t *output){
    const uint8_t n = outputlist_len();

    cx_blake2b_t ctx;
    hasher(&ctx, (uint8_t *) ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION);

    if (n == 0) {
        cx_hash(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE);
        return;
    }

    cx_blake2b_t ch_ctx;
    hasher(&ch_ctx, (uint8_t *) ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION);

    cx_blake2b_t mh_ctx;
    hasher(&mh_ctx, (uint8_t *) ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION);

    cx_blake2b_t nh_ctx;
    hasher(&nh_ctx, (uint8_t *) ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION);

    const uint8_t *cmu  = input + INDEX_OUTPUT_NOTECMT;
    const uint8_t *ephemeral_key  = input + INDEX_OUTPUT_EPK;
    const uint8_t *enc_ciphertext  = input + INDEX_OUTPUT_ENC;


    const uint8_t *enc_ciphertext_memo  = input + INDEX_OUTPUT_ENC_MEMO;

    const uint8_t *cv  = input + INDEX_OUTPUT_VALUECMT;
    const uint8_t *enc_ciphertext_aead_tag  = input + INDEX_OUTPUT_ENC_AEAD_TAG;
    const uint8_t *out_ciphertext = input + INDEX_OUTPUT_OUT;

    for (uint8_t i = 0; i < n - 1; i++,
            cmu  += OUTPUT_TX_LEN,
            ephemeral_key += OUTPUT_TX_LEN,
            enc_ciphertext += OUTPUT_TX_LEN,
            enc_ciphertext_memo  += OUTPUT_TX_LEN)
    {
        cx_hash(&ch_ctx.header, 0, cmu , NOTE_COMMITMENT_SIZE, NULL, 0);
        cx_hash(&ch_ctx.header, 0, ephemeral_key , EPK_SIZE, NULL, 0);
        cx_hash(&ch_ctx.header, 0, enc_ciphertext , 52, NULL, 0);

        cx_hash(&mh_ctx.header, 0, enc_ciphertext_memo , OUTPUT_ENC_MEMO_SIZE, NULL, 0);

        cx_hash(&nh_ctx.header, 0, cv , VALUE_COMMITMENT_SIZE, NULL, 0);
        cx_hash(&nh_ctx.header, 0, enc_ciphertext_aead_tag , OUTPUT_ENC_AEAD_TAG_SIZE, NULL, 0);
        cx_hash(&nh_ctx.header, 0, out_ciphertext , OUTPUT_OUT_SIZE, NULL, 0);
    }

    const uint8_t *ch_out;
    cx_hash(&ch_ctx.header, 0, cmu , NOTE_COMMITMENT_SIZE, NULL, 0);
    cx_hash(&ch_ctx.header, 0, ephemeral_key , EPK_SIZE, NULL, 0);
    cx_hash(&ch_ctx.header, CX_LAST, enc_ciphertext , 52, ch_out, HASH_SIZE);

    const uint8_t *mh_out;
    cx_hash(&mh_ctx.header, CX_LAST, enc_ciphertext_memo , OUTPUT_ENC_MEMO_SIZE, mh_out, HASH_SIZE);

    const uint8_t *nh_out;
    cx_hash(&nh_ctx.header, 0, cv , VALUE_COMMITMENT_SIZE, NULL, 0);
    cx_hash(&nh_ctx.header, 0, enc_ciphertext_aead_tag , OUTPUT_ENC_AEAD_TAG_SIZE, NULL, 0);
    cx_hash(&nh_ctx.header, CX_LAST, out_ciphertext , OUTPUT_OUT_SIZE, nh_out, HASH_SIZE);

    cx_hash(&ctx.header, 0, ch_out, HASH_SIZE, NULL, 0);
    cx_hash(&ctx.header, 0, mh_out, HASH_SIZE, NULL, 0);
    cx_hash(&ctx.header, CX_LAST, nh_out, HASH_SIZE, output, HASH_SIZE);
}

/// The txid commits to the hash of all transparent outputs. The
/// prevout and sequence_hash components of txid

