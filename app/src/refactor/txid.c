#include <inttypes.h>
#include <zxformat.h>
#include <zxmacros.h>

#include "constants.h"
#include "cx.h"
#include "index_sapling.h"
#include "nvdata.h"
#include "os.h"
#include "sighash.h"
#include "zxerror.h"

#define PERSONALIZATION_SIZE 16

// TxId level 1 node personalization
#define ZCASH_HEADERS_HASH_PERSONALIZATION     "ZTxIdHeadersHash"
#define ZCASH_TRANSPARENT_HASH_PERSONALIZATION "ZTxIdTranspaHash"
#define ZCASH_SAPLING_HASH_PERSONALIZATION     "ZTxIdSaplingHash"
#define ZCASH_ORCHARD_HASH_PERSONALIZATION     "ZTxIdOrchardHash"

// TxId transparent level 2 node personalization
#define ZCASH_PREVOUTS_HASH_PERSONALIZATION "ZTxIdPrevoutHash"
#define ZCASH_SEQUENCE_HASH_PERSONALIZATION "ZTxIdSequencHash"
#define ZCASH_OUTPUTS_HASH_PERSONALIZATION  "ZTxIdOutputsHash"

// TxId sapling level 2 node personalization
#define ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION             "ZTxIdSSpendsHash"
#define ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION     "ZTxIdSSpendCHash"
#define ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION  "ZTxIdSSpendNHash"

#define ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION            "ZTxIdSOutputHash"
#define ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION    "ZTxIdSOutC__Hash"
#define ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION      "ZTxIdSOutM__Hash"
#define ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION "ZTxIdSOutN__Hash"

#define ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION          "Zcash___TxInHash"
#define ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION        "ZTxTrAmountsHash"
#define ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION        "ZTxTrScriptsHash"

#define SIGHASH_ALL                                           0x01

zxerr_t nu5_transparent_prevouts_hash(const uint8_t *input, uint8_t *output) {
    zemu_log_stack("nu5_transparent_prevouts_hash\n");
    if (input == NULL || output == NULL) {
        return zxerr_no_data;
    }

    const uint8_t n = t_inlist_len();
    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(
        cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_PREVOUTS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    if (n == 0) {
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }

    const uint8_t *data = input + INDEX_TIN_PREVOUT;
    for (uint8_t i = 0; i < n - 1; i++, data += T_IN_TX_LEN) {
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, data, PREVOUT_SIZE, NULL, 0));
        io_seproxyhal_io_heartbeat();
    }
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, data, PREVOUT_SIZE, output, HASH_SIZE));
    return zxerr_ok;
}

zxerr_t nu5_transparent_sequence_hash(const uint8_t *input, uint8_t *output) {
    zemu_log_stack("nu5_transparent_sequence_hash");
    if (input == NULL || output == NULL) {
        return zxerr_no_data;
    }
    const uint8_t n = t_inlist_len();

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(
        cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_SEQUENCE_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    if (n == 0) {
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }

    const uint8_t *data = input + INDEX_TIN_SEQ;
    for (uint8_t i = 0; i < n - 1; i++, data += T_IN_TX_LEN) {
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, data, SEQUENCE_SIZE, NULL, 0));
        io_seproxyhal_io_heartbeat();
    }
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, data, SEQUENCE_SIZE, output, HASH_SIZE));
    return zxerr_ok;
}

/// Sequentially append the full serialized value of each transparent output
/// to a hash personalized by ZCASH_OUTPUTS_HASH_PERSONALIZATION.
/// In the case that no outputs are provided, this produces a default
/// hash from just the personalization string.
zxerr_t nu5_transparent_outputs_hash(uint8_t *output) {
    if (output == NULL) {
        return zxerr_no_data;
    }

    const uint8_t n = t_outlist_len();

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(
        cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_OUTPUTS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    if (n == 0) {
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }

    uint8_t data[T_OUTPUT_SIZE] = {0};
    uint8_t i = 0;
    for (; i < n - 1; i++) {
        t_output_item_t *item = t_outlist_retrieve_item(i);
        MEMCPY(data, (uint8_t *)&(item->value), 8);
        MEMCPY(data + 8, item->address, SCRIPT_SIZE);
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, data, sizeof(data), NULL, 0));
    }

    t_output_item_t *item = t_outlist_retrieve_item(i);
    MEMCPY(data, (uint8_t *)&(item->value), 8);
    MEMCPY(data + 8, item->address, SCRIPT_SIZE);
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, data, sizeof(data), output, HASH_SIZE));

    return zxerr_ok;
}

/// Implements [ZIP 244 section
/// T.3a](https://zips.z.cash/zip-0244#t-3a-sapling-spends-digest)
///
/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * \[nullifier*\] - personalized with
/// ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION
/// * \[(cv, anchor, rk, zkproof)*\] - personalized with
/// ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by
/// ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
zxerr_t nu5_hash_sapling_spends(const uint8_t *input, uint8_t *output) {
    zemu_log_stack("nu5_hash_sapling_spends");
    if (input == NULL || output == NULL) {
        return zxerr_no_data;
    }

    const uint8_t n = spendlist_len();

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION,
                                          PERSONALIZATION_SIZE));

    if (n == 0) {
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }
    cx_blake2b_t ch_ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ch_ctx, 256, NULL, 0,
                                          (uint8_t *)ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION,
                                          PERSONALIZATION_SIZE));

    cx_blake2b_t nh_ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&nh_ctx, 256, NULL, 0,
                                          (uint8_t *)ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION,
                                          PERSONALIZATION_SIZE));

    const uint8_t *nullifier_data = input + INDEX_SPEND_NF;
    const uint8_t *cv_data = input + INDEX_SPEND_VALUECMT;
    const uint8_t *anchor_data = input + INDEX_SPEND_ANCHOR;
    const uint8_t *rk_data = input + INDEX_SPEND_RK;

    for (uint8_t i = 0; i < n - 1; i++, nullifier_data += SPEND_TX_LEN, cv_data += SPEND_TX_LEN, anchor_data += SPEND_TX_LEN,
                 rk_data += SPEND_TX_LEN) {
        // build the hash of nullifiers separately for compact blocks.
        CHECK_CX_OK(cx_hash_no_throw(&ch_ctx.header, 0, nullifier_data, NULLIFIER_SIZE, NULL, 0));

        CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, 0, cv_data, VALUE_COMMITMENT_SIZE, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, 0, anchor_data, ANCHOR_SIZE, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, 0, rk_data, RK_SIZE, NULL, 0));
    }

    uint8_t ch_out[HASH_SIZE] = {0};
    CHECK_CX_OK(cx_hash_no_throw(&ch_ctx.header, CX_LAST, nullifier_data, NULLIFIER_SIZE, (uint8_t *)ch_out, HASH_SIZE));

    uint8_t nh_out[HASH_SIZE] = {0};
    CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, 0, cv_data, VALUE_COMMITMENT_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, 0, anchor_data, ANCHOR_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, CX_LAST, rk_data, RK_SIZE, (uint8_t *)nh_out, HASH_SIZE));

    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, (uint8_t *)ch_out, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, (uint8_t *)nh_out, HASH_SIZE, output, HASH_SIZE));

    return zxerr_ok;
}

/// Implements [ZIP 244 section
/// T.3b](https://zips.z.cash/zip-0244#t-3b-sapling-outputs-digest)
///
/// Write disjoint parts of each Sapling shielded output as 3 separate hashes:
/// * \[(cmu, epk, enc_ciphertext\[..52\])*\] personalized with
/// ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized with
/// ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION
/// * \[(cv, enc_ciphertext\[564..\], out_ciphertext, zkproof)*\] personalized
/// with ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized with
/// ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION
zxerr_t nu5_hash_sapling_outputs(const uint8_t *input, uint8_t *output) {
    zemu_log_stack("nu5_hash_sapling_outputs");
    if (input == NULL || output == NULL) {
        return zxerr_no_data;
    }

    const uint8_t n = outputlist_len();

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION,
                                          PERSONALIZATION_SIZE));

    if (n == 0) {
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }

    cx_blake2b_t ch_ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ch_ctx, 256, NULL, 0,
                                          (uint8_t *)ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION,
                                          PERSONALIZATION_SIZE));

    cx_blake2b_t mh_ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&mh_ctx, 256, NULL, 0, (uint8_t *)ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION,
                                          PERSONALIZATION_SIZE));

    cx_blake2b_t nh_ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&nh_ctx, 256, NULL, 0,
                                          (uint8_t *)ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION,
                                          PERSONALIZATION_SIZE));

    const uint8_t *cmu = input + INDEX_OUTPUT_NOTECMT;
    const uint8_t *ephemeral_key = input + INDEX_OUTPUT_EPK;
    const uint8_t *enc_ciphertext = input + INDEX_OUTPUT_ENC;

    const uint8_t *enc_ciphertext_memo = input + INDEX_OUTPUT_ENC_MEMO;

    const uint8_t *cv = input + INDEX_OUTPUT_VALUECMT;
    const uint8_t *enc_ciphertext_aead_tag = input + INDEX_OUTPUT_ENC_AEAD_TAG;
    const uint8_t *out_ciphertext = input + INDEX_OUTPUT_OUT;

    for (uint8_t i = 0; i < n - 1; i++, cmu += OUTPUT_TX_LEN, ephemeral_key += OUTPUT_TX_LEN,
                 enc_ciphertext += OUTPUT_TX_LEN, enc_ciphertext_memo += OUTPUT_TX_LEN, cv += OUTPUT_TX_LEN,
                 enc_ciphertext_aead_tag += OUTPUT_TX_LEN, out_ciphertext += OUTPUT_TX_LEN) {
        CHECK_CX_OK(cx_hash_no_throw(&ch_ctx.header, 0, cmu, NOTE_COMMITMENT_SIZE, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&ch_ctx.header, 0, ephemeral_key, EPK_SIZE, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&ch_ctx.header, 0, enc_ciphertext, 52, NULL, 0));

        CHECK_CX_OK(cx_hash_no_throw(&mh_ctx.header, 0, enc_ciphertext_memo, OUTPUT_ENC_MEMO_SIZE, NULL, 0));

        CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, 0, cv, VALUE_COMMITMENT_SIZE, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, 0, enc_ciphertext_aead_tag, OUTPUT_ENC_AEAD_TAG_SIZE, NULL, 0));
        CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, 0, out_ciphertext, OUTPUT_OUT_SIZE, NULL, 0));
    }

    uint8_t ch_out[HASH_SIZE] = {0};
    CHECK_CX_OK(cx_hash_no_throw(&ch_ctx.header, 0, cmu, NOTE_COMMITMENT_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ch_ctx.header, 0, ephemeral_key, EPK_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ch_ctx.header, CX_LAST, enc_ciphertext, 52, ch_out, HASH_SIZE));

    uint8_t mh_out[HASH_SIZE] = {0};
    CHECK_CX_OK(
        cx_hash_no_throw(&mh_ctx.header, CX_LAST, enc_ciphertext_memo, OUTPUT_ENC_MEMO_SIZE, (uint8_t *)mh_out, HASH_SIZE));

    uint8_t nh_out[HASH_SIZE] = {0};
    CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, 0, cv, VALUE_COMMITMENT_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, 0, enc_ciphertext_aead_tag, OUTPUT_ENC_AEAD_TAG_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&nh_ctx.header, CX_LAST, out_ciphertext, OUTPUT_OUT_SIZE, nh_out, HASH_SIZE));

    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, ch_out, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, mh_out, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, nh_out, HASH_SIZE, output, HASH_SIZE));

    return zxerr_ok;
}

/// The txid commits to the hash of all transparent outputs. The
/// prevout and sequence_hash components of txid

zxerr_t hash_header_txid_data(const uint8_t *input, uint8_t *output) {
    zemu_log_stack("hash_header_txid_data");
    if (input == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(
        cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_HEADERS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    const uint8_t *version = input + NU5_INDEX_HASH_VERSION;
    const uint8_t *version_group_id = input + NU5_INDEX_HASH_VERSION_GROUP_ID;
    const uint8_t *consensus_branch_id = input + NU5_INDEX_HASH_CONSENSUS_BRANCH_ID;
    const uint8_t *lock_time = input + NU5_INDEX_HASH_LOCK_TIME;
    const uint8_t *expiry_height = input + NU5_INDEX_EXPIRY_HEIGHT;

    if (cx_hash_no_throw(&ctx.header, 0, version, 4, NULL, 0) != CX_OK ||
        cx_hash_no_throw(&ctx.header, 0, version_group_id, 4, NULL, 0) != CX_OK ||
        cx_hash_no_throw(&ctx.header, 0, consensus_branch_id, 4, NULL, 0) != CX_OK ||
        cx_hash_no_throw(&ctx.header, 0, lock_time, 4, NULL, 0) != CX_OK ||
        cx_hash_no_throw(&ctx.header, CX_LAST, expiry_height, 4, output, HASH_SIZE) != CX_OK) {
        return zxerr_invalid_crypto_settings;
    }

    return zxerr_ok;
}

zxerr_t hash_transparent_txid_data(const uint8_t *input, uint8_t *output) {
    zemu_log_stack("hash_transparent_txid_data");
    if (input == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_TRANSPARENT_HASH_PERSONALIZATION,
                                          PERSONALIZATION_SIZE));

    if ((t_inlist_len() + t_outlist_len()) == 0) {
        return cx_hash_no_throw(&ctx.header, CX_LAST, NULL, 0, output, HASH_SIZE) == CX_OK ? zxerr_ok : zxerr_unknown;
    }

    const uint8_t *prevout_digest = input + NU5_INDEX_HASH_PREVOUTSHASH;
    const uint8_t *sequence_digest = input + NU5_INDEX_HASH_SEQUENCEHASH;
    const uint8_t *outputs_digest = input + NU5_INDEX_HASH_OUTPUTSHASH;

    if (cx_hash_no_throw(&ctx.header, 0, prevout_digest, HASH_SIZE, NULL, 0) != CX_OK ||
        cx_hash_no_throw(&ctx.header, 0, sequence_digest, HASH_SIZE, NULL, 0) != CX_OK ||
        cx_hash_no_throw(&ctx.header, CX_LAST, outputs_digest, HASH_SIZE, output, HASH_SIZE) != CX_OK) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}

zxerr_t transparent_sig_digest(
    const uint8_t *input, uint8_t *start_signdata, uint8_t index, signable_input type, uint8_t *output) {
    zemu_log_stack("transparent_sig_digest");
    if (input == NULL || start_signdata == NULL || output == NULL) {
        return zxerr_no_data;
    }

    if (t_inlist_len() == 0) {
        return hash_transparent_txid_data(start_signdata, output);
    }

    // the following implies that flag_anyonecanpay = flag_single = flag_none = false
    uint8_t hash_type = SIGHASH_ALL;
    const uint8_t *prevout_digest = start_signdata + NU5_INDEX_HASH_PREVOUTSHASH;

    // compute amounts digest
    cx_blake2b_t ctx_amounts = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx_amounts, 256, NULL, 0,
                                          (uint8_t *)ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    uint64_t amount = 0;
    uint8_t amounts_digest[HASH_SIZE] = {0};
    for (uint8_t i = 0; i < t_inlist_len() - 1; ++i) {
        amount = t_inlist_retrieve_item_amount(i);
        CHECK_CX_OK(cx_hash_no_throw(&ctx_amounts.header, 0, (uint8_t *)&amount, sizeof(uint64_t), NULL, 0));
    }

    // t_inlist_len will be >0
    amount = t_inlist_retrieve_item_amount(t_inlist_len() - 1);
    CHECK_CX_OK(
        cx_hash_no_throw(&ctx_amounts.header, CX_LAST, (uint8_t *)&amount, sizeof(uint64_t), amounts_digest, HASH_SIZE));

    cx_blake2b_t ctx_scripts = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx_scripts, 256, NULL, 0,
                                          (uint8_t *)ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    uint8_t scripts[SCRIPT_SIZE] = {0};
    uint8_t scripts_digest[HASH_SIZE] = {0};
    for (uint8_t i = 0; i < t_inlist_len() - 1; ++i) {
        t_inlist_retrieve_item_script(i, scripts);
        CHECK_CX_OK(cx_hash_no_throw(&ctx_scripts.header, 0, scripts, sizeof(scripts), NULL, 0));
        MEMZERO(scripts, SCRIPT_SIZE);
    }
    t_inlist_retrieve_item_script(t_inlist_len() - 1, scripts);
    CHECK_CX_OK(cx_hash_no_throw(&ctx_scripts.header, CX_LAST, scripts, SCRIPT_SIZE, scripts_digest, HASH_SIZE));

    const uint8_t *sequence_digest = start_signdata + NU5_INDEX_HASH_SEQUENCEHASH;
    const uint8_t *outputs_digest = start_signdata + NU5_INDEX_HASH_OUTPUTSHASH;

    cx_blake2b_t ctx_txin_sig_digest = {0};
    uint8_t txin_sig_digest[HASH_SIZE] = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx_txin_sig_digest, 256, NULL, 0,
                                          (uint8_t *)ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    if (type == transparent) {
        const t_input_item_t *item = t_inlist_retrieve_item(index);

        const uint8_t *prevout_data = input + index * T_IN_TX_LEN + INDEX_TIN_PREVOUT;
        CHECK_CX_OK(cx_hash_no_throw(&ctx_txin_sig_digest.header, 0, prevout_data, PREVOUT_SIZE, NULL, 0));

        uint64_t value = item->value;
        CHECK_CX_OK(cx_hash_no_throw(&ctx_txin_sig_digest.header, 0, (uint8_t *)&value, sizeof(uint64_t), NULL, 0));

        const uint8_t *script = item->script;
        CHECK_CX_OK(cx_hash_no_throw(&ctx_txin_sig_digest.header, 0, script, SCRIPT_SIZE, NULL, 0));

        const uint8_t *sequence_data = input + index * T_IN_TX_LEN + INDEX_TIN_SEQ;
        CHECK_CX_OK(cx_hash_no_throw(&ctx_txin_sig_digest.header, 0, sequence_data, SEQUENCE_SIZE, NULL, 0));
    }

    CHECK_CX_OK(cx_hash_no_throw(&ctx_txin_sig_digest.header, CX_LAST, NULL, 0, txin_sig_digest, HASH_SIZE));

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_TRANSPARENT_HASH_PERSONALIZATION,
                                          PERSONALIZATION_SIZE));

    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, &hash_type, sizeof(uint8_t), NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, prevout_digest, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, amounts_digest, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, scripts_digest, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, sequence_digest, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, outputs_digest, HASH_SIZE, NULL, 0));

    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, txin_sig_digest, HASH_SIZE, output, HASH_SIZE));

    return zxerr_ok;
}

zxerr_t hash_sapling_txid_data(const uint8_t *input, uint8_t *output) {
    zemu_log_stack("hash_sapling_txid_data");
    if (input == NULL || output == NULL) {
        return zxerr_no_data;
    }

    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(
        cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_SAPLING_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));

    if (spendlist_len() + outputlist_len() == 0) {
        CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));
        return zxerr_ok;
    }

    const uint8_t *hash_sapling_spends = input + NU5_INDEX_HASH_SHIELDEDSPENDHASH;
    const uint8_t *hash_sapling_outputs = input + NU5_INDEX_HASH_SHIELDEDOUTPUTHASH;
    const uint8_t *value_balance = input + NU5_INDEX_HASH_VALUEBALANCE;
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, hash_sapling_spends, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, hash_sapling_outputs, HASH_SIZE, NULL, 0));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, value_balance, NU5_VALUEBALANCE_SIZE, output, HASH_SIZE));

    return zxerr_ok;
}

zxerr_t hash_empty_orchard_txid_data(uint8_t *output) {
    if (output == NULL) {
        return zxerr_no_data;
    }
    cx_blake2b_t ctx = {0};
    CHECK_CX_OK(
        cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_ORCHARD_HASH_PERSONALIZATION, PERSONALIZATION_SIZE));
    CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE));

    return zxerr_ok;
}
