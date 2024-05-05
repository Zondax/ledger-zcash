#include "zip-0317.h"

#define DIV_CEIL(x, y)             ((x + (y - 1)) / y)

#define MARGINAL_FEE               5000
#define GRACE_ACTIONS              2
#define P2PKH_STANDARD_INPUT_SIZE  150
#define P2PKH_STANDARD_OUTPUT_SIZE 34

uint64_t zip_0317_fee_raw(uint64_t tx_in_total_size, uint64_t tx_out_total_size, uint64_t n_join_split,
                          uint64_t n_spends_sapling, uint64_t n_outputs_sapling, uint64_t n_actions_orchard) {
    uint64_t tin_actions = DIV_CEIL(tx_in_total_size, P2PKH_STANDARD_INPUT_SIZE);
    uint64_t tout_actions = DIV_CEIL(tx_out_total_size, P2PKH_STANDARD_OUTPUT_SIZE);

    uint64_t transparent_actions = (tin_actions > tout_actions) ? tin_actions : tout_actions;
    uint64_t sapling_actions = (n_spends_sapling > n_outputs_sapling) ? n_spends_sapling : n_outputs_sapling;
    uint64_t joinsplit_actions = 2 * n_join_split;
    uint64_t orchard_actions = n_actions_orchard;

    uint64_t logical_actions = transparent_actions + sapling_actions + joinsplit_actions + orchard_actions;

    return MARGINAL_FEE * ((GRACE_ACTIONS > logical_actions) ? GRACE_ACTIONS : logical_actions);
}

uint64_t zip_0317(uint64_t n_tin, uint64_t n_tout, uint64_t n_sapling_spends, uint64_t n_sapling_outs) {
    return zip_0317_fee_raw(n_tin * P2PKH_STANDARD_INPUT_SIZE, n_tout * P2PKH_STANDARD_OUTPUT_SIZE, 0, n_sapling_spends,
                            n_sapling_outs, 0);
}
