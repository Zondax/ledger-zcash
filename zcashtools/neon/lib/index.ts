import addon, { OutputInfo, SpendInfo, TransactionSignatures, TransparentInputInfo, TransparentOutputInfo, ZcashBuilder } from './native';

export type { InitData } from './native'
export const get_inittx_data = addon.get_inittx_data;

export class ZcashBuilderBridge {
    private boxed: ZcashBuilder;

    constructor(fee: number) {
        this.boxed = addon.builderNew(fee)
    }

    add_transparent_input(t_input: TransparentInputInfo) {
        return addon.builderAddTransparentInput.call(this.boxed, t_input);
    }
    add_transparent_output(t_output: TransparentOutputInfo) {
        return addon.builderAddTransparentOutput.call(this.boxed, t_output);
    }
    add_sapling_spend(z_spend: SpendInfo) {
        return addon.builderAddSaplingSpend.call(this.boxed, z_spend);
    }
    add_sapling_output(z_output: OutputInfo) {
        return addon.builderAddSaplingOutput.call(this.boxed, z_output);
    }
    build(spend_path: string, output_path: string, tx_version: number) {
        return addon.builderBuild.call(this.boxed, spend_path, output_path, tx_version);
    }
    add_signatures(signatures: TransactionSignatures) {
        return addon.builderAddSignatures.call(this.boxed, signatures);
    }

    finalize() {
        return addon.builderFinalize.call(this.boxed);
    }
}
