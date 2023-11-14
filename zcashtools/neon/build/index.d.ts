/// <reference types="node" />
import { OutputInfo, SpendInfo, TransactionSignatures, TransparentInputInfo, TransparentOutputInfo } from './native';
export type { InitData } from './native';
export declare const get_inittx_data: (_: import("./native").InitData) => Buffer;
export declare function calculate_fee(n_tin?: number, n_tout?: number, n_spend?: number, n_sout?: number): number;
export declare var SPEND_PATH: string;
export declare var OUTPUT_PATH: string;
export declare class ZcashBuilderBridge {
    private boxed;
    constructor(fee: number);
    add_transparent_input(t_input: TransparentInputInfo): boolean;
    add_transparent_output(t_output: TransparentOutputInfo): boolean;
    add_sapling_spend(z_spend: SpendInfo): boolean;
    add_sapling_output(z_output: OutputInfo): boolean;
    build(spend_path: string, output_path: string, tx_version: number): Uint8Array;
    add_signatures(signatures: TransactionSignatures): boolean;
    finalize(): Uint8Array;
}
