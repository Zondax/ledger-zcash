/// <reference types="node" />
import { SaplingOutputInfo, SaplingSpendInfo, Signatures, TransparentInputInfo, TransparentOutputInfo } from './native';
export type { InitData } from './native';
export declare const get_inittx_data: (_: import("./native").InitData) => Buffer;
export declare function calculate_fee(n_tin?: number, n_tout?: number, n_spend?: number, n_sout?: number): number;
export declare var SPEND_PATH: string;
export declare var OUTPUT_PATH: string;
export declare class ZcashBuilderBridge {
    private readonly boxed;
    constructor(fee: number);
    add_transparent_input(t_input: TransparentInputInfo): boolean;
    add_transparent_output(t_output: TransparentOutputInfo): boolean;
    add_sapling_spend(s_spend: SaplingSpendInfo): boolean;
    add_sapling_output(s_output: SaplingOutputInfo): boolean;
    build(spend_path: string, output_path: string, tx_version: number): Uint8Array;
    add_signatures(signatures: Signatures): boolean;
    finalize(): Uint8Array;
}
