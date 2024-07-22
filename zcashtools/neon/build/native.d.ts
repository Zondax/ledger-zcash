/// <reference types="node" />
type GrowToSize<T, N extends number, A extends T[]> = A['length'] extends N ? A : GrowToSize<T, N, [...A, T]>;
export type FixedArray<T, N extends number> = GrowToSize<T, N, []>;
export interface TinData {
    path: FixedArray<number, 5>;
    address: string;
    value: number;
}
export interface ToutData {
    address: string;
    value: number;
}
export interface SaplingSpendData {
    path: number;
    address: string;
    value: number;
}
export interface SaplingOutputData {
    ovk: string | null;
    address: string;
    value: number;
    memo_type: number;
}
export interface InitData {
    t_in: TinData[];
    t_out: ToutData[];
    s_spend: SaplingSpendData[];
    s_output: SaplingOutputData[];
}
export type ZcashBuilder = {
    readonly __brand: unique symbol;
};
export interface TransparentInputInfo {
    outp: string;
    pk: string;
    address: string;
    value: number;
}
export interface TransparentOutputInfo {
    address: string;
    value: number;
}
export interface SaplingSpendInfo {
    proofkey: string;
    rcv: string;
    alpha: string;
    address: string;
    value: number;
    witness: string;
    rseed: string;
}
export interface SaplingOutputInfo {
    ovk: string | null;
    address: string;
    value: number;
    memo: string | null;
    rcv: string;
    rseed: string;
    hash_seed?: string;
}
export interface Signatures {
    transparent_sigs: string[];
    sapling_sigs: string[];
}
interface NativeModule {
    get_inittx_data(_: InitData): Buffer;
    calculate_zip317_fee(n_tin: number, n_tout: number, n_sspend: number, n_sout: number): number;
    builderNew(fee: number): ZcashBuilder;
    builderAddTransparentInput(this: ZcashBuilder, tin: TransparentInputInfo): boolean;
    builderAddTransparentOutput(this: ZcashBuilder, tout: TransparentOutputInfo): boolean;
    builderAddSaplingSpend(this: ZcashBuilder, spend: SaplingSpendInfo): boolean;
    builderAddSaplingOutput(this: ZcashBuilder, out: SaplingOutputInfo): boolean;
    builderBuild(this: ZcashBuilder, spend_path: string, output_path: string, tx_version: number): Uint8Array;
    builderAddSignatures(this: ZcashBuilder, sigs: Signatures): boolean;
    builderFinalize(this: ZcashBuilder): Uint8Array;
}
declare const addon: NativeModule;
export default addon;
