type GrowToSize<T, N extends number, A extends T[]> =
  A['length'] extends N ? A : GrowToSize<T, N, [...A, T]>;

export type FixedArray<T, N extends number> = GrowToSize<T, N, []>;

export interface TinData {
    path: FixedArray<number, 5>;
    address: string,
    value: number,
}

export interface ToutData {
    address: string,
    value: number
}

export interface ShieldedSpendData {
    path: number,
    address: string,
    value: number,
}

export interface ShieldedOutputData {
    address: string,
    value: number,
    memo_type: number,
    ovk: string | null,
}

export interface InitData {
    t_in: TinData[],
    t_out: ToutData[],
    s_spend: ShieldedSpendData[],
    s_output: ShieldedOutputData[],
}

export type ZcashBuilder = {
    readonly __brand: unique symbol;
};

export interface TransparentInputInfo {
    outp: string,
    pk: string,
    address: string,
    value: number
}

export interface TransparentOutputInfo {
    address: string
    value: number
}

export interface SpendInfo {
    proofkey: string;
    rcv: string;
    alpha: string;
    address: string,
    value: number,
    witness: string,
    rseed: string,
}

export interface OutputInfo {
    rcv: string,
    rseed: string,
    ovk: string | null,
    address: string,
    value: number,
    memo: string | null,
    hash_seed: Uint8Array | null,
}

export interface TransactionSignatures {
    transparent_sigs: string[],
    spend_sigs: string[]
}

interface NativeModule {
    get_inittx_data(_: InitData): Buffer;

    builderNew(fee: number): ZcashBuilder;

    builderAddTransparentInput(this: ZcashBuilder, tin: TransparentInputInfo): boolean;
    builderAddTransparentOutput(this: ZcashBuilder, tout: TransparentOutputInfo): boolean;
    builderAddSaplingSpend(this: ZcashBuilder, spend: SpendInfo): boolean;
    builderAddSaplingOutput(this: ZcashBuilder, out: OutputInfo): boolean;

    builderBuild(this: ZcashBuilder, spend_path: string, output_path: string, tx_version: number): Uint8Array;

    builderAddSignatures(this: ZcashBuilder, sigs: TransactionSignatures): boolean;
    builderFinalize(this: ZcashBuilder): Uint8Array;
}

const addon: NativeModule = require("../native/index.node")
export default addon;
