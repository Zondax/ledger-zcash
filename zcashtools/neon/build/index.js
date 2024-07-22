"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZcashBuilderBridge = exports.OUTPUT_PATH = exports.SPEND_PATH = exports.calculate_fee = exports.get_inittx_data = void 0;
const path_1 = require("path");
const native_1 = __importDefault(require("./native"));
exports.get_inittx_data = native_1.default.get_inittx_data;
function calculate_fee(n_tin = 0, n_tout = 0, n_spend = 0, n_sout = 0) {
    return native_1.default.calculate_zip317_fee(n_tin, n_tout, n_spend, n_sout);
}
exports.calculate_fee = calculate_fee;
exports.SPEND_PATH = (0, path_1.resolve)(__dirname, "..", "params/sapling-spend.params");
exports.OUTPUT_PATH = (0, path_1.resolve)(__dirname, "..", "params/sapling-output.params");
class ZcashBuilderBridge {
    constructor(fee) {
        this.boxed = native_1.default.builderNew(fee);
    }
    add_transparent_input(t_input) {
        return native_1.default.builderAddTransparentInput.call(this.boxed, t_input);
    }
    add_transparent_output(t_output) {
        return native_1.default.builderAddTransparentOutput.call(this.boxed, t_output);
    }
    add_sapling_spend(s_spend) {
        return native_1.default.builderAddSaplingSpend.call(this.boxed, s_spend);
    }
    add_sapling_output(s_output) {
        return native_1.default.builderAddSaplingOutput.call(this.boxed, s_output);
    }
    build(spend_path, output_path, tx_version) {
        return native_1.default.builderBuild.call(this.boxed, spend_path, output_path, tx_version);
    }
    add_signatures(signatures) {
        return native_1.default.builderAddSignatures.call(this.boxed, signatures);
    }
    finalize() {
        return native_1.default.builderFinalize.call(this.boxed);
    }
}
exports.ZcashBuilderBridge = ZcashBuilderBridge;
