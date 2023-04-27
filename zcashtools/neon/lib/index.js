var addon = require('../native');
const { get_inittx_data, builderNew, builderAddTransparentInput, builderAddTransparentOutput,
        builderAddSaplingSpend, builderAddSaplingOutput, builderBuild, builderAddSignatures,
        builderFinalize} = require("../native/index.node");

// Here we can write some simple tests for play around
console.log("--------------------------------------")
console.log("- Zcash Tools Scratch Tests          -")
console.log("--------------------------------------\n\n")


function addr_to_script(addr) {
    const begin = Buffer.from("1976a914", 'hex');
    const end = Buffer.from("88ac", 'hex');
    var x = Buffer.concat([begin, addr, end]);
    return x;
}

class ZcashBuilderBridge{
    constructor(fee) {
        this.boxed = builderNew(fee)
    }
    // Wrap each method with a delegate to `this.db`
    // This could be done in several other ways, for example binding assignment
    // in the constructor
    add_transparent_input(t_input){
        return builderAddTransparentInput.call(this.boxed, t_input);
    }
    add_transparent_output(t_output){
        return builderAddTransparentOutput.call(this.boxed, t_output);
    }
    add_sapling_spend(z_spend){
        return builderAddSaplingSpend.call(this.boxed, z_spend);
    }
    add_sapling_output(z_output){
        return builderAddSaplingOutput.call(this.boxed, z_output);
    }
    build(spend_path, output_path, tx_version){
        return builderBuild.call(this.boxed, spend_path, output_path, tx_version);
    }
    add_signatures(signatures){
        return builderAddSignatures.call(this.boxed, signatures);
    }

    finalize(signatures){
        return builderFinalize.call(this.boxed);
    }

}
module.exports = {ZcashBuilderBridge,get_inittx_data}
/*
const Resolve = require("path").resolve;
const SPEND_PATH = Resolve("../zcashtools/src/sapling-spend.params");
const OUTPUT_PATH = Resolve("../zcashtools/src/sapling-output.params");

outp = Buffer.alloc(36); //get this from blockchain
script = Buffer.from("76a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac",'hex');
valuet = U64ToBuf(100);
pk = Buffer.from("031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e",'hex');

//send to ledger to check: [HDPATH (120), script (33), value (8)]
//check by: computing pk from HDPATH -> convert to scriptthing
//check value in the hash

//send ledger to check: [outaddr, value]
//check by: the outputhash

tbuf = Buffer.concat([outp, pk, valuet,script]);
console.log(builder.add_transparent_input(tbuf))

valuetout = U64ToBuf(50);
outaddr = Buffer.alloc(20);
obuf = Buffer.concat([outaddr,valuetout]);

console.log(builder.add_transparent_output(obuf));


proofkey = Buffer.from("4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405",'hex');
rcv = Buffer.from("f802b07c85afb64a271f8e9641ce04ca75f255ba1d52d7a889a4fb38ea03bb09",'hex');
alpha = Buffer.from("78770181665b6142dcd104fe1f9b9c8788ea46b90192df144cdca3e5f0560002",'hex');
ovk = Buffer.from("6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca",'hex');
address = Buffer.from("c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",'hex');
value = Buffer.from("0100100000000000",'hex');

buf = Buffer.concat([proofkey,rcv,alpha,ovk,address,value, rcv]);

builder.add_sapling_spend(buf);
xx = Buffer.concat([rcv,rcv,alpha,ovk,address]);
builder.add_change_address(xx);

rcn = Buffer.from("f802b07c85afb64a271f8e9641ce04ca75f255ba1d52d7a889a4fb38ea03bb09",'hex');
esk = Buffer.from("f802b07c85afb64a271f8e9641ce04ca75f255ba1d52d7a889a4fb38ea03bb09",'hex');
ovk = Buffer.from("0000000000000000000000000000000000000000000000000000000000000000",'hex');
address = Buffer.from("c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",'hex');
value = Buffer.from("0100000000000000",'hex');
memo = Buffer.from("f600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",'hex');

outputbuf = Buffer.concat([rcv,rcn,esk,ovk,address,value,memo]);

builder.add_sapling_output(outputbuf);

buf = Buffer.alloc(320 + 948 * 2 + 220);

console.log(builder.build(SPEND_PATH, OUTPUT_PATH, buf));
builder.add_signatures(Buffer.concat([rcv,alpha]));//should fail
console.log(buf);


 */
console.log("\n\n--------------------------------------")
/*
- get_shielded_address
- make transaction:
1. send #spends | #outputs | spenddata (pos + value + address) |  outputdata (address/value + value)
 */
