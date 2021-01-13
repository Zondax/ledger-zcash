/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import { expect, test } from "jest";
import Zemu from "@zondax/zemu";
import ZCashApp from "@zondax/ledger-zcash";

import { TX_TESTS } from './unshielded_tx';

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app.elf");
const fs = require('fs');
var addon = require('../../zcashtools/neon/native');
const crypto = require('crypto');

const SPEND_PATH = Resolve("../zcashtools/params/sapling-spend.params");
const OUTPUT_PATH = Resolve("../zcashtools/params/sapling-output.params");

const clicksTIN = 3;
const clicksTOUT = 3;
const clicksSSPEND = 4;
const clicksSOUT = 6;
const clicksOVKset = 1;
const clicksConst = 2

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const sim_options = {
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`
   ,X11: true
};

jest.setTimeout(600000);

describe('Zcashtool tests', function () {
    test('get ivk', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const ivkreq = app.getivk(1000);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(),600000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const ivk = await ivkreq;

            console.log(ivk)
            expect(ivk.return_code).toEqual(0x9000);

            const expected_ivk_raw = "6dfadf175921e6fbfa093c8f7c704a0bdb07328474f56c833dfcfa5301082d03";
            const ivk_raw = ivk.ivk_raw.toString('hex');
            expect(ivk_raw).toEqual(expected_ivk_raw);
        } finally {
            await sim.close();
        }
    });

    test('get outgoing viewing key', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const ovkreq = app.getovk(1000);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(),600000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const ovk = await ovkreq;
            console.log(ovk)
            expect(ovk.return_code).toEqual(0x9000);

            const expected_ovk_raw = "6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca";
            const ovk_raw = ovk.ovk_raw.toString('hex');
            expect(ovk_raw).toEqual(expected_ovk_raw);

        } finally {
            await sim.close();
        }
    });

    test('get shielded address with div', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const path = 1000;
            const div = Buffer.from("c69e979c6763c1b09238dc",'hex');

            const addr = await app.getaddrdiv(path,div);
            console.log(addr)
            expect(addr.return_code).toEqual(0x9000);

            const expected_addr_raw = "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667";
            const expected_addr = "zs1c60f08r8v0qmpy3cm34ath9lx5mqm72aet0ccrazth97m2hkq46n3wqj6pn9vunw5fmxwclltd3";

            const addr_raw = addr.address_raw.toString('hex');
            expect(addr_raw).toEqual(expected_addr_raw);
            expect(addr.address).toEqual(expected_addr);

        } finally {
            await sim.close();
        }
    });

    test('show shielded address with div', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const path = 1000;
            const div = Buffer.from("c69e979c6763c1b09238dc",'hex');

            const addrreq = app.showaddrdiv(path,div);
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(),600000);
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const addr = await addrreq;

            console.log(addr)
            expect(addr.return_code).toEqual(0x9000);

            const expected_addr_raw = "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667";

            const addr_raw = addr.address_raw.toString('hex');
            expect(addr_raw).toEqual(expected_addr_raw);

        } finally {
            await sim.close();
        }
    });

    test('get div list with startindex', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const startindex = Buffer.from([0,0,0,0,0,0,0,0,0,0,0]);

            const divlist = await app.getdivlist(1000, startindex);
            console.log(divlist)
            expect(divlist.return_code).toEqual(0x9000);

            const first_div = "c69e979c6763c1b09238dc";

            const first_div_raw = divlist.divlist[0];
            expect(first_div).toEqual(first_div_raw);


        } finally {
            await sim.close();
        }
    });

   test('make a transaction with 2 spend 2 outputs', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const {zcashtools} = addon;
            console.log(SPEND_PATH)

            var builder = new zcashtools(1000);

            /*
            In this test, Alice wants to send 55000 ZEC to Bob.
            For this she needs two notes of 50000 ZEC sent to her address belonging to path: 1000.
            The inputs to the initialization is therefor two spend notes and two output notes.
            She takes a transaction fee of 1000.
            All this info is gathered from the UI and put in the correct jsons.
             */

            const s_spend1 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 50000,
            }

            const s_spend2 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 50000,
            }

            const s_out1 = {
                address: "15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc",
                value: 55000,
                memo_type: 0xf6,
                ovk: null,
            }
            //CHANGE ADDRESS:
            const s_out2 = {
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 100000-1000-55000,
                memo_type: 0xf6,
                ovk: "6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca",
            }

            const tx_input_data = {
                t_in : [],
                t_out : [],
                s_spend: [s_spend1,s_spend2],
                s_output: [s_out1, s_out2],
            }

            /*
            The inputs to the get_inittx_data function are the inputs to the transaction.
            The output is a blob that can be send to the ledger device.
            */

            const ledgerblob_initdata = addon.get_inittx_data(tx_input_data);
            console.log(Buffer.from(ledgerblob_initdata).byteLength);

            /*
            The output of the get_inittx_data can be send to the ledger.
            The ledger will check this data and show the inputs on screen for verification.
            If confirmed, the ledger also computes the randomness needed for :
                - The shielded spends
                - the shielded outputs
             */

            const reqinit = app.inittx(ledgerblob_initdata);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
            //we have to click several times...
            for (let i = 1; i < 2*clicksSSPEND + 2 * clicksSOUT + clicksConst + clicksOVKset; i += 1) {
                await sim.clickRight();
            }
            await sim.clickBoth();

            const req = await reqinit;

            console.log(req);
            expect(req.return_code).toEqual(0x9000);
            expect(req.txdata.byteLength).toEqual(32);

            /*
            Check the hash of the return
             */
            let hash = crypto.createHash('sha256');
            hash.update(Buffer.from(ledgerblob_initdata));
            let h = hash.digest('hex');
            expect(req.txdata.toString('hex')).toEqual(h);

            /*
            Now we start building the transaction using the builder.
            /*

             /*
            To add a shielded spend to the builder, we need:
                - the proof generation key belonging to the spend address (proofkey)
                - the randomness needed for the value commitment (rcv)
                - the randomness needed for the random verification key (alpha)
            All this is retrieved from the ledger using a extractspenddata call with no inputs.
            The ledger already knows how much data it needs to send after the inittx call.
            */

            var req2 = await app.extractspenddata();
            console.log(req2);
            expect(req2.return_code).toEqual(0x9000);
            const expected_proofkey_raw = "4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405";
            expect(req2.key_raw.toString('hex')).toEqual(expected_proofkey_raw);
            expect(req2.rcv_raw).not.toEqual(req2.alpha_raw);

            /*
            The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
            It furthermore uses the spend address and value from the UI.
            We also need the witness from the blockchain, which is now a fake/incorrect one.
             */

            var spendj1 = {
                proofkey: req2.key_raw,
                rcv: req2.rcv_raw,
                alpha: req2.alpha_raw,
                address: s_spend1.address,
                value: s_spend1.value,
                witness: "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                rseed: "0000000000000000000000000000000000000000000000000000000000000000"
            };

            /*
            The builder adds the spend to its state.
             */

            var b1 = builder.add_sapling_spend(spendj1);
            console.log(b1);

            /*
            We need to repeat the above process for the second spend.
             */

            var req3 = await app.extractspenddata();
            console.log(req3);
            expect(req3.return_code).toEqual(0x9000);
            expect(req3.key_raw.toString('hex')).toEqual(expected_proofkey_raw);

            var spendj2 = {
                proofkey: req3.key_raw,
                rcv: req3.rcv_raw,
                alpha: req3.alpha_raw,
                address: s_spend2.address,
                value: s_spend2.value,
                witness: "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                rseed: "0000000000000000000000000000000000000000000000000000000000000000"
            };

            var b2 = builder.add_sapling_spend(spendj2);
            console.log(b2);

            /*
            At this point we added all spends.
            We cannot get more spend data from the ledger.
            We now start the shielded output process.
             */


            /*
           To add a shielded output to the builder, we need:
               - the randomness needed for the value commitment (rcv)
               - the randomness needed for the note commitment (rcm)
               - the randomness needed for the random encryption key (esk)
           All this is retrieved from the ledger using a extractoutputdata call with no inputs.
           The ledger already knows how much data it needs to send after the inittx call.
           */

            const req4 = await app.extractoutputdata();
            console.log(req4);
            expect(req4.return_code).toEqual(0x9000);

            /*
            The builder needs the data retrieved from the ledger (rcv, rcm, esk)
            It CAN send along an outgoing viewing key (OVK), can also be all zero's.
            It furthermore uses the output address, value and memo from the UI.
            */

            var outj1 = {
                rcv: req4.rcv_raw,
                rseed: req4.rseed_raw,
                ovk: s_out1.ovk,
                address: s_out1.address,
                value: s_out1.value,
                memo: "0000"
            }

            /*
            The builder adds the shielded output to its state.
             */

            var b3 = builder.add_sapling_output(outj1);
            console.log(b3);

            /*
            This process needs to be repeated for the second output.
            Note that this output address belongs to Alice.
            There is no concept of a "change address" as all inputs and outputs need to be known in advance for the ledger verification on screen.
            The UI needs to take care of this before initalizing a transaction to the ledger.
             */

            const req5 = await app.extractoutputdata();
            console.log(req5);
            expect(req5.return_code).toEqual(0x9000);

            var outj2 = {
                rcv: req5.rcv_raw,
                rseed: req5.rseed_raw,
                ovk: s_out2.ovk,
                address: s_out2.address,
                value: s_out2.value,
                memo: "0000"
            }

            var b4 = builder.add_sapling_output(outj2);
            console.log(b4);

            /*
            We are now done with adding the shielded outputs to the builder.
            In fact, we are done adding all inputs the builder needs for this transaction.
            We now let the builder build the transaction, including the ZK proofs.
            The builder returns a txdata blob.
            The ledger needs this blob to validate the correctness of the tx.
             */

            const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH);

            /*
            Now the ledger will validate the txdata blob.
            For this, it uses the input from inittx to verify.
            If all checks are ok, the ledger signs the transaction.
             */

            const req6 = await app.checkandsign(ledgerblob_txdata);
            console.log(req6);
            expect(req6.return_code).toEqual(0x9000);

            /*
            Check the hash of the return
            */

            hash = crypto.createHash('sha256');
            hash.update(Buffer.from(ledgerblob_txdata));
            h = hash.digest('hex');
            expect(req6.signdata.toString('hex')).toEqual(h);


            /*
            The builder needs these signatures to add it to the transaction blob.
            We need to do this one by one.
            So we first gather all signatures we need.
             */


            const req7 = await app.extractspendsig();
            console.log(req7);
            expect(req7.return_code).toEqual(0x9000);

            const req8 = await app.extractspendsig();
            console.log(req8);
            expect(req8.return_code).toEqual(0x9000);

            /*
            At this point we gathered all signatures.
            We now add these signaturs to the builder.
            Note that for this transaction, we do not have any transparent signatures.
             */


            const signatures = {
                transparent_sigs: [],
                spend_sigs: [req7.sig_raw, req8.sig_raw],
            }

            var b5 = builder.add_signatures(signatures);
            console.log(b5);

            /*
            The builder is now done and the transaction is complete.
             */

            var b6 = builder.finalize();
            console.log(b6);

        } finally {
            await sim.close();
        }
    });

    test('make a transaction with 1 transparent input 1 transparent output 1 spend 2 shielded outputs', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const {zcashtools} = addon;
            console.log(SPEND_PATH)

            var builder = new zcashtools(1000);

            /*
            In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
            For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
            She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
            The inputs to the initialization is therefor:
            - one transparent input and one transparent output
            - one shielded spend notes and two shielded output notes.
            She takes a transaction fee of 10000 and all leftovers is sent shielded to her own address.
            All this info is gathered from the UI and put in the correct jsons.
             */

            const tin1 = {
                path: [(44 + 0x80000000), (133 + 0x80000000), (5 + 0x80000000), 0 ,0],
                address: "1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac",
                value: 60000,
            }

            const tout1 = {
                address: "1976a914000000000000000000000000000000000000000088ac",
                value: 10000,
            }

            const s_spend1 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 40000,
            }

            const s_out1 = {
                address: "15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc",
                value: 55000,
                memo_type: 0xf6,
                ovk: null,
            }

            const s_out2 = {
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 100000-1000-55000 - 10000,
                memo_type: 0xf6,
                ovk: "6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca",
            }

            const tx_input_data = {
                t_in : [tin1],
                t_out : [tout1],
                s_spend: [s_spend1],
                s_output: [s_out1, s_out2],
            }

            /*
            The inputs to the get_inittx_data function are the inputs to the transaction.
            The output is a blob that can be send to the ledger device.
            */

            const ledgerblob_initdata = addon.get_inittx_data(tx_input_data);
            console.log(ledgerblob_initdata);

            /*
            The output of the get_inittx_data can be send to the ledger.
            The ledger will check this data and show the inputs on screen for verification.
            If confirmed, the ledger also computes the randomness needed for :
                - The shielded spends
                - the shielded outputs
             */

            const reqinit = app.inittx(ledgerblob_initdata);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            //we have to click several times...
            for (let i = 1; i < 1 * clicksTIN + 1 * clicksTOUT + 1*clicksSSPEND + 2 * clicksSOUT + clicksOVKset + clicksConst; i += 1) {
                await sim.clickRight();
            }
            await sim.clickBoth();

            const req = await reqinit;

            //const req = await app.inittx(ledgerblob_initdata);
            console.log(req);
            expect(req.return_code).toEqual(0x9000);
            expect(req.txdata.byteLength).toEqual(32);

            /*
            Check the hash of the return
            */
            let hash = crypto.createHash('sha256');
            hash.update(Buffer.from(ledgerblob_initdata));
            let h = hash.digest('hex');
            expect(req.txdata.toString('hex')).toEqual(h);

            /*
            Now we start building the transaction using the builder.
            /*

            /*
            To add transparent inputs to the builder, we dont need fresh information from the ledger.
            The builder does need the secp256k1 public key beloging to the address.
             The builder also need outpoint from the blockchain.
             */

            const t_data = {
                outp: "000000000000000000000000000000000000000000000000000000000000000000000000",
                pk: "031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e",
                address:tin1.address,
                value:tin1.value,
            }

            var bt0 = builder.add_transparent_input(t_data);
            console.log(bt0);

            /*
            To add a transparent output, the builder does not need anything other than the input to the inittx.
             */

            var bt1 = builder.add_transparent_output(tout1);
            console.log(bt1);

             /*
            To add a shielded spend to the builder, we need:
                - the proof generation key belonging to the spend address (proofkey)
                - the randomness needed for the value commitment (rcv)
                - the randomness needed for the random verification key (alpha)
            All this is retrieved from the ledger using a extractspenddata call with no inputs.
            The ledger already knows how much data it needs to send after the inittx call.
            */

            var req2 = await app.extractspenddata();
            console.log(req2);
            expect(req2.return_code).toEqual(0x9000);
            const expected_proofkey_raw = "4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405";
            expect(req2.key_raw.toString('hex')).toEqual(expected_proofkey_raw);
            expect(req2.rcv_raw).not.toEqual(req2.alpha_raw);

            /*
            The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
            It furthermore uses the spend address and value from the UI.
             */

            var spendj1 = {
                proofkey: req2.key_raw,
                rcv: req2.rcv_raw,
                alpha: req2.alpha_raw,
                address: s_spend1.address,
                value: s_spend1.value,
                witness: "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                rseed: "0000000000000000000000000000000000000000000000000000000000000000"
            };

            /*
            The builder adds the spend to its state.
             */

            var b1 = builder.add_sapling_spend(spendj1);
            console.log(b1);

            /*
            At this point we added all spends.
            We cannot get more spend data from the ledger.
            We now start the shielded output process.
             */

            /*
           To add a shielded output to the builder, we need:
               - the randomness needed for the value commitment (rcv)
               - the randomness needed for the note commitment (rcm)
               - the randomness needed for the random encryption key (esk)
           All this is retrieved from the ledger using a extractoutputdata call with no inputs.
           The ledger already knows how much data it needs to send after the inittx call.
           */

            const req4 = await app.extractoutputdata();
            console.log(req4);
            expect(req4.return_code).toEqual(0x9000);

            /*
            The builder needs the data retrieved from the ledger (rcv, rcm, esk)
            It CAN send along an outgoing viewing key (OVK), can also be all zero's.
            It furthermore uses the output address, value and memo from the UI.
            */

            var outj1 = {
                rcv: req4.rcv_raw,
                rseed: req4.rseed_raw,
                ovk: s_out1.ovk,
                address: s_out1.address,
                value: s_out1.value,
                memo: "0000"
            }

            /*
            The builder adds the shielded output to its state.
             */

            var b3 = builder.add_sapling_output(outj1);
            console.log(b3);

            /*
            This process needs to be repeated for the second output.
            Note that this output address belongs to Alice.
             */

            const req5 = await app.extractoutputdata();
            console.log(req5);
            expect(req5.return_code).toEqual(0x9000);

            var outj2 = {
                rcv: req5.rcv_raw,
                rseed: req5.rseed_raw,
                ovk: s_out2.ovk,
                address: s_out2.address,
                value: s_out2.value,
                memo: "0000"
            }

            var b4 = builder.add_sapling_output(outj2);
            console.log(b4);

            /*
            We are now done with adding the shielded outputs to the builder.
            In fact, we are done adding all inputs the builder needs for this transaction.
            We now let the builder build the transaction, including the ZK proofs.
            The builder returns a txdata blob.
            The ledger needs this blob to validate the correctness of the tx.
             */

            const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH);

            /*
            Now the ledger will validate the txdata blob.
            For this, it uses the input from inittx to verify.
            If all checks are ok, the ledger signs the transaction.
             */

            const req6 = await app.checkandsign(ledgerblob_txdata);
            console.log(req6);
            expect(req6.return_code).toEqual(0x9000);

            /*
            Check the hash of the return
            */

            hash = crypto.createHash('sha256');
            hash.update(Buffer.from(ledgerblob_txdata));
            h = hash.digest('hex');
            expect(req6.signdata.toString('hex')).toEqual(h);

            /*
            The builder needs the spend signatures to add it to the transaction blob.
            We need to do this one by one.
            So we first gather all signatures we need.
             */


            const req7 = await app.extractspendsig();
            console.log(req7);
            expect(req7.return_code).toEqual(0x9000);

            /*
            The builder also needs the transparent signature for the transparent input.
             */

            const req9 = await app.extracttranssig();
            console.log(req9);
            expect(req9.return_code).toEqual(0x9000);

            /*
            At this point we gathered all signatures.
            We now add these signaturs to the builder.
            Note that for this transaction, we do not have any transparent signatures.
             */


            const signatures = {
                transparent_sigs: [req9.sig_raw],
                spend_sigs: [req7.sig_raw],
            }

            var b5 = builder.add_signatures(signatures);
            console.log(b5);

            /*
            The builder is now done and the transaction is complete.
             */

            var b6 = builder.finalize();
            console.log(b6);

        } finally {
            await sim.close();
        }
    });

    test('make a transaction with 2 transparent input 2 transparent output', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const {zcashtools} = addon;
            console.log(SPEND_PATH)

            var builder = new zcashtools(1000);

            /*
            In this test, Alice wants to send 10000 ZEC to Bob transparent and send the change back to herself.
             */
            const tin1 = {
                path: [(44 + 0x80000000), (133 + 0x80000000), (5 + 0x80000000), 0 ,0],
                address: "1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac",
                value: 50000,
            }

            const tin2 = {
                path: [(44 + 0x80000000), (133 + 0x80000000), (5 + 0x80000000), 0 ,0],
                address: "1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac",
                value: 50000,
            }

            const tout1 = {
                address: "1976a914000000000000000000000000000000000000000088ac",
                value: 10000,
            }

            const tout2 = {
                address: "1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac",
                value: 100000 - 1000 - 10000,
            }


            const tx_input_data = {
                t_in : [tin1, tin2],
                t_out : [tout1, tout2],
                s_spend: [],
                s_output: [],
            }

            const ledgerblob_initdata = addon.get_inittx_data(tx_input_data);
            console.log(ledgerblob_initdata);


            const reqinit = app.inittx(ledgerblob_initdata);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            //we have to click several times...
            for (let i = 1; i < 2 * clicksTIN + 2 * clicksTOUT + clicksConst; i += 1) {
                await sim.clickRight();
            }
            await sim.clickBoth();

            const req = await reqinit;
            expect(req.return_code).toEqual(0x9000);
            expect(req.txdata.byteLength).toEqual(32);

            let hash = crypto.createHash('sha256');
            hash.update(Buffer.from(ledgerblob_initdata));
            let h = hash.digest('hex');
            expect(req.txdata.toString('hex')).toEqual(h);

            /*
            Now we start building the transaction using the builder.
            */

            const t_data = {
                outp: "000000000000000000000000000000000000000000000000000000000000000000000000",
                pk: "031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e",
                address:tin1.address,
                value:tin1.value,
            }

            var bt0 = builder.add_transparent_input(t_data);
            console.log(bt0);

            const t_data2 = {
                outp: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                pk: "031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e",
                address:tin1.address,
                value:tin1.value,
            }

            var bt0 = builder.add_transparent_input(t_data2);
            console.log(bt0);

            /*
            To add a transparent output, the builder does not need anything other than the input to the inittx.
             */

            var bt1 = builder.add_transparent_output(tout1);
            console.log(bt1);

            var bt2 = builder.add_transparent_output(tout2);
            console.log(bt2);


            const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH);


            const req6 = await app.checkandsign(ledgerblob_txdata);
            console.log(req6);
            expect(req6.return_code).toEqual(0x9000);

            hash = crypto.createHash('sha256');
            hash.update(Buffer.from(ledgerblob_txdata));
            h = hash.digest('hex');
            expect(req6.signdata.toString('hex')).toEqual(h);


            const req9 = await app.extracttranssig();
            console.log(req9);
            expect(req9.return_code).toEqual(0x9000);

            const req10 = await app.extracttranssig();
            console.log(req10);
            expect(req10.return_code).toEqual(0x9000);

            /*
            At this point we gathered all signatures.
            We now add these signaturs to the builder.
            Note that for this transaction, we do not have any transparent signatures.
             */


            const signatures = {
                transparent_sigs: [req9.sig_raw, req10.sig_raw],
                spend_sigs: [],
            }

            var b5 = builder.add_signatures(signatures);
            console.log(b5);

            /*
            The builder is now done and the transaction is complete.
             */

            var b6 = builder.finalize();
            console.log(b6);

        } finally {
            await sim.close();
        }
    });

    test('try to extract spend data without calling inittx', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const req = app.extractspenddata();
            expect(req.return_code).not.toEqual(0x9000);
            expect(req.proofkey).toEqual(undefined);

        } finally {
            await sim.close();
        }
    });

    test('test extracting output without extracting spend data', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const {zcashtools} = addon;
            console.log(SPEND_PATH)

            var builder = new zcashtools(1000);

            /*
            In this test, we try to extract signatures without having done the checks and signing.
             */

            const s_spend1 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 50000,
            }

            const s_spend2 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 50000,
            }

            const s_out1 = {
                address: "15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc",
                value: 55000,
                memo_type: 0xF6,
                ovk: null,
            }

            const s_out2 = {
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 100000-1000-55000,
                memo_type: 0xF6,
                ovk: null,
            }

            const tx_input_data = {
                t_in : [],
                t_out : [],
                s_spend: [s_spend1,s_spend2],
                s_output: [s_out1, s_out2],
            }

            const ledgerblob_initdata = addon.get_inittx_data(tx_input_data);
            console.log(ledgerblob_initdata);

            const reqinit = app.inittx(ledgerblob_initdata);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            //we have to click several times...
            for (let i = 1; i < 2 * clicksSSPEND + 2 * clicksSOUT + clicksConst; i += 1) {
                await sim.clickRight();
            }
            await sim.clickBoth();

            const req = await reqinit;
            expect(req.return_code).toEqual(0x9000);
            expect(req.txdata.byteLength).toEqual(32);

            const req4 = await app.extractoutputdata();
            console.log(req4);
            expect(req4.return_code).not.toEqual(0x9000);



        } finally {
            await sim.close();
        }
    });

    test('test extracting signatures without checkandsign', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const {zcashtools} = addon;
            console.log(SPEND_PATH)

            var builder = new zcashtools(1000);

            /*
            In this test, we try to extract signatures without having done the checks and signing.
             */

            const s_spend1 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 50000,
            }

            const s_spend2 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 50000,
            }

            const s_out1 = {
                address: "15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc",
                value: 55000,
                memo_type: 0xF6,
                ovk: null,

            }

            const s_out2 = {
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 100000-1000-55000,
                memo_type: 0xF6,
                ovk: null,
            }

            const tx_input_data = {
                t_in : [],
                t_out : [],
                s_spend: [s_spend1,s_spend2],
                s_output: [s_out1, s_out2],
            }

            const ledgerblob_initdata = addon.get_inittx_data(tx_input_data);
            console.log(ledgerblob_initdata);

            const reqinit = app.inittx(ledgerblob_initdata);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            //we have to click several times...
            for (let i = 1; i < 2 * clicksSSPEND + 2 * clicksSOUT + clicksConst; i += 1) {
                await sim.clickRight();
            }
            await sim.clickBoth();

            const req = await reqinit;
            expect(req.return_code).toEqual(0x9000);
            expect(req.txdata.byteLength).toEqual(32);


            var req2 = await app.extractspenddata();
            console.log(req2);
            expect(req2.return_code).toEqual(0x9000);
            const expected_proofkey_raw = "4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405";
            expect(req2.key_raw.toString('hex')).toEqual(expected_proofkey_raw);
            expect(req2.rcv_raw).not.toEqual(req2.alpha_raw);

            var req3 = await app.extractspenddata();
            console.log(req3);
            expect(req3.return_code).toEqual(0x9000);
            expect(req3.key_raw.toString('hex')).toEqual(expected_proofkey_raw);


            const req4 = await app.extractoutputdata();
            console.log(req4);
            expect(req4.return_code).toEqual(0x9000);

            const req5 = await app.extractoutputdata();
            console.log(req5);
            expect(req5.return_code).toEqual(0x9000);


            const req7 = await app.extractspendsig();
            console.log(req7);
            expect(req7.return_code).not.toEqual(0x9000);


            const req8 = await app.extracttranssig();
            console.log(req8);
            expect(req8.return_code).not.toEqual(0x9000);



        } finally {
            await sim.close();
        }
    });

    test('test extracting more signatures than needed for tx', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const {zcashtools} = addon;
            console.log(SPEND_PATH)

            var builder = new zcashtools(1000);

            /*
            In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
            For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
            She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
            The inputs to the initialization is therefor:
            - one transparent input and one transparent output
            - one shielded spend notes and two shielded output notes.
            She takes a transaction fee of 10000 and all leftovers is sent shielded to her own address.
            All this info is gathered from the UI and put in the correct jsons.
             */

            const tin1 = {
                path: [(44 + 0x80000000), (133 + 0x80000000), (5 + 0x80000000), 0 ,0],
                address: "1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac",
                value: 60000,
            }

            const tout1 = {
                address: "1976a914000000000000000000000000000000000000000088ac",
                value: 10000,
            }

            const s_spend1 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 40000,
            }

            const s_out1 = {
                address: "15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc",
                value: 55000,
                memo_type: 0xf6,
                ovk: null,
            }

            const s_out2 = {
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 100000-1000-55000 - 10000,
                memo_type: 0xf6,
                ovk: null,
            }

            const tx_input_data = {
                t_in : [tin1],
                t_out : [tout1],
                s_spend: [s_spend1],
                s_output: [s_out1, s_out2],
            }

            /*
            The inputs to the get_inittx_data function are the inputs to the transaction.
            The output is a blob that can be send to the ledger device.
            */

            const ledgerblob_initdata = addon.get_inittx_data(tx_input_data);
            console.log(ledgerblob_initdata);

            /*
            The output of the get_inittx_data can be send to the ledger.
            The ledger will check this data and show the inputs on screen for verification.
            If confirmed, the ledger also computes the randomness needed for :
                - The shielded spends
                - the shielded outputs
             */

            const reqinit = app.inittx(ledgerblob_initdata);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            //we have to click several times...
            for (let i = 1; i < 1 * clicksTIN + 1 * clicksTOUT + 1*clicksSSPEND + 2 * clicksSOUT + clicksConst; i += 1) {
                await sim.clickRight();
            }
            await sim.clickBoth();
            const req = await reqinit;
            expect(req.return_code).toEqual(0x9000);
            expect(req.txdata.byteLength).toEqual(32);

            /*
            Now we start building the transaction using the builder.
            /*

            /*
            To add transparent inputs to the builder, we dont need fresh information from the ledger.
            The builder does need the secp256k1 public key beloging to the address.
             The builder also need outpoint from the blockchain.
             */

            const t_data = {
                outp: "000000000000000000000000000000000000000000000000000000000000000000000000",
                pk: "031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e",
                address:tin1.address,
                value:tin1.value,
            }

            var bt0 = builder.add_transparent_input(t_data);
            console.log(bt0);

            /*
            To add a transparent output, the builder does not need anything other than the input to the inittx.
             */

            var bt1 = builder.add_transparent_output(tout1);
            console.log(bt1);

            /*
           To add a shielded spend to the builder, we need:
               - the proof generation key belonging to the spend address (proofkey)
               - the randomness needed for the value commitment (rcv)
               - the randomness needed for the random verification key (alpha)
           All this is retrieved from the ledger using a extractspenddata call with no inputs.
           The ledger already knows how much data it needs to send after the inittx call.
           */

            var req2 = await app.extractspenddata();
            console.log(req2);
            expect(req2.return_code).toEqual(0x9000);
            const expected_proofkey_raw = "4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405";
            expect(req2.key_raw.toString('hex')).toEqual(expected_proofkey_raw);
            expect(req2.rcv_raw).not.toEqual(req2.alpha_raw);

            /*
            The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
            It CAN send along an outgoing viewing key (OVK), can also be all zero's.
            It furthermore uses the spend address and value from the UI.
             */

            var spendj1 = {
                proofkey: req2.key_raw,
                rcv: req2.rcv_raw,
                alpha: req2.alpha_raw,
                address: s_spend1.address,
                value: s_spend1.value,
                witness: "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                rseed: "0000000000000000000000000000000000000000000000000000000000000000"
            };

            /*
            The builder adds the spend to its state.
             */

            var b1 = builder.add_sapling_spend(spendj1);
            console.log(b1);

            /*
            At this point we added all spends.
            We cannot get more spend data from the ledger.
            We now start the shielded output process.
             */

            /*
           To add a shielded output to the builder, we need:
               - the randomness needed for the value commitment (rcv)
               - the randomness needed for the note commitment (rcm)
               - the randomness needed for the random encryption key (esk)
           All this is retrieved from the ledger using a extractoutputdata call with no inputs.
           The ledger already knows how much data it needs to send after the inittx call.
           */

            const req4 = await app.extractoutputdata();
            console.log(req4);
            expect(req4.return_code).toEqual(0x9000);

            /*
            The builder needs the data retrieved from the ledger (rcv, rcm, esk)
            It CAN send along an outgoing viewing key (OVK), can also be all zero's.
            It furthermore uses the output address, value and memo from the UI.
            */

            var outj1 = {
                rcv: req4.rcv_raw,
                rseed: req4.rseed_raw,
                ovk: null,
                address: s_out1.address,
                value: s_out1.value,
                memo: "0000"
            }

            /*
            The builder adds the shielded output to its state.
             */

            var b3 = builder.add_sapling_output(outj1);
            console.log(b3);

            /*
            This process needs to be repeated for the second output.
            Note that this output address belongs to Alice.
             */

            const req5 = await app.extractoutputdata();
            console.log(req5);
            expect(req5.return_code).toEqual(0x9000);

            var outj2 = {
                rcv: req5.rcv_raw,
                rseed: req5.rseed_raw,
                ovk: null,
                address: s_out2.address,
                value: s_out2.value,
                memo: "0000"
            }

            var b4 = builder.add_sapling_output(outj2);
            console.log(b4);

            /*
            We are now done with adding the shielded outputs to the builder.
            In fact, we are done adding all inputs the builder needs for this transaction.
            We now let the builder build the transaction, including the ZK proofs.
            The builder returns a txdata blob.
            The ledger needs this blob to validate the correctness of the tx.
             */

            const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH);

            /*
            Now the ledger will validate the txdata blob.
            For this, it uses the input from inittx to verify.
            If all checks are ok, the ledger signs the transaction.
             */

            const req6 = await app.checkandsign(ledgerblob_txdata);
            console.log(req6);
            expect(req6.return_code).toEqual(0x9000);

            /*
            The builder needs the spend signatures to add it to the transaction blob.
            We need to do this one by one.
            So we first gather all signatures we need.
             */


            const req7 = await app.extractspendsig();
            console.log(req7);
            expect(req7.return_code).toEqual(0x9000);

            /*
            The builder also needs the transparent signature for the transparent input.
             */

            const req9 = await app.extracttranssig();
            console.log(req9);
            expect(req9.return_code).toEqual(0x9000);

            /*
            At this point we gathered all signatures.
            We now add these signaturs to the builder.
            Note that for this transaction, we do not have any transparent signatures.
             */

            /*
            Below are the failing extractions
             */

            const req10 = await app.extractspendsig();
            console.log(req10);
            expect(req10.return_code).not.toEqual(0x9000);


            const req11 = await app.extracttranssig();
            console.log(req11);
            expect(req11.return_code).not.toEqual(0x9000);

        } finally {
            await sim.close();
        }
    });

    test('test not using ledger randomness for tx', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const {zcashtools} = addon;
            console.log(SPEND_PATH)

            var builder = new zcashtools(1000);

            /*
            In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
            For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
            She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
            The inputs to the initialization is therefor:
            - one transparent input and one transparent output
            - one shielded spend notes and two shielded output notes.
            She takes a transaction fee of 10000 and all leftovers is sent shielded to her own address.
            All this info is gathered from the UI and put in the correct jsons.
             */

            const tin1 = {
                path: [(44 + 0x80000000), (133 + 0x80000000), (5 + 0x80000000), 0 ,0],
                address: "1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac",
                value: 60000,
            }

            const tout1 = {
                address: "1976a914000000000000000000000000000000000000000088ac",
                value: 10000,
            }

            const s_spend1 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 40000,
            }

            const s_out1 = {
                address: "15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc",
                value: 55000,
                memo_type: 0xf6,
                ovk: null,
            }

            const s_out2 = {
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 100000-1000-55000 - 10000,
                memo_type: 0xf6,
                ovk: null,
            }

            const tx_input_data = {
                t_in : [tin1],
                t_out : [tout1],
                s_spend: [s_spend1],
                s_output: [s_out1, s_out2],
            }

            /*
            The inputs to the get_inittx_data function are the inputs to the transaction.
            The output is a blob that can be send to the ledger device.
            */

            const ledgerblob_initdata = addon.get_inittx_data(tx_input_data);
            console.log(ledgerblob_initdata);

            /*
            The output of the get_inittx_data can be send to the ledger.
            The ledger will check this data and show the inputs on screen for verification.
            If confirmed, the ledger also computes the randomness needed for :
                - The shielded spends
                - the shielded outputs
             */


            const reqinit = app.inittx(ledgerblob_initdata);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            //we have to click several times...
            for (let i = 1; i < 1 * clicksTIN + 1 * clicksTOUT + 1*clicksSSPEND + 2 * clicksSOUT + clicksConst; i += 1) {
                await sim.clickRight();
            }
            await sim.clickBoth();
            const req = await reqinit;
            expect(req.return_code).toEqual(0x9000);
            expect(req.txdata.byteLength).toEqual(32);

            /*
            Now we start building the transaction using the builder.
            /*

            /*
            To add transparent inputs to the builder, we dont need fresh information from the ledger.
            The builder does need the secp256k1 public key beloging to the address.
             The builder also need outpoint from the blockchain.
             */

            const t_data = {
                outp: "000000000000000000000000000000000000000000000000000000000000000000000000",
                pk: "031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e",
                address:tin1.address,
                value:tin1.value,
            }

            var bt0 = builder.add_transparent_input(t_data);
            console.log(bt0);

            /*
            To add a transparent output, the builder does not need anything other than the input to the inittx.
             */

            var bt1 = builder.add_transparent_output(tout1);
            console.log(bt1);

            /*
           To add a shielded spend to the builder, we need:
               - the proof generation key belonging to the spend address (proofkey)
               - the randomness needed for the value commitment (rcv)
               - the randomness needed for the random verification key (alpha)
           All this is retrieved from the ledger using a extractspenddata call with no inputs.
           The ledger already knows how much data it needs to send after the inittx call.
           */

            var req2 = await app.extractspenddata();
            console.log(req2);
            expect(req2.return_code).toEqual(0x9000);
            const expected_proofkey_raw = "4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405";
            expect(req2.key_raw.toString('hex')).toEqual(expected_proofkey_raw);
            expect(req2.rcv_raw).not.toEqual(req2.alpha_raw);

            /*
            The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
            It CAN send along an outgoing viewing key (OVK), can also be all zero's.
            It furthermore uses the spend address and value from the UI.
             */

            var spendj1 = {
                proofkey: req2.key_raw,
                rcv: req2.rcv_raw,
                alpha: req2.alpha_raw,
                address: s_spend1.address,
                value: s_spend1.value,
                witness: "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                rseed: "0000000000000000000000000000000000000000000000000000000000000000"
            };

            /*
            The builder adds the spend to its state.
             */

            var b1 = builder.add_sapling_spend(spendj1);
            console.log(b1);

            /*
            At this point we added all spends.
            We cannot get more spend data from the ledger.
            We now start the shielded output process.
             */

            /*
           To add a shielded output to the builder, we need:
               - the randomness needed for the value commitment (rcv)
               - the randomness needed for the note commitment (rcm)
               - the randomness needed for the random encryption key (esk)
           All this is retrieved from the ledger using a extractoutputdata call with no inputs.
           The ledger already knows how much data it needs to send after the inittx call.
           */

            const req4 = await app.extractoutputdata();
            console.log(req4);
            expect(req4.return_code).toEqual(0x9000);

            /*
            The builder needs the data retrieved from the ledger (rcv, rcm, esk)
            It CAN send along an outgoing viewing key (OVK), can also be all zero's.
            It furthermore uses the output address, value and memo from the UI.
            */

            var outj1 = {
                rcv: req4.rcv_raw,
                rseed: req4.rseed_raw,
                ovk: null,
                address: s_out1.address,
                value: s_out1.value,
                memo: "0000"
            }

            /*
            The builder adds the shielded output to its state.
             */

            var b3 = builder.add_sapling_output(outj1);
            console.log(b3);

            /*
            This process needs to be repeated for the second output.
            Note that this output address belongs to Alice.
             */

            const req5 = await app.extractoutputdata();
            console.log(req5);
            expect(req5.return_code).toEqual(0x9000);

            /*
            Here we use the wrong rseed!!
             */

            var outj2 = {
                rcv: req5.rcv_raw,
                rseed: req5.rcv_raw,
                ovk: "6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca",
                address: s_out2.address,
                value: s_out2.value,
                memo: "0000"
            }

            var b4 = builder.add_sapling_output(outj2);
            console.log(b4);

            /*
            We are now done with adding the shielded outputs to the builder.
            In fact, we are done adding all inputs the builder needs for this transaction.
            We now let the builder build the transaction, including the ZK proofs.
            The builder returns a txdata blob.
            The ledger needs this blob to validate the correctness of the tx.
             */

            const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH);

            /*
            Now the ledger will validate the txdata blob.
            For this, it uses the input from inittx to verify.
            If all checks are ok, the ledger signs the transaction.
             */

            const req6 = await app.checkandsign(ledgerblob_txdata);
            console.log(req6);
            expect(req6.return_code).not.toEqual(0x9000);



        } finally {
            await sim.close();
        }
    });

    test('test use other address in builder than in inittx', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const {zcashtools} = addon;
            console.log(SPEND_PATH)

            var builder = new zcashtools(1000);

            /*
            In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
            For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
            She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
            The inputs to the initialization is therefor:
            - one transparent input and one transparent output
            - one shielded spend notes and two shielded output notes.
            She takes a transaction fee of 10000 and all leftovers is sent shielded to her own address.
            All this info is gathered from the UI and put in the correct jsons.
             */

            const tin1 = {
                path: [(44 + 0x80000000), (133 + 0x80000000), (5 + 0x80000000), 0 ,0],
                address: "1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac",
                value: 60000,
            }

            const tout1 = {
                address: "1976a914000000000000000000000000000000000000000088ac",
                value: 10000,
            }

            const s_spend1 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 40000,
            }

            const s_out1 = {
                address: "15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc",
                value: 55000,
                memo_type: 0xf6,
                ovk: null,
            }

            const s_out2 = {
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 100000-1000-55000 - 10000,
                memo_type: 0xf6,
                ovk: null,
            }

            const tx_input_data = {
                t_in : [tin1],
                t_out : [tout1],
                s_spend: [s_spend1],
                s_output: [s_out1, s_out2],
            }

            /*
            The inputs to the get_inittx_data function are the inputs to the transaction.
            The output is a blob that can be send to the ledger device.
            */

            const ledgerblob_initdata = addon.get_inittx_data(tx_input_data);
            console.log(ledgerblob_initdata);

            /*
            The output of the get_inittx_data can be send to the ledger.
            The ledger will check this data and show the inputs on screen for verification.
            If confirmed, the ledger also computes the randomness needed for :
                - The shielded spends
                - the shielded outputs
             */

            const reqinit = app.inittx(ledgerblob_initdata);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            //we have to click several times...
            for (let i = 1; i < 1 * clicksTIN + 1 * clicksTOUT + 1*clicksSSPEND + 2 * clicksSOUT + clicksConst; i += 1) {
                await sim.clickRight();
            }
            await sim.clickBoth();
            const req = await reqinit;
            expect(req.return_code).toEqual(0x9000);
            expect(req.txdata.byteLength).toEqual(32);

            /*
            Now we start building the transaction using the builder.
            /*

            /*
            To add transparent inputs to the builder, we dont need fresh information from the ledger.
            The builder does need the secp256k1 public key beloging to the address.
             The builder also need outpoint from the blockchain.
             */

            const t_data = {
                outp: "000000000000000000000000000000000000000000000000000000000000000000000000",
                pk: "031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e",
                address:tin1.address,
                value:tin1.value,
            }

            var bt0 = builder.add_transparent_input(t_data);
            console.log(bt0);

            /*
            To add a transparent output, the builder does not need anything other than the input to the inittx.
             */

            var bt1 = builder.add_transparent_output(tout1);
            console.log(bt1);

            /*
           To add a shielded spend to the builder, we need:
               - the proof generation key belonging to the spend address (proofkey)
               - the randomness needed for the value commitment (rcv)
               - the randomness needed for the random verification key (alpha)
           All this is retrieved from the ledger using a extractspenddata call with no inputs.
           The ledger already knows how much data it needs to send after the inittx call.
           */

            var req2 = await app.extractspenddata();
            console.log(req2);
            expect(req2.return_code).toEqual(0x9000);
            const expected_proofkey_raw = "4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405";
            expect(req2.key_raw.toString('hex')).toEqual(expected_proofkey_raw);
            expect(req2.rcv_raw).not.toEqual(req2.alpha_raw);

            /*
            The builder needs the data retrieved from the ledger (proofkey, rcv, alpha)
            It CAN send along an outgoing viewing key (OVK), can also be all zero's.
            It furthermore uses the spend address and value from the UI.
             */

            var spendj1 = {
                proofkey: req2.key_raw,
                rcv: req2.rcv_raw,
                alpha: req2.alpha_raw,
                address: s_spend1.address,
                value: s_spend1.value,
                witness: "01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000",
                rseed: "0000000000000000000000000000000000000000000000000000000000000000"
            };

            /*
            The builder adds the spend to its state.
             */

            var b1 = builder.add_sapling_spend(spendj1);
            console.log(b1);

            /*
            At this point we added all spends.
            We cannot get more spend data from the ledger.
            We now start the shielded output process.
             */

            /*
           To add a shielded output to the builder, we need:
               - the randomness needed for the value commitment (rcv)
               - the randomness needed for the note commitment (rcm)
               - the randomness needed for the random encryption key (esk)
           All this is retrieved from the ledger using a extractoutputdata call with no inputs.
           The ledger already knows how much data it needs to send after the inittx call.
           */

            const req4 = await app.extractoutputdata();
            console.log(req4);
            expect(req4.return_code).toEqual(0x9000);

            /*
            The builder needs the data retrieved from the ledger (rcv, rcm, esk)
            It CAN send along an outgoing viewing key (OVK), can also be all zero's.
            It furthermore uses the output address, value and memo from the UI.
            */

            var outj1 = {
                rcv: req4.rcv_raw,
                rseed: req4.rseed_raw,
                ovk: null,
                address: s_out1.address,
                value: s_out1.value,
                memo: "0000"
            }

            /*
            The builder adds the shielded output to its state.
             */

            var b3 = builder.add_sapling_output(outj1);
            console.log(b3);

            /*
            This process needs to be repeated for the second output.
            Note that this output address belongs to Alice.
             */

            const req5 = await app.extractoutputdata();
            console.log(req5);
            expect(req5.return_code).toEqual(0x9000);

            /*
            Here we use the wrong address and send the change funds to Bob instead.
             */

            var outj2 = {
                rcv: req5.rcv_raw,
                rseed: req5.rseed_raw,
                ovk: "6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca",
                address: s_out1.address,
                value: s_out2.value,
                memo: "0000"
            }

            var b4 = builder.add_sapling_output(outj2);
            console.log(b4);

            /*
            We are now done with adding the shielded outputs to the builder.
            In fact, we are done adding all inputs the builder needs for this transaction.
            We now let the builder build the transaction, including the ZK proofs.
            The builder returns a txdata blob.
            The ledger needs this blob to validate the correctness of the tx.
             */

            const ledgerblob_txdata = builder.build(SPEND_PATH, OUTPUT_PATH);

            /*
            Now the ledger will validate the txdata blob.
            For this, it uses the input from inittx to verify.
            If all checks are ok, the ledger signs the transaction.
             */

            const req6 = await app.checkandsign(ledgerblob_txdata);
            console.log(req6);
            expect(req6.return_code).not.toEqual(0x9000);

        } finally {
            await sim.close();
        }
    });

    test('try txfee of 10000', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            /*
            In this test, Alice wants to send 55000 ZEC to Bob shielded and 10000 ZEC to Charlie transparent.
            For this she needs one notes of 40000 ZEC sent to her address belonging to path: 1000.
            She also uses a transparent input with 60000 ZEC belonging to transparent path: 0.
            The inputs to the initialization is therefor:
            - one transparent input and one transparent output
            - one shielded spend notes and two shielded output notes.
            She takes a transaction fee of 10000 and all leftovers is sent shielded to her own address.
            All this info is gathered from the UI and put in the correct jsons.
             */

            const tin1 = {
                path: [(44 + 0x80000000), (133 + 0x80000000), (5 + 0x80000000), 0 ,0],
                address: "1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac",
                value: 60000,
            }

            const tout1 = {
                address: "1976a914000000000000000000000000000000000000000088ac",
                value: 10000,
            }

            const s_spend1 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 40000,
            }

            const s_out1 = {
                address: "15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc",
                value: 55000,
                memo_type: 0xf6,
                ovk: null,
            }

            const s_out2 = {
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 100000-10000-55000 - 10000,
                memo_type: 0xf6,
                ovk: null,
            }

            const tx_input_data = {
                t_in : [tin1],
                t_out : [tout1],
                s_spend: [s_spend1],
                s_output: [s_out1, s_out2],
            }

            /*
            The inputs to the get_inittx_data function are the inputs to the transaction.
            The output is a blob that can be send to the ledger device.
            */

            const ledgerblob_initdata = addon.get_inittx_data(tx_input_data);
            console.log(ledgerblob_initdata);

            /*
            The output of the get_inittx_data can be send to the ledger.
            The ledger will check this data and show the inputs on screen for verification.
            If confirmed, the ledger also computes the randomness needed for :
                - The shielded spends
                - the shielded outputs
             */

            const reqinit = app.inittx(ledgerblob_initdata);

            const req = await reqinit;

            console.log(req);
            expect(req.returnCode).not.toEqual(0x9000);

        } finally {
            await sim.close();
        }
    });

    test('extract data after tx reject', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const {zcashtools} = addon;
            console.log(SPEND_PATH)

            var builder = new zcashtools(1000);

            /*
            In this test, Alice wants to send 55000 ZEC to Bob.
            For this she needs two notes of 50000 ZEC sent to her address belonging to path: 1000.
            The inputs to the initialization is therefor two spend notes and two output notes.
            She takes a transaction fee of 1000.
            All this info is gathered from the UI and put in the correct jsons.
             */

            const s_spend1 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 50000,
            }

            const s_spend2 = {
                path: 1000,
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 50000,
            }

            const s_out1 = {
                address: "15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc",
                value: 55000,
                memo_type: 0xf6,
                ovk: null,
            }

            const s_out2 = {
                address: "c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667",
                value: 100000-1000-55000,
                memo_type: 0xf6,
                ovk: null,
            }

            const tx_input_data = {
                t_in : [],
                t_out : [],
                s_spend: [s_spend1,s_spend2],
                s_output: [s_out1, s_out2],
            }

            /*
            The inputs to the get_inittx_data function are the inputs to the transaction.
            The output is a blob that can be send to the ledger device.
            */

            const ledgerblob_initdata = addon.get_inittx_data(tx_input_data);
            console.log(ledgerblob_initdata);

            /*
            The output of the get_inittx_data can be send to the ledger.
            The ledger will check this data and show the inputs on screen for verification.
            If confirmed, the ledger also computes the randomness needed for :
                - The shielded spends
                - the shielded outputs
             */

            const reqinit = app.inittx(ledgerblob_initdata);

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
            //we have to click several times...
            for (let i = 1; i < 2*clicksSSPEND + 2 * clicksSOUT + clicksConst + 1; i += 1) {
                await sim.clickRight();
            }
            await sim.clickBoth();

            const req = await reqinit;

            console.log(req);
            expect(req.return_code).not.toEqual(0x9000);

            /*
            Try to extract data after a rejection of a transaction
             */

            const req0 = await app.extractspenddata();
            console.log(req0);
            expect(req0.return_code).not.toEqual(0x9000);

            const req1 = await app.extractoutputdata();
            console.log(req1);
            expect(req1.return_code).not.toEqual(0x9000);


        } finally {
            await sim.close();
        }
    });


});
