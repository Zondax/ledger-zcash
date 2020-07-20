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

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const sim_options = {
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`
    ,X11: true
};

jest.setTimeout(20000)

describe('Basic checks', function () {
    test('can start and stop container', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
        } finally {
            await sim.close();
        }
    });

    test('get app version', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());
            const version = await app.getVersion();
            expect(version.return_code).toEqual(0x9000);

            console.log(version)
        } finally {
            await sim.close();
        }
    });

    test('get unshielded address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const addr = await app.getAddressAndPubKey("m/44'/133'/5'/0/0", true);
            console.log(addr)
            expect(addr.return_code).toEqual(0x9000);

            const expected_addr_raw = "031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e";
            const expected_addr = "t1KHG39uhsssPkYcAXkzZ5Bk2w1rnFukZvx";

            const addr_raw = addr.address_raw.toString('hex');
            expect(addr_raw).toEqual(expected_addr_raw);
            expect(addr.address).toEqual(expected_addr);

        } finally {
            await sim.close();
        }
    });

    test('show unshielded address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/133'/5'/0/1", true);
            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const addr = await addrRequest;
            console.log(addr)
            expect(addr.return_code).toEqual(0x9000);

            const expected_addr_raw = "026f27818e7426a10773226b3553d0afe50a3697bd02652f1b57d67bf648577d11";
            const expected_addr = "t1PYLcQqpxou9Eak4nroMNGKYoxT4HPdHqJ";

            const addr_raw = addr.address_raw.toString('hex');
            expect(addr_raw).toEqual(expected_addr_raw);
            expect(addr.address).toEqual(expected_addr);

        } finally {
            await sim.close();
        }
    });

    test('get shielded address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const addr = await app.getAddressAndPubKey("m/44'/133'/5'/0/0");
            console.log(addr)
            expect(addr.return_code).toEqual(0x9000);

            const expected_addr_raw = "fa73b4c8ef0b7b49bb3c94bf2e1df1b27fbf73bb9599cf747714d1fa8b3bf2fb8fe600aca010f875b6ea53";
            const expected_addr = "zs1lfemfj80pda5nweujjlju803kflm7uamjkvu7arhzngl4zem7taclesq4jspp7r4km49xhd74ga";

            const addr_raw = addr.address_raw.toString('hex');
            expect(addr_raw).toEqual(expected_addr_raw);
            expect(addr.address).toEqual(expected_addr);

        } finally {
            await sim.close();
        }
    });

    test('show shielded address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/133'/5'/0'/1");
            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const addr = await addrRequest;
            console.log(addr)
            expect(addr.return_code).toEqual(0x9000);

            const expected_addr_raw = "fa73b4c8ef0b7b49bb3c94bf2e1df1b27fbf73bb9599cf747714d1fa8b3bf2fb8fe600aca010f875b6ea53";
            const expected_addr = "zs1lfemfj80pda5nweujjlju803kflm7uamjkvu7arhzngl4zem7taclesq4jspp7r4km49xhd74ga";

            const addr_raw = addr.address_raw.toString('hex');
            expect(addr_raw).toEqual(expected_addr_raw);
            expect(addr.address).toEqual(expected_addr);

        } finally {
            await sim.close();
        }
    });

    // This test tries to demonstrate
    // the functionality of the unshielded raw transaction
    // parser for an input transaction with 1 input and two outputs
    test('sign unshielded transaction with 1 input - 2 output', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());
            const blob = Buffer.from("010000000107578c9aff7cfd240c36fa1400ee130d540f4c3397d24e8bea50a7f061116a87010000006a473044022011aecead8f48e3b342856a8da2f30c4e05bec5dc147a5bc7b382d01bf68ae5c302204126fd77522ae311a88688bce967532456b08c94322ba182a18fb7786e696c610121027e563beec6765850071067e4fcc7a46d00cbb0d675ef8df1b8d15aaeef91a21fffffffff021cbb0100000000001976a91461aac8b58ac880a45fb06eeedfcf3017679778a988ac32432400000000001976a9144fc16e1766808c0ab090be4376cea9d3a0bbe12988ac00000000", "hex");
            const signatureRequest = app.sign("m/44'/133'/5'/0/0", blob);
            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            // Click right + double
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            let signature = await signatureRequest;
            console.log(signature)

            expect(signature.return_code).toEqual(0x9000);
        } finally {
            await sim.close();
        }
    });

});
