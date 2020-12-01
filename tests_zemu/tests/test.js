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

            const addr = await app.getAddressAndPubKey("m/44'/133'/5'/0/1000");
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

    test('show shielded address', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            const addrRequest = app.showAddressAndPubKey("m/44'/133'/5'/0'/1000");
            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.clickRight();
            await sim.clickRight();
            await sim.clickRight();
            await sim.clickBoth();

            const addr = await addrRequest;
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

});
