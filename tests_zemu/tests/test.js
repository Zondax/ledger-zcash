import { expect, test } from "jest";
import Zemu from "@zondax/zemu";
import ZCashApp from "@zondax/ledger-zcash";

const Resolve = require("path").resolve;
const APP_PATH = Resolve("../app/bin/app.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"
const sim_options = {
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`
//    ,X11: true
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
            await Zemu.sleep(1000);
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
            const expected_addr = "zs1lfemfj80pda5nweujjlju803kflm7uamjkvu7arhzngl4zem7taclesq4jspp7r4km49lpwx5l";

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
            await Zemu.sleep(1000);
            await sim.clickBoth();

            const addr = await addrRequest;
            console.log(addr)
            expect(addr.return_code).toEqual(0x9000);

            const expected_addr_raw = "fa73b4c8ef0b7b49bb3c94bf2e1df1b27fbf73bb9599cf747714d1fa8b3bf2fb8fe600aca010f875b6ea53";
            const expected_addr = "zs1lfemfj80pda5nweujjlju803kflm7uamjkvu7arhzngl4zem7taclesq4jspp7r4km49lpwx5l";

            const addr_raw = addr.address_raw.toString('hex');
            expect(addr_raw).toEqual(expected_addr_raw);
            expect(addr.address).toEqual(expected_addr);

        } finally {
            await sim.close();
        }
    });

    test('sign unshielded', async function () {
        const sim = new Zemu(APP_PATH);
        try {
            await sim.start(sim_options);
            const app = new ZCashApp(sim.getTransport());

            // Do not await.. we need to click asynchronously
            const signatureRequest = app.sign("m/44'/133'/5'/0/0", "1234");
            await Zemu.sleep(2000);

            await sim.clickBoth();

            let signature = await signatureRequest;
            console.log(signature)

            expect(signature.return_code).toEqual(0x9000);
        } finally {
            await sim.close();
        }
    });

});
