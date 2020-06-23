import Zemu from "@zondax/zemu";
import ZCashApp from "@zondax/ledger-zcash";
import path from "path";

const APP_PATH = path.resolve(`./../../app/bin/app.elf`);

const seed = "equip will roof matter pink blind book anxiety banner elbow sun young"
const SIM_OPTIONS = {
    logging: true,
    start_delay: 4000,
//    X11: true,
    custom: `-s "${seed}" --color LAGOON_BLUE`
};

async function beforeStart() {
    process.on("SIGINT", () => {
        Zemu.default.stopAllEmuContainers(function () {
            process.exit();
        });
    });
    await Zemu.default.checkAndPullImage();
}

async function beforeEnd() {
    await Zemu.default.stopAllEmuContainers();
}

async function debugScenario1(sim, app) {
    // Here you can customize what you want to do :)
    const addrRequest = app.showAddressAndPubKey("m/44'/133'/5'/0/0");

    await Zemu.default.sleep(1000);
    // await sim.clickRight();
    await sim.clickBoth();

    const addr = await addrRequest;
    console.log(addr)

    // From https://iancoleman.io/bip39/
    const expected_pk = "cf99b502893ec7f2a2d275857abfea9848ca284e20530c410bfc133322a84d8326129c9dd39829bf65cd41";
    const expected_addr = "zs1e7vm2q5f8mrl9gkjwkzh40l2npyv52zwypfscsgtlsfnxg4gfkpjvy5unhfes2dlvhx52ywndr";

    if (addr.return_code !== 0x9000) {
        console.log("INVALID RESPONSE")
        return;
    }

    const pk = addr.address_raw.toString('hex');
    console.log(pk)
    if (expected_pk !== pk) {
        console.log("INCORRECT PK!")
    }

    console.log(addr.address)
    if (expected_addr !== addr.address) {
        console.log("INVALID ADDRESS!")
    }
}

async function debugScenario2(sim, app) {
    // Here you can customize what you want to do :)
    // Do not await.. we need to click asynchronously
    const signatureRequest = app.sign("m/44'/133'/5'/0/0", "1234");
    await Zemu.default.sleep(2000);

    // Click right + double
    await sim.clickRight();
    await sim.clickBoth();

    let signature = await signatureRequest;
    console.log(signature)
}

async function debugScenario3(sim, app) {
    // Here you can customize what you want to do :)
    const addrRequest = await app.getAddressAndPubKey("m/44'/133'/5'/0/0");
    console.log(addrRequest)
}

async function debugScenario4(sim, app) {
    // Here you can customize what you want to do :)
    // Do not await.. we need to click asynchronously
    const blob = Buffer.from("010000000107578c9aff7cfd240c36fa1400ee130d540f4c3397d24e8bea50a7f061116a87010000006a473044022011aecead8f48e3b342856a8da2f30c4e05bec5dc147a5bc7b382d01bf68ae5c302204126fd77522ae311a88688bce967532456b08c94322ba182a18fb7786e696c610121027e563beec6765850071067e4fcc7a46d00cbb0d675ef8df1b8d15aaeef91a21fffffffff021cbb0100000000001976a91461aac8b58ac880a45fb06eeedfcf3017679778a988ac32432400000000001976a9144fc16e1766808c0ab090be4376cea9d3a0bbe12988ac00000000", "hex");
    const signatureRequest = app.sign("m/44'/133'/5'/0/0", blob);
    await Zemu.default.sleep(1000);

    // Click right + double
    await sim.clickRight();
    await sim.clickBoth();
    await sim.clickRight();

    let signature = await signatureRequest;
    console.log(signature)
}

async function main() {
    await beforeStart();

    if (process.argv.length > 2 && process.argv[2] === "debug") {
        SIM_OPTIONS["custom"] = SIM_OPTIONS["custom"] + " --debug";
    }

    const sim = new Zemu.default(APP_PATH);

    try {
        await sim.start(SIM_OPTIONS);
        const app = new ZCashApp.default(sim.getTransport());

        ////////////
        /// TIP you can use zemu commands here to take the app to the point where you trigger a breakpoint

        await debugScenario1(sim, app);

        /// TIP

    } finally {
        await sim.close();
        await beforeEnd();
    }
}

(async () => {
    await main();
})();
