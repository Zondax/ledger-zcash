import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import { listen } from '@ledgerhq/logs'
import ZCashApp from '@zondax/ledger-zcash'
import { get_inittx_data, ZcashBuilderBridge } from '@zondax/zcashtools'
import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { resolve as Resolve } from 'node:path'
import { TX_INPUT_DATA, TxInputData } from './tests/vectors'

const SPEND_PATH = Resolve('../zcashtools/params/sapling-spend.params')
const OUTPUT_PATH = Resolve('../zcashtools/params/sapling-output.params')
const tx_version = 0x05

async function test(app: ZCashApp, tx_init_data: TxInputData): Promise<Buffer> {
  const tx_init_data_blob = get_inittx_data(tx_init_data);
  const builder = new ZcashBuilderBridge(1000);

  const init = await app.inittx(tx_init_data_blob);
  assert.equal(init.return_code, 0x9000);

  var hasher = createHash('sha256');
  hasher.update(Buffer.from(tx_init_data_blob));

  var hash = hasher.digest('hex')
  assert.equal(init.txdata.toString('hex'), hash);

  for (const tinData of tx_init_data.t_in) {
    const input = {
      outp: '000000000000000000000000000000000000000000000000000000000000000000000000',
      pk: '031f6d238009787c20d5d7becb6b6ad54529fc0a3fd35088e85c2c3966bfec050e',
      address: tinData.address,
      value: tinData.value,
    };
    builder.add_transparent_input(input)
  }

  for (const toutData of tx_init_data.t_out) {
    const output = {
      address: toutData.address,
      value: toutData.value,
    };
    builder.add_transparent_output(output);
  }

  const expected_proofkey_raw =
    '4e005f180dab2f445ab109574fd2695e705631cd274b4f58e2b53bb3bc73ed5a3caddba8e4daddf42f11ca89e4961ae3ddc41b3bdd08c36d5a7dfcc30839d405'

  for (const spendData of tx_init_data.s_spend) {
    const spend = await app.extractspenddata();
    assert.equal(spend.return_code, 0x9000);
    assert.equal(spend.key_raw.toString('hex'), expected_proofkey_raw)
    assert.notEqual(spend.rcv_raw, spend.alpha_raw)

    const spendj = {
      proofkey: spend.key_raw,
      rcv: spend.rcv_raw,
      alpha: spend.alpha_raw,
      address: spendData.address,
      value: spendData.value,
      witness: '01305aef35a6fa9dd43af22d2557f99268fbab70a53e963fa67fc762391510406000000000',
      rseed: '0000000000000000000000000000000000000000000000000000000000000000',
    };
    builder.add_sapling_spend(spendj);
  }

  for (const outData of tx_init_data.s_output) {
    const out = await app.extractoutputdata()
    assert.equal(out.return_code, 0x9000);

    const outj = {
      rcv: out.rcv_raw,
      rseed: out.rseed_raw,
      ovk: outData.ovk,
      address: outData.address,
      value: outData.value,
      memo: '0000',
      hash_seed: out.hash_seed
    };
    builder.add_sapling_output(outj)
  }


  const txdata_blob = builder.build(SPEND_PATH, OUTPUT_PATH, tx_version);

  const checkAndSign = await app.checkandsign(txdata_blob, tx_version);
  assert.equal(checkAndSign.return_code, 0x9000);

  hasher = createHash('sha256');
  hasher.update(Buffer.from(txdata_blob))
  hash = hasher.digest('hex');
  assert.equal(checkAndSign.signdata.toString('hex'), hash);

  var signatures = { transparent_sigs: [] as string[], spend_sigs: [] as string[] };

  for (let i = 0; i < tx_init_data.t_in.length; i++) {
    const sig = await app.extracttranssig()
    assert.equal(sig.return_code, 0x9000)

    signatures.transparent_sigs[i] = sig.sig_raw;
  }

  for (let i = 0; i < tx_init_data.s_spend.length; i++) {
    const sig = await app.extractspendsig()
    assert.equal(sig.return_code, 0x9000)

    signatures.spend_sigs[i] = sig.sig_raw;
  }

  builder.add_signatures(signatures)

  const tx = builder.finalize();
  console.log(`Final transaction payload: ${tx.toString('hex')}`);
  return tx;
}

async function main() {
  const transport = await TransportNodeHid.open(null);
  listen((log) => {
    console.log(`${log.type} ${log.message}`)
  });
  const app = new ZCashApp(transport);

  for (const input of TX_INPUT_DATA) {
    await test(app, input);
  }
}

; (async () => {
  await main()
})()
