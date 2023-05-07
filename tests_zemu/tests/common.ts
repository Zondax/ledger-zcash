import { IDeviceModel } from '@zondax/zemu'

const Resolve = require('path').resolve

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/x_app.elf')
const APP_PATH_SP = Resolve('../app/output/app_s2.elf')

export const models: IDeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
]

export const SPEND_PATH = Resolve('../zcashtools/params/sapling-spend.params')
export const OUTPUT_PATH = Resolve('../zcashtools/params/sapling-output.params')

export const TX_TESTS = {
  parser_unshielded_tests: [
    {
      name: 'one_input_two_output',
      raw_tx:
        '010000000107578c9aff7cfd240c36fa1400ee130d540f4c3397d24e8bea50a7f061116a87010000006a473044022011aecead8f48e3b342856a8da2f30c4e05bec5dc147a5bc7b382d01bf68ae5c302204126fd77522ae311a88688bce967532456b08c94322ba182a18fb7786e696c610121027e563beec6765850071067e4fcc7a46d00cbb0d675ef8df1b8d15aaeef91a21fffffffff021cbb0100000000001976a91461aac8b58ac880a45fb06eeedfcf3017679778a988ac32432400000000001976a9144fc16e1766808c0ab090be4376cea9d3a0bbe12988ac00000000',
      addresses: ['19uR8tabimmJ9fhytbz74foP8wepgxksnE', '18Gi6umH8FTsw8K96F3FuQsjQv64MtojLu'],
      block_height: -1,
      block_index: -1,
      confirmations: 0,
      double_spend: false,
      fees: 25523,
      hash: '787a0a5fec6379b63f38377bf81b20872151ae989abfc5ba7a17f8a109663471',
      inputs: [
        {
          addresses: ['18Gi6umH8FTsw8K96F3FuQsjQv64MtojLu'],
          age: 0,
          output_index: 1,
          output_value: 2515457,
          prev_hash: '876a1161f0a750ea8b4ed297334c0f540d13ee0014fa360c24fd7cff9a8c5707',
          script:
            '473044022011aecead8f48e3b342856a8da2f30c4e05bec5dc147a5bc7b382d01bf68ae5c302204126fd77522ae311a88688bce967532456b08c94322ba182a18fb7786e696c610121027e563beec6765850071067e4fcc7a46d00cbb0d675ef8df1b8d15aaeef91a21f',
          script_type: 'pay-to-pubkey-hash',
          sequence: 4294967295,
        },
      ],
      outputs: [
        {
          addresses: ['19uR8tabimmJ9fhytbz74foP8wepgxksnE'],
          script: '76a91461aac8b58ac880a45fb06eeedfcf3017679778a988ac',
          script_type: 'pay-to-pubkey-hash',
          value: 113436,
        },
        {
          addresses: ['18Gi6umH8FTsw8K96F3FuQsjQv64MtojLu'],
          script: '76a9144fc16e1766808c0ab090be4376cea9d3a0bbe12988ac',
          script_type: 'pay-to-pubkey-hash',
          value: 2376498,
        },
      ],
      preference: 'high',
      received: '2020-05-12T21:36:21.316796626Z',
      relayed_by: '34.224.87.249',
      size: 225,
      total: 2489934,
      ver: 1,
      vin_sz: 1,
      vout_sz: 2,
    },
    {
      name: 'one_input_one_output',
      raw_tx:
        '0200000001c764160b432153d0445828c1cf44d3ead16b76325a0993499bd698b58dc1ab03000000006a473044022019a48ae0df27e3a1e75d64b8ac4ff41c703b54a87117aee1f101f278846bb5c702201587cd1c8980b0f7a34eb7c371b107f9833c128aaddba45574854b2e4e7f11ee012103421c4721b5c27c731b38cb8d0e573fd000a7be5538ade8fe23386f81619ae541ffffffff01d0bf4200000000001976a914d22b1794fe2c2c313abfd06d0c13718bba38382988ac00000000',
      addresses: ['1F1fXXbXH9PX1RZuP4aSBcAro9uSUi5tsh', '1NAK3za9MkbAkkSBMLcvmhTD6etgB4Vhpr'],
      block_height: -1,
      block_index: -1,
      confirmations: 0,
      double_spend: false,
      fees: 20000,
      hash: 'c0b8d7b7a8e45a57bfe0ebc033bf5cacd202f380df936d71712b95c8364bd581',
      inputs: [
        {
          addresses: ['1F1fXXbXH9PX1RZuP4aSBcAro9uSUi5tsh'],
          age: 460069,
          output_index: 0,
          output_value: 40000,
          prev_hash: '7e3ab0ea65b60f7d1ff4b231016fc958bc0766a46770410caa0a1855459b6e41',
          script: '76a91499b1ebcfc11a13df5161aba8160460fe1601d54188ac',
          script_type: 'pay-to-pubkey-hash',
          sequence: 4294967295,
        },
      ],
      outputs: [
        {
          addresses: ['1NAK3za9MkbAkkSBMLcvmhTD6etgB4Vhpr'],
          script: '76a914e81d742e2c3c7acd4c29de090fc2c4d4120b2bf888ac',
          script_type: 'pay-to-pubkey-hash',
          value: 20000,
        },
      ],
      preference: 'high',
      received: '2020-05-12T20:35:22.588216877Z',
      relayed_by: '34.224.87.249',
      size: 110,
      total: 20000,
      ver: 1,
      vin_sz: 1,
      vout_sz: 1,
    },
  ],
}
