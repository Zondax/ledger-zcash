import type { InitData as TxInputData } from '@zondax/zcashtools'

const zero: TxInputData = {
  t_in: [],
  t_out: [],
  s_spend: [
    {
      path: 1000,
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 50000,
    },
    {
      path: 1000,
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 50000,
    },
  ],
  s_output: [
    {
      address: '15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc',
      value: 55000,
      memo_type: 0xf6,
    },
    {
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 100000 - 1000 - 55000,
      memo_type: 0xf6,
      ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
    },
  ],
}

const one: TxInputData = {
  t_in: [
    {
      path: Uint32Array.from([44 + 0x80000000, 133 + 0x80000000, 5 + 0x80000000, 0, 0]),
      address: '1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac',
      value: 60000,
    },
  ],
  t_out: [],
  s_spend: [
    {
      path: 1000,
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 40000,
    },
  ],
  s_output: [
    {
      address: '15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc',
      value: 65000,
      memo_type: 0xf6,
    },
    {
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 100000 - 1000 - 55000 - 10000,
      memo_type: 0xf6,
      ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
    },
  ],
}

const two: TxInputData = {
  t_in: [],
  t_out: [
    {
      address: '1976a914000000000000000000000000000000000000000088ac',
      value: 10000,
    },
  ],
  s_spend: [
    {
      path: 1000,
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 100000,
    },
  ],
  s_output: [
    {
      address: '15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc',
      value: 55000,
      memo_type: 0xf6,
    },
    {
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 100000 - 1000 - 55000 - 10000,
      memo_type: 0xf6,
      ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
    },
  ],
}

const three: TxInputData = {
  t_in: [
    {
      path: Uint32Array.from([44 + 0x80000000, 133 + 0x80000000, 5 + 0x80000000, 0, 0]),
      address: '1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac',
      value: 60000,
    },
  ],
  t_out: [
    {
      address: '1976a914000000000000000000000000000000000000000088ac',
      value: 10000,
    },
  ],
  s_spend: [
    {
      path: 1000,
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 40000,
    },
  ],
  s_output: [
    {
      address: '15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc',
      value: 55000,
      memo_type: 0xf6,
    },
    {
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 100000 - 1000 - 55000 - 10000,
      memo_type: 0xf6,
      ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
    },
  ],
}

const four: TxInputData = {
  t_in: [
    {
      path: Uint32Array.from([44 + 0x80000000, 133 + 0x80000000, 5 + 0x80000000, 0, 0]),
      address: '1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac',
      value: 50000,
    },
    {
      path: Uint32Array.from([44 + 0x80000000, 133 + 0x80000000, 5 + 0x80000000, 0, 0]),
      address: '1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac',
      value: 50000,
    },
  ],
  t_out: [
    {
      address: '1976a914000000000000000000000000000000000000000088ac',
      value: 10000,
    },
    {
      address: '1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac',
      value: 100000 - 1000 - 10000,
    },
  ],
  s_spend: [],
  s_output: [],
}

const five: TxInputData = {
  t_in: [],
  t_out: [],
  s_spend: [
    {
      path: 1000,
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 50000,
    },
    {
      path: 1000,
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 50000,
    },
  ],
  s_output: [
    {
      address: '15eae700e01e24e2137d554d67bb0da64eee0bf1c2c392c5f1173a979baeb899663808cd22ed8df27566cc',
      value: 55000,
      memo_type: 0xf6,
    },
    {
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 100000 - 1000 - 55000,
      memo_type: 0xf6,
    },
  ],
}

export const TX_INPUT_DATA: TxInputData[] = [zero, one, two, three, four, five]
