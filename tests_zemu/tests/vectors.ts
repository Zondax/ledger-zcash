import type { InitData as TxInputData } from '@zondax/zcashtools'
import { calculate_fee } from '@zondax/zcashtools'

export const fee_for = (input: TxInputData) => {
  return calculate_fee(input.t_in.length, input.t_out.length, input.s_spend.length, input.s_output.length)
}

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
      ovk: null,
    },
    {
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 100000 - 55000,
      memo_type: 0xf6,
      ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
    },
  ],
}
zero.s_output[1].value -= fee_for(zero)

const one: TxInputData = {
  t_in: [
    {
      path: [44 + 0x80000000, 133 + 0x80000000, 5 + 0x80000000, 0, 0],
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
      ovk: null,
    },
    {
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 60000 + 40000 - 65000,
      memo_type: 0xf6,
      ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
    },
  ],
}
one.s_output[1].value -= fee_for(one)

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
      ovk: null,
    },
    {
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 100000 - 55000 - 10000,
      memo_type: 0xf6,
      ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
    },
  ],
}
two.s_output[1].value -= fee_for(two)

const three: TxInputData = {
  t_in: [
    {
      path: [44 + 0x80000000, 133 + 0x80000000, 5 + 0x80000000, 0, 0],
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
      ovk: null,
    },
    {
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 60000 + 40000 - 55000 - 10000,
      memo_type: 0xf6,
      ovk: '6fc01eaa665e03a53c1e033ed0d77b670cf075ede4ada769997a2ed2ec225fca',
    },
  ],
}
three.s_output[1].value -= fee_for(three)

const four: TxInputData = {
  t_in: [
    {
      path: [44 + 0x80000000, 133 + 0x80000000, 5 + 0x80000000, 0, 0],
      address: '1976a9140f71709c4b828df00f93d20aa2c34ae987195b3388ac',
      value: 50000,
    },
    {
      path: [44 + 0x80000000, 133 + 0x80000000, 5 + 0x80000000, 0, 0],
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
      value: 50000 + 50000 - 10000,
    },
  ],
  s_spend: [],
  s_output: [],
}
four.t_out[1].value -= fee_for(four)

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
      ovk: null,
    },
    {
      address: 'c69e979c6763c1b09238dc6bd5dcbf35360df95dcadf8c0fa25dcbedaaf6057538b812d06656726ea27667',
      value: 50000 + 50000 - 55000,
      memo_type: 0xf6,
      ovk: null,
    },
  ],
}
five.s_output[1].value -= fee_for(five)

export const TX_INPUT_DATA: TxInputData[] = [zero, one, two, three, four, five]
