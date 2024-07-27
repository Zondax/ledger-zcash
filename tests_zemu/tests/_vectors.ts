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
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
      value: 50000,
    },
    {
      path: 1000,
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
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
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
      value: 100000 - 55000,
      memo_type: 0xf6,
      ovk: '8cc016f9e2ab4a8e7d2d8565deb4e33de50b75b617d344ef0589ba4ad61d566c',
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
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
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
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
      value: 60000 + 40000 - 65000,
      memo_type: 0xf6,
      ovk: '8cc016f9e2ab4a8e7d2d8565deb4e33de50b75b617d344ef0589ba4ad61d566c',
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
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
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
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
      value: 100000 - 55000 - 10000,
      memo_type: 0xf6,
      ovk: '8cc016f9e2ab4a8e7d2d8565deb4e33de50b75b617d344ef0589ba4ad61d566c',
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
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
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
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
      value: 60000 + 40000 - 55000 - 10000,
      memo_type: 0xf6,
      ovk: '8cc016f9e2ab4a8e7d2d8565deb4e33de50b75b617d344ef0589ba4ad61d566c',
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
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
      value: 50000,
    },
    {
      path: 1000,
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
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
      address: 'c69e979c6763c1b09238dc766ebfc0bf485aa5383d41e61ae67ad482fdf9bac257f7e868fd09d48e6d7586',
      value: 50000 + 50000 - 55000,
      memo_type: 0xf6,
      ovk: null,
    },
  ],
}
five.s_output[1].value -= fee_for(five)

export const TX_INPUT_DATA: TxInputData[] = [zero, one, two, three, four, five]
