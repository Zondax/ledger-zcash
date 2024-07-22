import { IDeviceModel, DEFAULT_START_OPTIONS } from '@zondax/zemu'

import { resolve } from 'path'

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_S = resolve('../app/output/app_s.elf')
const APP_PATH_X = resolve('../app/output/app_x.elf')
const APP_PATH_SP = resolve('../app/output/app_s2.elf')
const APP_PATH_ST = resolve('../app/output/app_stax.elf')

// FIXME Enable all models again
export const models: IDeviceModel[] = [
  //{ name: 'nanos', prefix: 'S', path: APP_PATH_S },
  //{ name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  // { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
]

export const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  // startText: "DO NOT USE",
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}
