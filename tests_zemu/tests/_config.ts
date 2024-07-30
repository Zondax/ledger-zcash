import { IDeviceModel, DEFAULT_START_OPTIONS, ButtonKind } from '@zondax/zemu'

import { resolve } from 'path'

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_S = resolve('../app/output/app_s.elf')
const APP_PATH_X = resolve('../app/output/app_x.elf')
const APP_PATH_SP = resolve('../app/output/app_s2.elf')
const APP_PATH_ST = resolve('../app/output/app_stax.elf')
const APP_PATH_FL = resolve('../app/output/app_flex.elf')

export const models: IDeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'flex', prefix: 'FL', path: APP_PATH_FL },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
]

export const defaultOptions = (m: IDeviceModel, is_address = false) => {
  let approveAction = ButtonKind.ApproveHoldButton
  let approveKeyword = ''

  if (m.name == 'stax' && is_address) {
    approveKeyword = 'Show as QR'
    approveAction = ButtonKind.ApproveTapButton
  }

  return {
    ...DEFAULT_START_OPTIONS,
    logging: true,
    custom: `-s "${APP_SEED}"`,
    approveAction,
    approveKeyword,
    model: m.name,
  }
}
