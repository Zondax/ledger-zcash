/*******************************************************************************
*   (c) 2020 Zondax AG
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
********************************************************************************/

#include "os.h"
#include "cx.h"
#include "coin.h"
#include "app_main.h"
#include "tx.h"
#include "view.h"
#include "app_mode.h"

void secret_accept() {
#ifdef APP_SECRET_MODE_ENABLED
    app_mode_set_secret(true);
    view_idle_show(0, NULL);
#endif
}

zxerr_t secret_getNumItems(uint8_t *num_items) {
    *num_items = 0;
    return zxerr_no_data;
}

zxerr_t secret_getItem(__Z_UNUSED int8_t displayIdx,
                       __Z_UNUSED char *outKey, __Z_UNUSED uint16_t outKeyLen,
                       __Z_UNUSED char *outVal, __Z_UNUSED uint16_t outValLen,
                       __Z_UNUSED uint8_t pageIdx, __Z_UNUSED uint8_t *pageCount) {
    return zxerr_no_data;
}

zxerr_t secret_enabled() {
    return zxerr_no_data;
}
