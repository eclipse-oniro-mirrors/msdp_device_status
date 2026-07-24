/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "car_awareness_napi.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "CarAwarenessInit"

namespace OHOS {
namespace Msdp {

EXTERN_C_START
/*
 * Function for module exports.
 */
static napi_value CarAwarenessInit(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_value ret = CarAwarenessNapi::Init(env, exports);
    return ret;
}
EXTERN_C_END

/*
 * Module Definition.
 */
static napi_module g_module = {.nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "multimodalAwareness.carAwareness",
    .nm_register_func = CarAwarenessInit,
    .nm_modname = "multimodalAwareness.carAwareness",
    .nm_priv = (static_cast<void *>(0)),
    .reserved = {0}};

/*
 * carAwareness NAPI Module Init.
 */
extern "C" __attribute__((constructor)) void RegisterCarModeManageModule(void)
{
    FI_HILOGI("carAwareness service moudle register.");
    napi_module_register(&g_module);
}

} // namespace Msdp
} // namespace OHOS