/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "util_napi.h"

#undef LOG_TAG
#define LOG_TAG "UtilNapi"

namespace OHOS {
namespace Msdp {
namespace UtilNapi {

bool TypeOf(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valType = napi_undefined;
    CHKRF(napi_typeof(env, value, &valType), "napi_typeof");
    return (valType == type);
}

napi_value GetNull(napi_env env)
{
    napi_value value = nullptr;
    napi_get_null(env, &value);
    return value;
}
} // namespace UtilNapi
} // namespace Msdp
} // namespace OHO
