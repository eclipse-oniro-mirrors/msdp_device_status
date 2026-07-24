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

#ifndef CAR_AWARENESS_NAPI_UTILS_H
#define CAR_AWARENESS_NAPI_UTILS_H

#include <map>
#include <optional>
#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Msdp {
// 错误码定义
constexpr int32_t RES_SUCCESS { 0 };
constexpr int32_t PERMISSION_ERR { 201 };
constexpr int32_t NOT_SYSTEM_APP_ERR { 202 };
constexpr int32_t PARAM_ERR { 401 };
constexpr int32_t DEVICE_ERR { 801 };
constexpr int32_t SERVICE_ERR { 34000001 };
constexpr int32_t SPECIFIC_ERR { 34000002 };
constexpr int32_t SUBSCRIBE_ERR { 34000003 };

const std::map<int32_t, std::string> ERROR_MESSAGES = {
    {PERMISSION_ERR, "Permission check failed."},
    {NOT_SYSTEM_APP_ERR, "not system application."},
    {PARAM_ERR, "Params check failed."},
    {DEVICE_ERR, "The device does not support this API."},
    {SERVICE_ERR, "Service exception. Possible causes: 1. A system error, such as null pointer, "
        "container-related exception; 2. N-API invocation exception, invalid N-API status."},
    {SPECIFIC_ERR, "Specific capability not support"},
    {SUBSCRIBE_ERR, "Subscribe failed. Possible causes: "
        "1. Bind native object to js wrapper failed; 2. N-API invocation exception; "
        "3. IPC request exception."}
};

constexpr size_t MAX_ARG_STRING_LEN = 512;

napi_value CreateNapiError(const napi_env &env, int32_t errorCode, const std::string &errorMsg);
std::optional<std::string> GetErrMsg(int32_t errorCode);
void ThrowErrToJs(const napi_env &env, int32_t errorCode, const std::string &printMsg);
void SetStringProperty(napi_env env, napi_value targetObj, const std::string &value,
    const char *propName);
void SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);
bool TransJsToStr(napi_env env, napi_value value, std::string &str);
} // namespace OHOS
} // namespace Msdp

#endif
