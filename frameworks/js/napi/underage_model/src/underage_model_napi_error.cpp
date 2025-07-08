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

#include "underage_model_napi_error.h"

#include <optional>
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DeviceUnderageModelNapiError"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
const std::map<int32_t, std::string> ERROR_MESSAGES = {
    {PERMISSION_EXCEPTION, "Permission check failed."},
    {PARAM_EXCEPTION, "Params check failed."},
    {DEVICE_EXCEPTION, "The device does not support this API."},
    {SERVICE_EXCEPTION, "Service exception. Possible causes: 1. A system error, such as null pointer, "
        "container-related exception; 2. N-API invocation exception, invalid N-API status."},
    {SUBSCRIBE_EXCEPTION, "Subscription failed. Possible causes: 1. Callback registration failure; "
        "2. Failed to bind native object to js wrapper; 3. N-API invocation exception, invalid N-API status; "
        "4. IPC request exception."},
    {UNSUBSCRIBE_EXCEPTION, "Unsubscription failed. Possible causes: 1. Callback failure; "
        "2. N-API invocation exception, invalid N-API status; 3. IPC request exception."}
};
} // namespace

napi_value CreateUnderageModelNapiError(const napi_env &env, int32_t errorCode, const std::string &errorMsg)
{
    napi_value businessError = nullptr;
    napi_value code = nullptr;
    napi_value msg = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errorCode, &code));
    NAPI_CALL(env, napi_create_string_utf8(env, errorMsg.c_str(), NAPI_AUTO_LENGTH, &msg));
    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, "code", code);
    return businessError;
}

std::optional<std::string> GetUnderageModelErrMsg(int32_t errorCode)
{
    auto iter = ERROR_MESSAGES.find(errorCode);
    if (iter != ERROR_MESSAGES.end()) {
        return iter->second;
    }
    FI_HILOGE("Error, messages not found");
    return std::nullopt;
}

void ThrowUnderageModelErr(const napi_env &env, int32_t errorCode, const std::string &printMsg)
{
    FI_HILOGE("printMsg:%{public}s, errorCode:%{public}d", printMsg.c_str(), errorCode);
    std::optional<std::string> msg = GetUnderageModelErrMsg(errorCode);
    if (!msg) {
        FI_HILOGE("errorCode:%{public}d is invalid", errorCode);
        return;
    }
    napi_value error = CreateUnderageModelNapiError(env, errorCode, msg.value());
    napi_throw(env, error);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS