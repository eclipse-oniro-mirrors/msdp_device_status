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

#include "device_status_napi_error.h"

#include <optional>

#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusNapiError"

namespace OHOS {
namespace Msdp {
namespace DeviceStatusV1 {
napi_value CreateDeviceStatusNapiError(const napi_env &env, int32_t errCode, const std::string &errMessage)
{
    napi_value businessError = nullptr;
    napi_value code = nullptr;
    napi_value msg = nullptr;
    MSDP_CALL(napi_create_int32(env, errCode, &code));
    MSDP_CALL(napi_create_string_utf8(env, errMessage.c_str(), NAPI_AUTO_LENGTH, &msg));
    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, "code", code);
    return businessError;
}

std::optional<std::string> GetDeviceStatusErrMsg(int32_t errCode)
{
    auto iter = ERROR_MESSAGES.find(errCode);
    if (iter != ERROR_MESSAGES.end()) {
        return iter->second;
    }
    FI_HILOGE("Error messages not found");
    return std::nullopt;
}

void ThrowDeviceStatusErr(const napi_env &env, int32_t errCode, const std::string &printMsg)
{
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    std::optional<std::string> msg = GetDeviceStatusErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        return;
    }
    napi_value error = CreateDeviceStatusNapiError(env, errCode, msg.value());
    napi_throw(env, error);
}

void ThrowDeviceStatusErrByPromise(const napi_env &env, int32_t errCode, const std::string &printMsg,
    napi_value &value)
{
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    std::optional<std::string> msg = GetDeviceStatusErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        return;
    }
    value = CreateDeviceStatusNapiError(env, errCode, msg.value());
}
} // namespace DeviceStatusV1
} // namespace Msdp
} // namespace OHOS
