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

#include "boomerang_napi_error.h"

#include <optional>

#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangNapiError"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

napi_value CreateNapiError(const napi_env &env, int32_t errCode, const std::string &errMessage)
{
    napi_value businessError = nullptr;
    napi_value msg = nullptr;
    napi_value code = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &code));
    NAPI_CALL(env, napi_create_string_utf8(env, errMessage.c_str(), NAPI_AUTO_LENGTH, &msg));
    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, "code", code);
    return businessError;
}

std::optional <std::string> GetErrMsg(int32_t errorCode)
{
    auto emiter = ERROR_MESSAGES.find(errorCode);
    if (emiter != ERROR_MESSAGES.end()) {
        return emiter->second;
    }
    FI_HILOGE("Error messages not found");
    return std::nullopt;
}

void ThrowErr(const napi_env &env, int32_t errCode, const std::string &printMsg)
{
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    std::optional<std::string> msg = GetErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        return;
    }
    napi_value error = CreateNapiError(env, errCode, msg.value());
    napi_throw(env, error);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
