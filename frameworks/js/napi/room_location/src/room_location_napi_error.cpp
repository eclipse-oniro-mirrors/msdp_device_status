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

#include <optional>
#include "fi_log.h"
#include "room_location_napi_error.h"

#undef LOG_TAG
#define LOG_TAG "RoomLocationNapiError"

namespace OHOS {
namespace Msdp {
napi_value CreateRoomLocationNapiError(napi_env env, int32_t errCode, const std::string &errMessage)
{
    napi_value businessError = nullptr;
    napi_value code = nullptr;
    napi_value msg = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &code));
    NAPI_CALL(env, napi_create_string_utf8(env, errMessage.c_str(), NAPI_AUTO_LENGTH, &msg));
    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, "code", code);
    return businessError;
}

std::optional<std::string> GetRoomLocationErrMsg(int32_t errorCode)
{
    auto iter = ERROR_MESSAGES.find(errorCode);
    if (iter != ERROR_MESSAGES.end()) {
        return iter->second;
    }
    FI_HILOGE("Error, messages not found");
    return std::nullopt;
}

void ThrowErr(napi_env env, int32_t errCode, const std::string &printMsg)
{
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    std::optional<std::string> msg = GetRoomLocationErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        return;
    }
    napi_value error = CreateRoomLocationNapiError(env, errCode, msg.value());
    if (error == nullptr) {
        FI_HILOGE("Failed to create NAPI error object");
        return;
    }
    napi_throw(env, error);
}
} // namespace Msdp
} // namespace OHOS
