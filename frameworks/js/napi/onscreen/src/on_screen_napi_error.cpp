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
#include "on_screen_napi_error.h"

#include <optional>

#include "fi_log.h"
#include "on_screen_data.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenNapiError"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
std::map<int32_t, std::string> ERROR_MESSAGES = {
    { RET_NO_PERMISSION, "Permission check failed." },
    { RET_NO_SYSTEM_CALLING, "Permission check failed. A non-system application uses the system API." },
    { RET_PARAM_ERR, "Params check failed." },
    { RET_NO_SUPPORT, "The device does not support this API." },
    { RET_SERVICE_EXCEPTION, "Service exception." },
    { RET_NOT_IN_WHITELIST, "The application or page is not supported." },
    { RET_WINDOW_ID_ERR, "The window ID is invalid. Possible causes: 1. window id is not passes when"
                        "screen is splited. 2. passed window id is not on screen or floating." },
    { RET_PAGE_NOT_READY, "The page is not ready." },
    { RET_TARGET_NOT_FOUND, "The target is not found." },
};

napi_value CreateOnScreenNapiError(const napi_env &env, int32_t errCode, const std::string &errMessage)
{
    napi_value businessError = nullptr;
    napi_value code = nullptr;
    napi_value msg = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &code));
    NAPI_CALL(env, napi_create_string_utf8(env, errMessage.c_str(), NAPI_AUTO_LENGTH, &msg));
    NAPI_CALL(env, napi_create_error(env, nullptr, msg, &businessError));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "code", code));
    return businessError;
}

std::optional<std::string> GetOnScreenErrMsg(int32_t errCode)
{
    auto iter = ERROR_MESSAGES.find(errCode);
    if (iter != ERROR_MESSAGES.end()) {
        return iter->second;
    }
    FI_HILOGE("Error messages not found");
    return std::nullopt;
}

void ThrowOnScreenErr(const napi_env &env, int32_t errCode, const std::string &printMsg)
{
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    std::optional<std::string> msg = GetOnScreenErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        return;
    }
    napi_value error = CreateOnScreenNapiError(env, errCode, msg.value());
    napi_throw(env, error);
}

void ThrowOnScreenErrByPromise(const napi_env &env, int32_t errCode, const std::string &printMsg,
    napi_value &value)
{
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    std::optional<std::string> msg = GetOnScreenErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        return;
    }
    value = CreateOnScreenNapiError(env, errCode, msg.value());
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS