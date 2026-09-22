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

#include "behavior_awareness_napi_error.h"

#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessNapiError"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
std::map<int32_t, std::string> NAPI_ERROR_MESSAGES = {
    { RET_NO_SYSTEM_API,
        "Permission verification failed. A non-system application uses the system API." },
    { RET_PARAM_EXCEPTION, "Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; "
        "2. Incorrect parameter types; 3. Parameter verification failed." },
    { RET_SERVICE_EXCEPTION, "Service exception." },
    { RET_UNSUBSCRIBE_EXCEPTION, "Unsubscription failed." },
};

napi_value CreateBehaviorAwarenessNapiError(const napi_env &env, int32_t errCode,
    const std::string &errMessage)
{
    napi_value businessError = nullptr;
    napi_value code = nullptr;
    napi_value msg = nullptr;
    napi_create_int32(env, errCode, &code);
    napi_create_string_utf8(env, errMessage.c_str(), NAPI_AUTO_LENGTH, &msg);
    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, "code", code);
    return businessError;
}

std::optional<std::string> GetBehaviorAwarenessErrMsg(int32_t errCode)
{
    auto iter = NAPI_ERROR_MESSAGES.find(errCode);
    if (iter != NAPI_ERROR_MESSAGES.end()) {
        return iter->second;
    }
    FI_HILOGE("Error messages not found");
    return std::nullopt;
}

void ThrowBehaviorAwarenessErr(const napi_env &env, int32_t errCode, const std::string &printMsg)
{
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    std::optional<std::string> msg = GetBehaviorAwarenessErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        return;
    }
    napi_value error = CreateBehaviorAwarenessNapiError(env, errCode, msg.value());
    napi_throw(env, error);
}

void ThrowBehaviorAwarenessErrByPromise(const napi_env &env, int32_t errCode,
    const std::string &printMsg, napi_value &value)
{
    FI_HILOGE("printMsg:%{public}s, errCode:%{public}d", printMsg.c_str(), errCode);
    std::optional<std::string> msg = GetBehaviorAwarenessErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        return;
    }
    value = CreateBehaviorAwarenessNapiError(env, errCode, msg.value());
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
