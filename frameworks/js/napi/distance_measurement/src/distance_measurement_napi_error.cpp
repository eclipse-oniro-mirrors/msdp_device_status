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
#include "distance_measurement_napi_error.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DistanceMeasurementNapiError"

namespace OHOS {
namespace Msdp {
const std::map<int32_t, std::string> ERROR_MESSAGES = {
    {PERMISSION_EXCEPTION, "Permission exception."},
    {DEVICE_EXCEPTION, "The device does not support this API."},
    {SERVICE_EXCEPTION, "Service exception."},
    {SUBSCRIBE_EXCEPTION, "Subscription failed."},
    {UNSUBSCRIBE_EXCEPTION, "Unsubscription failed."},
    {PARAMETER_EXCEPTION, "Parameter invalid."}
};

napi_value CreateDistanceMeasurementNapiError(napi_env env, int32_t errCode, const std::string &errMessage)
{
    napi_value businessError = nullptr;
    napi_value code = nullptr;
    napi_value msg = nullptr;
    MSDP_CALL(napi_create_int32(env, errCode, &code));
    MSDP_CALL(napi_create_string_utf8(env, errMessage.c_str(), NAPI_AUTO_LENGTH, &msg));
    MSDP_CALL(napi_create_error(env, nullptr, msg, &businessError));
    napi_set_named_property(env, businessError, "code", code);
    return businessError;
}

std::optional<std::string> GetDistanceMeasurementNapiErrMsg(int32_t errorCode)
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
    std::optional<std::string> msg = GetDistanceMeasurementNapiErrMsg(errCode);
    if (!msg) {
        FI_HILOGE("errCode:%{public}d is invalid", errCode);
        msg = "Invalid error code";
    }
    napi_value error = CreateDistanceMeasurementNapiError(env, errCode, msg.value());
    if (error == nullptr) {
        FI_HILOGE("Failed to create NAPI error object, creating generic error.");
        napi_value genericError = nullptr;
        napi_status status = napi_create_string_utf8(env, "Internal error creating error object",
            NAPI_AUTO_LENGTH, &genericError);
        if (status == napi_ok) {
            napi_throw(env, genericError);
        }
        return;
    }
    napi_throw(env, error);
}
} // namespace Msdp
} // namespace OHOS
