/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "car_awareness_napi_utils.h"

#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "CarAwarenessNapiUtil"

static inline bool CheckNapiCall(napi_env env, napi_status status, const char *funcName)
{
    if (status != napi_ok) {
        FI_HILOGE("%{public}s failed", funcName);
        return true;
    }
    return false;
}

namespace OHOS {
namespace Msdp {
napi_value CreateNapiError(const napi_env &env, int32_t errorCode, const std::string &errorMsg)
{
    napi_value businessError = nullptr;
    napi_value code = nullptr;
    napi_value msg = nullptr;
    MSDP_CALL(napi_create_int32(env, errorCode, &code));
    MSDP_CALL(napi_create_string_utf8(env, errorMsg.c_str(), NAPI_AUTO_LENGTH, &msg));
    MSDP_CALL(napi_create_error(env, nullptr, msg, &businessError));
    MSDP_CALL(napi_set_named_property(env, businessError, "code", code));
    return businessError;
}

std::optional<std::string> GetErrMsg(int32_t errorCode)
{
    auto iter = ERROR_MESSAGES.find(errorCode);
    if (iter != ERROR_MESSAGES.end()) {
        return iter->second;
    }
    FI_HILOGE("Error, messages not found");
    return std::nullopt;
}

void ThrowErrToJs(const napi_env &env, int32_t errorCode, const std::string &printMsg)
{
    FI_HILOGE("printMsg:%{public}s, errorCode:%{public}d", printMsg.c_str(), errorCode);
    std::optional<std::string> msg = GetErrMsg(errorCode);
    if (!msg) {
        FI_HILOGE("errorCode:%{public}d is invalid", errorCode);
        return;
    }
    napi_value error = CreateNapiError(env, errorCode, msg.value());
    napi_throw(env, error);
}

void SetStringProperty(napi_env env, napi_value targetObj, const std::string &value,
    const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_string_utf8(env, value.c_str(), value.size(), &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_string_utf8 failed");
        return;
    }
    SetPropertyName(env, targetObj, propName, prop);
}

void SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue)
{
    napi_status status = napi_set_named_property(env, targetObj, propName, propValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the name property: %{public}s", propName);
    }
}

bool TransJsToStr(napi_env env, napi_value value, std::string &str)
{
    FI_HILOGD("Enter");
    size_t strlen = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("Error string length invalid");
        return false;
    }
    if (strlen == 0 || strlen > MAX_ARG_STRING_LEN) {
        FI_HILOGE("The string length invalid");
        return false;
    }
    std::vector<char> buf(strlen + 1);
    status = napi_get_value_string_utf8(env, value, buf.data(), strlen+1, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_value_string_utf8 failed");
        return false;
    }
    str = buf.data();
    return true;
}

static napi_value CreateJsonString(napi_env env, const std::string &str)
{
    napi_value result = nullptr;
    napi_status status = napi_create_string_utf8(env, str.c_str(), NAPI_AUTO_LENGTH, &result);
    if (CheckNapiCall(env, status, "napi_create_string_utf8")) return nullptr;
    return result;
}

static napi_value CreateJsonInt64(napi_env env, int64_t val)
{
    napi_value result = nullptr;
    napi_status status = napi_create_int64(env, val, &result);
    if (CheckNapiCall(env, status, "napi_create_int64")) return nullptr;
    return result;
}

static napi_value CreateJsonDouble(napi_env env, double val)
{
    napi_value result = nullptr;
    napi_status status = napi_create_double(env, val, &result);
    if (CheckNapiCall(env, status, "napi_create_double")) return nullptr;
    return result;
}

static napi_value CreateJsonBool(napi_env env, bool val)
{
    napi_value result = nullptr;
    napi_status status = napi_get_boolean(env, val, &result);
    if (CheckNapiCall(env, status, "napi_get_boolean")) return nullptr;
    return result;
}

static napi_value ConvertJsonObject(napi_env env, const nlohmann::json &jsonVal)
{
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (CheckNapiCall(env, status, "napi_create_object")) return nullptr;

    for (auto &[key, val] : jsonVal.items()) {
        napi_value propValue = ConvertJsonValueToNapiValue(env, val);
        if (propValue == nullptr) {
            return nullptr;
        }
        napi_value propName = nullptr;
        status = napi_create_string_utf8(env, key.c_str(), NAPI_AUTO_LENGTH, &propName);
        if (CheckNapiCall(env, status, "napi_create_string_utf8")) return nullptr;
        status = napi_set_property(env, result, propName, propValue);
        if (CheckNapiCall(env, status, "napi_set_property")) return nullptr;
    }
    return result;
}

static napi_value ConvertJsonArray(napi_env env, const nlohmann::json &jsonVal)
{
    napi_value result = nullptr;
    napi_status status = napi_create_array(env, &result);
    if (CheckNapiCall(env, status, "napi_create_array")) return nullptr;

    uint32_t index = 0;
    for (const auto &item : jsonVal) {
        napi_value itemVal = ConvertJsonValueToNapiValue(env, item);
        if (itemVal == nullptr) {
            return nullptr;
        }
        status = napi_set_element(env, result, index, itemVal);
        if (CheckNapiCall(env, status, "napi_set_element")) return nullptr;
        index++;
    }
    return result;
}

napi_value ConvertJsonValueToNapiValue(napi_env env, const nlohmann::json &jsonVal)
{
    if (jsonVal.is_object()) {
        return ConvertJsonObject(env, jsonVal);
    } else if (jsonVal.is_array()) {
        return ConvertJsonArray(env, jsonVal);
    } else if (jsonVal.is_string()) {
        return CreateJsonString(env, jsonVal.get<std::string>());
    } else if (jsonVal.is_number_integer()) {
        return CreateJsonInt64(env, jsonVal.get<int64_t>());
    } else if (jsonVal.is_number_float()) {
        return CreateJsonDouble(env, jsonVal.get<double>());
    } else if (jsonVal.is_boolean()) {
        return CreateJsonBool(env, jsonVal.get<bool>());
    }
    napi_value result = nullptr;
    napi_status status = napi_get_undefined(env, &result);
    if (CheckNapiCall(env, status, "napi_get_undefined")) return nullptr;
    return result;
}
} // namespace Msdp
} // namespace OHOS
