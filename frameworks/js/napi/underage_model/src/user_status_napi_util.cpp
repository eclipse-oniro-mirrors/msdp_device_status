/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "user_status_napi_util.h"

#include "securec.h"

#include "devicestatus_define.h"
#include "fi_log.h"
#include "user_blow_data.h"
#include "user_mood_data.h"
#include "util_napi.h"

namespace OHOS {
namespace Msdp {
namespace UserStatusAwareness {
namespace {
constexpr int32_t LINEAR_ACC_SIZE = 4;
} // namespace

napi_value UserStatusNapiUtil::NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

void UserStatusNapiUtil::ReportUserDataToJs(napi_env env, std::shared_ptr<UserStatusData> data,
    napi_value userData)
{
    if (data == nullptr) {
        FI_HILOGE("data is nullptr");
        return;
    }
    FI_HILOGD("data: %{public}s", data->Dump().c_str());
    napi_value feature = nullptr;
    CHKRV(napi_create_uint32(env, data->GetFeature(), &feature), "napi_create_uint32 failed");
    CHKRV(napi_set_named_property(env, userData, "feature", feature), "napi_set_named_property failed");
    CHKRV(SetValueUTF8String(env, "status", data->GetStatus().c_str(), userData), "SetValueUTF8String failed");
    CHKRV(SetValueInt32(env, "result", data->GetResult(), userData), "SetValueInt32 failed");
    CHKRV(SetValueInt32(env, "errCode", data->GetErrorCode(), userData), "SetValueInt32 failed");
    auto featureId = data->GetFeature();
    if (featureId == FEATURE_USER_PLAYING || featureId == FEATURE_USER_FACE) {
        SetPlayAbilityData(env, data, userData);
    }
    if (featureId == FEATURE_USER_PLAY_ABILITY_FATIGUE || featureId == FEATURE_USER_GESTURE) {
        SetPlayAbilityData(env, data, userData);
        SetJsGesturesData(env, data, userData);
    }
    if (featureId == FEATURE_USER_FACE_ANGLE) {
        CHKRV(SetValueUTF8String(env, "hpeNetworkId", data->GetHpeDeviceId().c_str(), userData),
            "set hpeNetworkId failed");
    }
    if (featureId == FEATURE_USER_BLOW) {
        SetBlowJsData(env, data, userData);
    }
    if (featureId == FEATURE_COMFORT_REMINDER) {
        SetComfortReminderData(env, data, userData);
    }
    if (featureId == FEATURE_USER_MOOD) {
        SetMoodJsData(env, data, userData);
    }
}

void UserStatusNapiUtil::SetMoodJsData(napi_env env, std::shared_ptr<UserStatusData> data, napi_value& jsData)
{
    FI_HILOGD("emotion data: %{public}s", data->Dump().c_str());
    std::shared_ptr<UserMoodData> moodData = std::static_pointer_cast<UserMoodData>(data);
    CHKPV(moodData);
    if (moodData->GetIsValidMoodTag()) {
        FI_HILOGI("report emotion data to hap: %{public}s", data->Dump().c_str());
        CHKRV(SetValueInt32(env, "emotionRealTime", moodData->GetRealTimeEmotion(), jsData),
            "SetValueInt32 failed");
        CHKRV(SetValueInt32(env, "confidence", moodData->GetConfidence(), jsData), "SetValueInt32 failed");
        CHKRV(SetValueBool(env, "isRealTime", moodData->GetIsRealTimeTag(), jsData), "SetValueBool failed");
        napi_value napiValue;
        CHKRV(napi_create_array_with_length(env, moodData->GetNonRealTimeEmotion().size(), &napiValue),
            "napi_create_array_with_length failed");
        if (Int32VectorToJsArray(env, moodData->GetNonRealTimeEmotion(), napiValue) != napi_ok) {
            FI_HILOGE("FeaturesToJsArray failed");
            return;
        }
        CHKRV(napi_set_named_property(env, jsData, "emotionNonRealTime", napiValue),
            "napi_set_named_property failed");
    }
    SetJsArrayProperty(env, moodData->GetGravityAcc(), "gravityAcceleration", jsData);
    uint32_t jdx = 0;
    napi_value linearAccNapiValue = nullptr;
    CHKRV(napi_create_array_with_length(env, moodData->GetLinearAcc().size(), &linearAccNapiValue),
        "napi_create_array_with_length failed");
    auto linearacc = moodData->GetLinearAcc();
    for (int32_t i = 0; i < LINEAR_ACC_SIZE; ++i) {
        napi_value eachAccNapiValue = nullptr;
        uint32_t idx = 0;
        CHKRV(napi_create_array_with_length(env, linearacc.size(), &eachAccNapiValue),
            "napi_create_array_with_length failed");
        for (auto& each : linearacc) {
            napi_value eachObj;
            CHKRV(napi_create_object(env, &eachObj), "napi_create_object failed");
            CHKRV(napi_create_double(env, each, &eachObj), "napi_create_double");
            napi_status status = napi_set_element(env, eachAccNapiValue, idx++, eachObj);
            if (status != napi_ok) {
                FI_HILOGE("error: napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
                return;
            }
        }
        CHKRV(napi_set_element(env, linearAccNapiValue, jdx++, eachAccNapiValue), "napi_set_element failed");
    }
    CHKRV(napi_set_named_property(env, jsData, "linearAcceleration", linearAccNapiValue),
        "napi_set_named_property failed");
}

void UserStatusNapiUtil::SetComfortReminderData(napi_env env, std::shared_ptr<UserStatusData> data, napi_value& jsData)
{
    CHKPV(data);
    FI_HILOGD("comfort reminder data: %{public}s", data->Dump().c_str());
    std::shared_ptr<ComfortReminderData> reminderData = std::static_pointer_cast<ComfortReminderData>(data);
    CHKRV(SetValueInt32(env, "fusionReminderData", reminderData->GetFusionReminderData(), jsData),
        "napi_set_property failed");
    CHKRV(SetValueInt32(env, "swingReminderData", reminderData->GetSwingReminderData(), jsData),
        "napi_set_property failed");
    CHKRV(SetValueInt32(env, "eventType", reminderData->GetEventType(), jsData), "napi_set_property failed");
}

void UserStatusNapiUtil::SetBlowJsData(napi_env env, std::shared_ptr<UserStatusData> data, napi_value& jsData)
{
    CHKPV(data);
    FI_HILOGI("blow data: %{public}s", data->Dump().c_str());
    std::shared_ptr<UserBlowData> blowData = std::static_pointer_cast<UserBlowData>(data);
    CHKRV(SetValueInt32(env, "strengthLevel", blowData->GetStrengthLevel(), jsData), "napi_set_property failed");
    CHKRV(SetValueInt32(env, "blowDirection", blowData->GetDirection(), jsData), "napi_set_property failed");
    CHKRV(SetValueInt32(env, "emotion", blowData->GetEmotion(), jsData), "napi_set_property failed");
    CHKRV(SetValueBool(env, "isGazeStatus", blowData->GetEyesOn(), jsData), "napi_set_property failed");
    SetJsArrayProperty(env, blowData->GetFacePosition(), "facePosition", jsData);
    SetJsArrayProperty(env, blowData->GetGravityAcc(), "gravityAcceleration", jsData);
    uint32_t jdx = 0;
    napi_value linearAccNapiValue = nullptr;
    CHKRV(napi_create_array_with_length(env, blowData->GetLinearAcc().size(), &linearAccNapiValue),
        "napi_create_array_with_length failed");
    auto linearacc = blowData->GetLinearAcc();
    for (int32_t i = 0; i < LINEAR_ACC_SIZE; ++i) {
        napi_value eachAccNapiValue = nullptr;
        uint32_t idx = 0;
        CHKRV(napi_create_array_with_length(env, linearacc.size(), &eachAccNapiValue),
            "napi_create_array_with_length failed");
        for (auto& each : linearacc) {
            napi_value eachObj;
            CHKRV(napi_create_object(env, &eachObj), "napi_create_object failed");
            CHKRV(napi_create_double(env, each, &eachObj), "napi_create_double");
            napi_status status = napi_set_element(env, eachAccNapiValue, idx++, eachObj);
            if (status != napi_ok) {
                FI_HILOGE("error: napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
                return;
            }
        }
        CHKRV(napi_set_element(env, linearAccNapiValue, jdx++, eachAccNapiValue), "napi_set_element failed");
    }
    CHKRV(napi_set_named_property(env, jsData, "linearAcceleration", linearAccNapiValue),
        "napi_set_named_property failed");
}

void UserStatusNapiUtil::SetJsGesturesData(napi_env env, std::shared_ptr<UserStatusData> data, napi_value& jsData)
{
    CHKPV(data);
    FI_HILOGD("data: %{public}s", data->Dump().c_str());
    std::shared_ptr<PlayAbilityStatusData> pData = std::static_pointer_cast<PlayAbilityStatusData>(data);
    CHKRV(SetValueBool(env, "isHandExist", pData->GetHandExistFlag(), jsData), "napi_set_property failed");
    CHKRV(SetValueInt32(env, "motionGesture", pData->GetMotionGesture(), jsData), "napi_set_property failed");
    CHKRV(SetValueInt32(env, "handType", pData->GetHandType(), jsData), "napi_set_property failed");
    SetJsArrayProperty(env, pData->GetHandPosition(), "handPosition", jsData);
    SetJsArrayProperty(env, pData->GetDirectionAngle(), "directionAngle", jsData);
    SetJsArrayProperty(env, pData->GetGestureSpeed(), "gestureSpeed", jsData);
}

void UserStatusNapiUtil::SetPlayAbilityData(napi_env env, std::shared_ptr<UserStatusData> data, napi_value& jsData)
{
    CHKPV(data);
    FI_HILOGD("data: %{public}s", data->Dump().c_str());
    std::shared_ptr<PlayAbilityStatusData> pData = std::static_pointer_cast<PlayAbilityStatusData>(data);
    SetJsArrayProperty(env, pData->GetVisualAngle(), "visualAngle", jsData);
    SetJsArrayProperty(env, pData->GetAngularVelocity(), "angularVelocity", jsData);
    SetJsArrayProperty(env, pData->GetGravityAcc(), "gravityAcceleration", jsData);
    uint32_t jdx = 0;
    napi_value linearAccNapiValue = nullptr;
    CHKRV(napi_create_array_with_length(env, pData->GetLinearAcc().size(), &linearAccNapiValue),
        "napi_create_array_with_length failed");
    for (const auto &vec : pData->GetLinearAcc()) {
        napi_value eachAccNapiValue = nullptr;
        uint32_t idx = 0;
        CHKRV(napi_create_array_with_length(env, vec.size(), &eachAccNapiValue),
            "napi_create_array_with_length failed");
        for (auto& each : vec) {
            napi_value eachObj;
            CHKRV(napi_create_object(env, &eachObj), "napi_create_object failed");
            CHKRV(napi_create_double(env, each, &eachObj), "napi_create_double");
            napi_status status = napi_set_element(env, eachAccNapiValue, idx++, eachObj);
            if (status != napi_ok) {
                FI_HILOGE("error: napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
                return;
            }
        }
        CHKRV(napi_set_element(env, linearAccNapiValue, jdx++, eachAccNapiValue), "napi_set_element failed");
    }
    CHKRV(napi_set_named_property(env, jsData, "linearAcceleration", linearAccNapiValue),
        "napi_set_named_property failed");
    SetJsArrayProperty(env, pData->GetGameRotationData(), "azimuth", jsData);
    CHKRV(SetValueInt32(env, "faceNum", pData->GetFaceNum(), jsData), "napi_set_property failed");
}

void UserStatusNapiUtil::SetJsArrayProperty(napi_env env, const std::vector<float>& vec, const char* key,
    napi_value& jsData)
{
    napi_value napiValue;
    CHKRV(napi_create_array_with_length(env, vec.size(), &napiValue), "napi_create_array_with_length failed");
    if (VectorToJsArray(env, vec, napiValue) != napi_ok) {
        FI_HILOGE("FeaturesToJsArray failed");
        return;
    }
    CHKRV(napi_set_named_property(env, jsData, key, napiValue), "napi_set_named_property failed");
}

napi_status UserStatusNapiUtil::VectorToJsArray(napi_env env, const std::vector<float>& vec,
    napi_value& arrayResult)
{
    CALL_DEBUG_ENTER;
    uint32_t idx = 0;
    for (auto& each : vec) {
        napi_value eachObj;
        napi_status status = napi_create_object(env, &eachObj);
        if (status != napi_ok) {
            FI_HILOGE("napi_create_object failed");
            return napi_object_expected;
        }
        status = napi_create_double(env, each, &eachObj);
        if (status != napi_ok) {
            FI_HILOGE("napi_create_double failed");
            return napi_object_expected;
        }
        status = napi_set_element(env, arrayResult, idx++, eachObj);
        if (status != napi_ok) {
            FI_HILOGE("error: napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
            return napi_function_expected;
        }
    }
    return napi_ok;
}

napi_status UserStatusNapiUtil::Int32VectorToJsArray(napi_env env, const std::vector<int32_t>& vec,
    napi_value& arrayResult)
{
    CALL_DEBUG_ENTER;
    uint32_t idx = 0;
    for (auto& each : vec) {
        napi_value eachObj;
        napi_status status = napi_create_object(env, &eachObj);
        if (status != napi_ok) {
            FI_HILOGE("napi_create_object failed");
            return napi_object_expected;
        }
        status = napi_create_int32(env, each, &eachObj);
        if (status != napi_ok) {
            FI_HILOGE("napi_create_double failed");
            return napi_object_expected;
        }
        status = napi_set_element(env, arrayResult, idx++, eachObj);
        if (status != napi_ok) {
            FI_HILOGE("error: napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
            return napi_function_expected;
        }
    }
    return napi_ok;
}

void UserStatusNapiUtil::GetUserDataToJs(napi_env env, UserStatusNapiResult &statusResult, napi_value result)
{
    FI_HILOGI("statusResult.features:%{public}d", statusResult.feature);
    napi_value feature = nullptr;
    CHKRV(napi_create_uint32(env, statusResult.feature, &feature), "napi_create_uint32 failed");
    CHKRV(napi_set_named_property(env, result, "feature", feature), "napi_set_named_property failed");
    if (statusResult.statusDescription.empty()) {
        FI_HILOGE("status is empty");
        return;
    }
    if (SetValueUTF8String(env, "status", statusResult.statusDescription.c_str(), result) != napi_ok) {
        FI_HILOGE("SetValueUTF8String status failed");
        return;
    }
    if (SetValueInt32(env, "result", statusResult.result, result) != napi_ok) {
        FI_HILOGE("SetValueInt32 result failed");
        return;
    }
    if (SetValueInt32(env, "errCode", statusResult.errCode, result) != napi_ok) {
        FI_HILOGE("SetValueInt32 errCode failed");
        return;
    }
}

void UserStatusNapiUtil::ParseIntArray(const napi_env& env, const napi_value& value, std::vector<std::int32_t>& result)
{
    bool isArray = false;
    CHKRV(napi_is_array(env, value, &isArray), "napi_is_array failed");
    if (!isArray) {
        FI_HILOGE("is not array");
        return;
    }
    uint32_t length = 0;
    CHKRV(napi_get_array_length(env, value, &length), "napi_get_array_length failed");
    FI_HILOGI("array size is %{public}u", length);
    if (length == 0) {
        FI_HILOGE("array is empty");
        return;
    }
    napi_value element = nullptr;
    const int32_t invalidCap = -1;
    int32_t cap = invalidCap;
    for (uint32_t i = 0; i < length; i++) {
        CHKRV(napi_get_element(env, value, i, &element), "napi_get_element failed");
        CHKRV(napi_get_value_int32(env, element, &cap), "napi_get_value_int32 failed");
        result.emplace_back(cap);
    }
}

napi_value UserStatusNapiUtil::GetNapiValueByInt32(napi_env env, int32_t number)
{
    napi_value value = nullptr;
    if (napi_create_int32(env, number, &value) != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        ExceptionProcess(env);
        return nullptr;
    }
    return value;
}

napi_value UserStatusNapiUtil::GetNapiUInt32(napi_env env, int32_t number)
{
    napi_value value = nullptr;
    if (napi_create_uint32(env, number, &value) != napi_ok) {
        FI_HILOGE("napi_create_uint32 failed");
        ExceptionProcess(env);
        return nullptr;
    }
    return value;
}

napi_value UserStatusNapiUtil::UndefinedNapiValue(napi_env env)
{
    napi_value result = nullptr;
    napi_status getUndefinedStatus = napi_get_undefined(env, &result);
    if (getUndefinedStatus != napi_ok) {
        FI_HILOGE("Getters for defined singletons");
    }
    return result;
}

napi_status UserStatusNapiUtil::VerifyProperty(napi_env env, const napi_value object, const char *fieldStr)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, fieldStr, &hasProperty) != napi_ok) {
        FI_HILOGE("napi_has_named_property failed");
        return napi_invalid_arg;
    }
    if (!hasProperty) {
        FI_HILOGE("Js object dose not have property: %{public}s", fieldStr);
        return napi_invalid_arg;
    }
    return napi_ok;
}

napi_value UserStatusNapiUtil::JsObjectToString(napi_env env, const napi_value object, const char *fieldStr,
    const int32_t bufLen, std::string &fieldRef)
{
    napi_status verfyResult = VerifyProperty(env, object, fieldStr);
    if (verfyResult != napi_ok) {
        FI_HILOGE("VerifyProperty failed");
        return nullptr;
    }
    napi_value field = nullptr;
    napi_valuetype valueType = napi_undefined;

    CHKRP(napi_get_named_property(env, object, fieldStr, &field), "napi_get_named_property failed");
    CHKRP(napi_typeof(env, field, &valueType), "napi_typeof failed");
    if (valueType != napi_string) {
        ThrowErr(env, PARAM_ERROR, "Wrong argument type. String expected");
        return nullptr;
    }
    const int32_t maxBufLen = 1024;
    if (bufLen <= 0 || bufLen >= maxBufLen) {
        FI_HILOGE("buf length is illegal");
        return UndefinedNapiValue(env);
    }
    char buf[maxBufLen] = { 0 };
    size_t result = 0;
    CHKRP(napi_get_value_string_utf8(env, field, buf, bufLen, &result),
        "napi_get_value_string_utf8 failed");
    fieldRef = buf;
    return UndefinedNapiValue(env);
}

napi_value UserStatusNapiUtil::JsObjectToInt(napi_env env, const napi_value object, const char *fieldStr,
    int32_t &fieldRef)
{
    CHKRP(VerifyProperty(env, object, fieldStr), "VerifyProperty failed");
    napi_value field = nullptr;
    CHKRP(napi_get_named_property(env, object, fieldStr, &field), "napi_get_named_property failed");
    napi_valuetype valueType = napi_undefined;
    CHKRP(napi_typeof(env, field, &valueType), "napi_typeof failed");
    if (valueType != napi_number) {
        ThrowErr(env, PARAM_ERROR, "Wrong argument type. Number expected");
        return nullptr;
    }
    CHKRP(napi_get_value_int32(env, field, &fieldRef), "napi_get_value_int32");
    return UndefinedNapiValue(env);
}

napi_value UserStatusNapiUtil::JsObjectToUint(napi_env env, const napi_value object, const char *fieldStr,
    uint32_t &fieldRef)
{
    CHKRP(VerifyProperty(env, object, fieldStr), "VerifyProperty failed");
    napi_value field = nullptr;
    CHKRP(napi_get_named_property(env, object, fieldStr, &field), "napi_get_named_property");
    napi_valuetype valueType = napi_undefined;
    CHKRP(napi_typeof(env, field, &valueType), "napi_typeof failed");
    if (valueType != napi_number) {
        ThrowErr(env, PARAM_ERROR, "Wrong argument type. Number expected");
        return nullptr;
    }
    CHKRP(napi_get_value_uint32(env, field, &fieldRef), "napi_get_value_uint32 failed");
    return UndefinedNapiValue(env);
}

napi_value UserStatusNapiUtil::JsObjectToBool(napi_env env, const napi_value object, const char *fieldStr,
    bool &fieldRef)
{
    CHKRP(VerifyProperty(env, object, fieldStr), "VerifyProperty failed");
    napi_value field = nullptr;
    CHKRP(napi_get_named_property(env, object, fieldStr, &field), "napi_get_named_property failed");
    napi_valuetype valueType = napi_undefined;
    CHKRP(napi_typeof(env, field, &valueType), "napi_typeof failed");
    if (valueType != napi_boolean) {
        ThrowErr(env, PARAM_ERROR, "Wrong argument type. Bool expected");
        return nullptr;
    }
    CHKRP(napi_get_value_bool(env, field, &fieldRef), "napi_get_value_bool failed");
    return UndefinedNapiValue(env);
}

napi_status UserStatusNapiUtil::SetValueUTF8String(napi_env env, const char *fieldStr, const char *str,
    napi_value result, size_t strLen)
{
    FI_HILOGD("fieldStr: %{public}s, str: %{public}s", fieldStr, str);
    napi_value napiStringValue = nullptr;
    napi_status status = napi_create_string_utf8(env, str, strLen, &napiStringValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_create_string_utf8 failed! field: %{public}s", fieldStr);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, napiStringValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_set_named_property failed! field: %{public}s", fieldStr);
        return status;
    }
    return status;
}

napi_status UserStatusNapiUtil::SetValueInt32(napi_env env, const char *fieldStr, int32_t intValue, napi_value result)
{
    napi_value napiIntValue = nullptr;
    napi_status status = napi_create_int32(env, intValue, &napiIntValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_create_int32 failed! intValue: %{public}d", intValue);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, napiIntValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_set_named_property failed! field: %{public}s", fieldStr);
        return status;
    }
    return status;
}

napi_status UserStatusNapiUtil::SetValueFloat(napi_env env, const char *fieldStr, float floatValue, napi_value result)
{
    napi_value napiIntValue = nullptr;
    napi_status status = napi_create_double(env, static_cast<double>(floatValue), &napiIntValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_create_double failed! floatValue: %{public}f", floatValue);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, napiIntValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_set_named_property failed! field: %{public}s", fieldStr);
        return status;
    }
    return status;
}

napi_status UserStatusNapiUtil::SetValueUnsignedInt32(napi_env env, const char *fieldStr, uint32_t uintValue,
    napi_value result)
{
    napi_value napiUintValue = nullptr;
    napi_status status = napi_create_uint32(env, uintValue, &napiUintValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_create_int32 failed! uintValue: %{public}u", uintValue);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, napiUintValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_set_named_property failed! field: %{public}s", fieldStr);
        return status;
    }
    return status;
}

napi_status UserStatusNapiUtil::SetValueInt64(napi_env env, const char *fieldStr, int64_t intValue, napi_value result)
{
    napi_value napiIntValue = nullptr;
    napi_status status = napi_create_int64(env, intValue, &napiIntValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_create_int64 failed! intValue");
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, napiIntValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_set_named_property failed! field: %{public}s", fieldStr);
        return status;
    }
    return status;
}

napi_status UserStatusNapiUtil::SetValueBool(napi_env env, const char *fieldStr, const bool boolValue,
    napi_value result)
{
    napi_value napiBoolValue = nullptr;
    napi_status status = napi_get_boolean(env, boolValue, &napiBoolValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_boolean failed! boolValue: %{public}d", boolValue);
        return status;
    }
    status = napi_set_named_property(env, result, fieldStr, napiBoolValue);
    if (status != napi_ok) {
        FI_HILOGE("napi_set_named_property failed! field: %{public}s", fieldStr);
        return status;
    }
    return status;
}

void UserStatusNapiUtil::ExceptionProcess(napi_env env)
{
    const napi_extended_error_info *errorInfo = nullptr;
    CHKRV(napi_get_last_error_info(env, &errorInfo), "napi_get_last_error_info failed");
    bool isPending = false;
    CHKRV(napi_is_exception_pending(env, &isPending), "napi_is_exception_pending");
    if (!isPending && errorInfo != nullptr) {
        std::string errDesc = std::string(__FUNCTION__) + ": napi_create_uint32 failed";
        std::string errorMessage =
            errorInfo->error_message != nullptr ? errorInfo->error_message : "empty error message";
        errDesc += errorMessage;
        ThrowErr(env, SERVICE_EXCEPTION, errDesc.c_str());
    }
}

napi_value UserStatusNapiUtil::CreateNapiError(napi_env env, int32_t errCode, const std::string &errMessage)
{
    napi_value businessError = nullptr;
    napi_value msg = nullptr;
    napi_value code = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &code));
    NAPI_CALL(env, napi_create_string_utf8(env, errMessage.c_str(), NAPI_AUTO_LENGTH, &msg));
    CHKRP(napi_create_error(env, nullptr, msg, &businessError), "napi_create_error failed");
    CHKRP(napi_set_named_property(env, businessError, "code", code), "napi_set_named_property failed");
    return businessError;
}

std::optional<std::string> UserStatusNapiUtil::GetErrMsg(int32_t errorCode)
{
    auto emiter = ERROR_MESSAGES.find(errorCode);
    if (emiter != ERROR_MESSAGES.end()) {
        return emiter->second;
    }
    FI_HILOGE("Error messages not found");
    return std::nullopt;
}

void UserStatusNapiUtil::ThrowErr(napi_env env, int32_t errCode, const std::string &printMsg)
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
} // namespace UserStatusAwareness
} // namespace Msdp
} // namespace OHOS