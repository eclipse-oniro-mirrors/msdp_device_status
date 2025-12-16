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

#include <vector>
#include <securec.h>
#include <ipc_skeleton.h>
#include "bundle_mgr_proxy.h"
#include <bundle_mgr_interface.h>
#include "iservice_registry.h"

#include "fi_log.h"
#include "distance_measurement_napi.h"
#include "distance_measurement_napi_error.h"

#undef LOG_TAG
#define LOG_TAG "DistanceMeasurementNapi"

namespace OHOS {
namespace Msdp {
namespace {
DistanceMeasurementNapi* g_DistanceMeasurementNapi; // DistanceMeasurementNapi manager
std::map<std::string, int32_t>g_distanceRankFilterMap = {
    {"rank_ultra_short", DistanceRank::TYPE_RANK_ULTRA_SHORT_RANGE},
    {"rank_short", DistanceRank::TYPE_RANK_SHORT_RANGE},
    {"rank_medium_short", DistanceRank::TYPE_RANK_SHORT_MEDIUM_RANGE},
    {"rank_medium", DistanceRank::TYPE_RANK_MEDIUM_RANGE},
};

const std::vector<std::string> EXPECTED_ON_ARG_TYPES_R1 = {"string", "object", "function"};
const std::vector<std::string> EXPECTED_ON_ARG_TYPES_R2 = {"string", "object"};
const std::vector<std::string> EXPECTED_STATIC_ARG_TYPES_R1 = {"object", "function"};
const std::vector<std::string> EXPECTED_STATIC_ARG_TYPES_R2 = {"object"};
const std::string_view SUBSCRIBE_FUNC_NAME = { "CSubscribeDistanceMeasurement" };
const std::string_view UNSUBSCRIBE_FUNC_NAME = { "CUnsubscribeDistanceMeasurement" };
const std::string SPATIAL_AWARENESS_CLIENT_SO_PATH = "libspatial_awareness_client.z.so";
const std::string INPUT_TYPE_RANK_MEASUREMENT = "distanceMeasure";
const std::string INPUT_TYPE_INDOOR_OR_OUTDOOR_IDENTIFY = "indoorOrOutdoorIdentify";
const std::vector<std::string> INPUT_TYPE_VEC = {"distanceMeasure", "indoorOrOutdoorIdentify"};
constexpr size_t MAX_ARG_STRING_LEN = 512;
constexpr int32_t NAPI_INDEX_ZERO = 0;
constexpr int32_t NAPI_INDEX_ONE = 1;
constexpr int32_t NAPI_INDEX_TWO = 2;
} // namespace

std::mutex g_mutex;
std::shared_ptr<OHOS::Msdp::IDistanceMeasurementListener> DistanceMeasurementNapi::distMeasureCallback_ = nullptr;

bool DistanceMeasurementNapi::LoadLibrary()
{
    if (g_DistanceMeasurementNapi->g_distanceMeasurementHandle == nullptr) {
        dlerror(); // 清除之前的错误状态
        g_DistanceMeasurementNapi->g_distanceMeasurementHandle =
            dlopen(SPATIAL_AWARENESS_CLIENT_SO_PATH.c_str(), RTLD_LAZY);
        if (g_DistanceMeasurementNapi->g_distanceMeasurementHandle == nullptr) {
            FI_HILOGE("Load failed, error after: %{public}s", dlerror());
            return false;
        }
    }
    FI_HILOGI("Load library success");
    return true;
}

DistanceMeasurementNapi *DistanceMeasurementNapi::GetDistanceMeasurementNapi()
{
    return g_DistanceMeasurementNapi;
}

void DistanceMeasurementNapi::SetValueUtf8String(const napi_env &env,
    const std::string &fieldStr, const std::string &str, napi_value &result)
{
    napi_handle_scope scope = nullptr;
    napi_status status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok) {
        FI_HILOGE("Failed to open handle scope, error:%{public}d", status);
        return;
    }
    napi_value value = nullptr;
    status = napi_create_string_utf8(env, str.c_str(), NAPI_AUTO_LENGTH, &value);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create UTF-8 string for field: %{public}s, error: %{public}d",
            fieldStr.c_str(), status);
        return;
    }
    if (napi_set_named_property(env, result, fieldStr.c_str(), value) != napi_ok) {
        FI_HILOGE("Failed to set the named property for field: %s", fieldStr.c_str());
        return;
    }
}

void DistanceMeasurementNapi::SetValueDouble(const napi_env &env, const std::string &fieldStr,
    const double &doubleValue, napi_value &result)
{
    napi_value value = nullptr;
    napi_status status = napi_create_double(env, doubleValue, &value);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create double");
        return;
    }
    status = napi_set_named_property(env, result, fieldStr.c_str(), value);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the named property");
        return;
    }
}

void DistanceMeasurementNapi::SetValueInt32(const napi_env &env, const std::string &fieldStr,
    const int32_t &intValue, napi_value &result)
{
    napi_value value = nullptr;
    napi_status status = napi_create_int32(env, intValue, &value);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create int32, error: %{public}d", status);
        return;
    }
    status = napi_set_named_property(env, result, fieldStr.c_str(), value);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the fieldStr named property, error: %{public}d", status);
        return;
    }
}

void DistanceMeasurementNapi::SetValueBool(const napi_env &env, const std::string &fieldStr,
    const bool &boolValue, napi_value &result)
{
    napi_value value = nullptr;
    napi_status status = napi_get_boolean(env, boolValue, &value);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create bool, error: %{public}d", status);
        return;
    }
    status = napi_set_named_property(env, result, fieldStr.c_str(), value);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the fieldStr named property, error: %{public}d", status);
        return;
    }
}

bool DistanceMeasurementNapi::ConstructDistanceMeasurement(
    napi_env env, napi_value jsThis, const int32_t callbackIdx) __attribute__((no_sanitize("cfi")))
{
    if (g_DistanceMeasurementNapi == nullptr) {
        g_DistanceMeasurementNapi = new(std::nothrow) DistanceMeasurementNapi(env, jsThis, callbackIdx);
        if (g_DistanceMeasurementNapi == nullptr) {
            FI_HILOGE("g_DistanceMeasurementNapi is nullptr");
            return false;
        }
        napi_status status = napi_wrap(env, jsThis, reinterpret_cast<void *>(g_DistanceMeasurementNapi),
            [](napi_env env, void *data, void *hint) {
                (void)env;
                (void)hint;
                if (data != nullptr) {
                    DistanceMeasurementNapi *spatial = static_cast<DistanceMeasurementNapi *>(data);
                    g_DistanceMeasurementNapi->ClearEnv();
                    delete spatial;
                    g_DistanceMeasurementNapi = nullptr;
                }
            }, nullptr, nullptr);
        if (status != napi_ok) {
            delete g_DistanceMeasurementNapi;
            g_DistanceMeasurementNapi = nullptr;
            FI_HILOGE("Failed to napi_wrap");
            return false;
        }
    }
    if (g_DistanceMeasurementNapi->env_ != env) {
    FI_HILOGW("call in different thread");
    g_DistanceMeasurementNapi->UpdateEnv(env, jsThis);
    }
    return true;
}

bool DistanceMeasurementNapi::TransJsToStr(napi_env env, napi_value value, std::string &str)
{
    FI_HILOGD("Enter");
    size_t strlen = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("Error string length invalid");
        return false;
    }
    if (strlen > MAX_ARG_STRING_LEN) {
        FI_HILOGE("The string length invalid");
        return false;
    }
    std::vector<char> buf(strlen + 1);
    status = napi_get_value_string_utf8(env, value, buf.data(), strlen+1, &strlen);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_value_string_utf8 failed");
        return false;
    }
    str = std::string(buf.data());
    return true;
}

bool DistanceMeasurementNapi::GetDistanceMeasurementType(const std::string &type)
{
    FI_HILOGD("Enter");
    auto it = std::find(INPUT_TYPE_VEC.begin(), INPUT_TYPE_VEC.end(), type);
    if (it != INPUT_TYPE_VEC.end()) {
        return true;
    }
    for (size_t i = 0; i < INPUT_TYPE_VEC.size(); ++i) {
        FI_HILOGI("expected types, item: %{public}s", INPUT_TYPE_VEC[i].c_str());
    }
    FI_HILOGE("Don't find this type: %{public}s", type.c_str());
    return false;
}

bool DistanceMeasurementNapi::ValidateArgsType(napi_env env, napi_value *args,
    size_t argc, const std::vector<std::string> &expectedTypes)
{
    FI_HILOGD("Enter");
    napi_status status = napi_ok;
    napi_valuetype valueType = napi_undefined;
    
    FI_HILOGI("argc:%{public}zu, expectedTypes.size(): %{public}zu", argc, expectedTypes.size());
    for (size_t i = 0; i < expectedTypes.size(); ++i) {
        FI_HILOGI("expectedTypes, item: %{public}s", expectedTypes[i].c_str());
    }
    
    if (argc != expectedTypes.size()) {
        FI_HILOGE("Wrong number of arguments");
        return false;
    }
    
    for (size_t i = 0; i < argc; ++i) {
        status = napi_typeof(env, args[i], &valueType);
        if (status != napi_ok) {
            FI_HILOGE("Error while checking argument types");
            return false;
        }
        std::string expectedType = expectedTypes[i];
        if ((expectedType == "string" && valueType != napi_string) ||
            (expectedType == "function" && valueType != napi_function) ||
            (expectedType == "number" && valueType != napi_number) ||
            (expectedType == "object" && valueType != napi_object)) {
            FI_HILOGE("Wrong argument type");
            return false;
        }
    }
    return true;
}

std::string DistanceMeasurementNapi::JsObjectToString(const napi_env &env, const napi_value &param)
{
    FI_HILOGI("JsObjectToString in");
    size_t size = 0;
    if (napi_get_value_string_utf8(env, param, nullptr, 0, &size) != napi_ok) {
        return "";
    }
    if (size == 0) {
        return "";
    }
    char *buf = new (std::nothrow) char[size + 1];
    if (buf == nullptr) {
        return "";
    }
    memset_s(buf, (size + 1), 0, (size + 1));
    bool rev = napi_get_value_string_utf8(env, param, buf, size + 1, &size) == napi_ok;
    
    std::string value;
    if (rev) {
        value = buf;
    } else {
        value = "";
    }
    delete[] buf;
    buf = nullptr;
    return value;
}

bool DistanceMeasurementNapi::GetRankMask(napi_env env, napi_value mask, RankMaskType &rankfilter)
{
    uint32_t count = 0;
    napi_status status = napi_get_array_length(env, mask, &count);
    if (status != napi_ok) {
        FI_HILOGE("rank get array length failed!");
        return false;
    }
    for (uint32_t i = 0; i < count; i++) {
        napi_value value {};
        status = napi_get_element(env, mask, i, &value);
        if (status != napi_ok) {
            FI_HILOGE ("rank get element failed");
            return false;
        }
        std::string rankKey = JsObjectToString(env, value);
        for (const auto& pair : g_distanceRankFilterMap) {
            if (pair.first == rankKey) {
                rankfilter.set(pair.second);
            }
        }
    }
    if (rankfilter.none()) {
        FI_HILOGE("array element invalid");
        return false;
    }
    return true;
}

bool DistanceMeasurementNapi::GetDeviceIdList(napi_env env, napi_value deviceValue,
    std::vector<std::string> &deviceIds)
{
    uint32_t count = 0;
    napi_status status = napi_get_array_length(env, deviceValue, &count);
    if (status != napi_ok) {
        FI_HILOGE("get deviceIdList array length failed");
        ThrowErr(env, PARAMETER_EXCEPTION, "get deviceIdList array length failed");
        return false;
    }

    if (count < DEVICES_LIST_MIN_LEN || count > DEVICES_LIST_MAX_LEN) {
        FI_HILOGE("deviceList error, count=%{public}d", count);
        ThrowErr(env, PARAMETER_EXCEPTION, "deviceIdList array length must be between 1 and 128.");
        return false;
    }

    for (uint32_t i = 0; i < count; i++) {
        napi_value value {};
        status = napi_get_element(env, deviceValue, i, &value);
        if (status != napi_ok) {
            FI_HILOGE("get deviceIdList element failed");
            ThrowErr(env, PARAMETER_EXCEPTION, "get deviceIdList element failed");
            return false;
        }

        napi_valuetype valueType;
        status = napi_typeof(env, value, &valueType);
        if (status != napi_ok || valueType != napi_string) {
            FI_HILOGE("device id element type error, expected string, got %{public}d", valueType);
            ThrowErr(env, PARAMETER_EXCEPTION, "device id element must be a string");
            return false;
        }
        std::string deviceId = JsObjectToString(env, value);
        if (deviceId.length() < DEVICES_LIST_MIN_LEN || deviceId.length() > DEVICES_LIST_MAX_LEN) {
            FI_HILOGE(" device id length error, length=%{public}zu", deviceId.length());
            ThrowErr(env, PARAMETER_EXCEPTION, "device id length must be between 1 and 128.");
            return false;
        }
        deviceIds.push_back(deviceId);
    }
    return true;
}

void DistanceMeasurementNapi::OnDoorIdentifyChangedDone(const CDoorPositionResponse &identifyRes)
{
    FI_HILOGI("Enter");
    napi_value identifyObj = nullptr;
    napi_status status = napi_create_object(env_, &identifyObj);
    if (status != napi_ok) {
        FI_HILOGE("failed to create object");
        return;
    }
    SetValueInt32(env_, "doorLockCode", identifyRes.pinCode, identifyObj);
    SetValueInt32(env_, "position", static_cast<int32_t>(identifyRes.position), identifyObj);
    SetValueUtf8String(env_, "deviceId", static_cast<std::string>(identifyRes.deviceId), identifyObj);
    FI_HILOGI("callbackIdx_=%{public}d", callbackIdx_);
   
    OnDistMeasureEvent(callbackIdx_, &identifyObj, INPUT_TYPE_INDOOR_OR_OUTDOOR_IDENTIFY);
}

void DistanceMeasurementNapi::OnDistanceMeasurementChangedDone(const CDistMeasureResponse &distMeasureRes)
{
    FI_HILOGI("Enter");
    napi_value distMeaObj = nullptr;
    napi_status status = napi_create_object(env_, &distMeaObj);
    if (status != napi_ok) {
        FI_HILOGE("failed to create object");
        return;
    }

    SetValueInt32(env_, "rank", static_cast<int32_t>(distMeasureRes.rank), distMeaObj);
    SetValueDouble(env_, "confidence", static_cast<double>(distMeasureRes.confidence), distMeaObj);
    SetValueDouble(env_, "distance", static_cast<double>(distMeasureRes.distance), distMeaObj);
    SetValueUtf8String(env_, "deviceId", distMeasureRes.deviceId, distMeaObj);
    FI_HILOGI("callbackIdx_=%{public}d", callbackIdx_);
    OnDistMeasureEvent(callbackIdx_, &distMeaObj, INPUT_TYPE_RANK_MEASUREMENT);
}

void DistMeasureListener::UpdateEnv(const napi_env &env)
{
    env_ = env;
}

void DistMeasureListener::OnDoorIdentifyChanged(const CDoorPositionResponse &identifyRes) const
{
    FI_HILOGI("Enter");
    CDoorPositionResponse staticIdentifyRes;
    staticIdentifyRes.pinCode = identifyRes.pinCode;
    staticIdentifyRes.position = identifyRes.position;
    staticIdentifyRes.deviceId = identifyRes.deviceId;
    FI_HILOGI("door position=%{public}d",
              static_cast<int32_t>(staticIdentifyRes.position));

    napi_env env = env_;
    auto task = [env, staticIdentifyRes]() {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            FI_HILOGE("Failed to open scope");
            return;
        }
        do {
            DistanceMeasurementNapi *DistanceMeasurementNapi = DistanceMeasurementNapi::GetDistanceMeasurementNapi();
            if (DistanceMeasurementNapi == nullptr) {
                FI_HILOGE("DistanceMeasurementNapi is nullptr");
                return;
            }
            DistanceMeasurementNapi->OnDoorIdentifyChangedDone(staticIdentifyRes);
        } while (0);
        napi_close_handle_scope(env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to send event for auth");
        return;
    }
}

void DistMeasureListener::OnDistanceMeasurementChanged(const CDistMeasureResponse &distMeasureRes) const
{
    FI_HILOGI("Enter");
    CDistMeasureResponse staticDistMeasureRes;
    staticDistMeasureRes.rank = distMeasureRes.rank;
    staticDistMeasureRes.confidence = distMeasureRes.confidence;
    staticDistMeasureRes.distance = distMeasureRes.distance;
    staticDistMeasureRes.deviceId = distMeasureRes.deviceId;
    FI_HILOGI("rank=%{public}d, distance=%{public}f",
              static_cast<int32_t>(staticDistMeasureRes.rank),
              staticDistMeasureRes.distance);

    napi_env env = env_;
    auto task = [env, staticDistMeasureRes]() {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            FI_HILOGE("Failed to open scope");
            return;
        }
        do {
            DistanceMeasurementNapi *DistanceMeasurementNapi = DistanceMeasurementNapi::GetDistanceMeasurementNapi();
            if (DistanceMeasurementNapi == nullptr) {
                FI_HILOGE("DistanceMeasurementNapi is nullptr");
                return;
            }
            DistanceMeasurementNapi->OnDistanceMeasurementChangedDone(staticDistMeasureRes);
        } while (0);
        napi_close_handle_scope(env, scope);
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        FI_HILOGE("Failed to send event for auth");
        return;
    }
}

bool DistanceMeasurementNapi::ParseParams(napi_env env,
    napi_value jsParams, DistanceMeasurementConfigParams& distMeasureParams)
{
    napi_value jsDeviceList;
    napi_status status = napi_get_named_property(env, jsParams, "deviceList", &jsDeviceList);
    if (status != napi_ok) {
        FI_HILOGE("get deviceList failed");
        return false;
    }
    // 检查deviceList是否为数组类型
    bool isArray;
    status = napi_is_array(env, jsDeviceList, &isArray);
    if (status != napi_ok || !isArray) {
        FI_HILOGE("deviceList must be an array");
        ThrowErr(env, PARAMETER_EXCEPTION, "deviceList must be an array");
        return false;
    }
    // 对端设备列表
    if (!GetDeviceIdList(env, jsDeviceList, distMeasureParams.deviceList)) {
        ThrowErr(env, PARAMETER_EXCEPTION, "Get deviceList failed");
        return false;
    }
    // 选择的测距技术类型
    napi_value jsTechType;
    status = napi_get_named_property(env, jsParams, "techType", &jsTechType);
    if (status != napi_ok) {
        FI_HILOGE("Get techType failed");
        return false;
    }
    status = napi_get_value_int32(env, jsTechType, &distMeasureParams.techType);
    if (status != napi_ok) {
        FI_HILOGE("Get technologyType failed");
        ThrowErr(env, PARAMETER_EXCEPTION, "Get technologyType failed");
        return false;
    }
    if (!IsValidTechnologyType(distMeasureParams.techType)) {
        FI_HILOGE("techType must be one of the values in the enum TechnologyType, techType=%{public}d",
            distMeasureParams.techType);
        ThrowErr(env, PARAMETER_EXCEPTION, "techType must be one of the values in the enum TechnologyType");
        return false;
    }
    // 结果上报模式
    if (!isValidReportMode(env, jsParams, distMeasureParams)) {
        return false;
    }
    // 结果上报频率
    if (!isValidReportFrequency(env, jsParams, distMeasureParams)) {
        return false;
    }
    return true;
}

bool DistanceMeasurementNapi::IsValidTechnologyType(int32_t techType)
{
    switch (techType) {
        case TechnologyType::BLE_RSSI:
        case TechnologyType::WIFI_RSSI:
        case TechnologyType::ULTRASOUND:
        case TechnologyType::NEARLINK:
        case TechnologyType::WIFI_BLE_RSSI:
            return true;
        default:
            return false;
    }
}

bool DistanceMeasurementNapi::isValidReportMode(napi_env env,
    napi_value jsParams, DistanceMeasurementConfigParams& distMeasureParams)
{
    napi_value jsRepMode;
    napi_status status  = napi_get_named_property(env, jsParams, "reportMode", &jsRepMode);
    if (status != napi_ok) {
        FI_HILOGE("get reportMode failed");
        return false;
    }
    status = napi_get_value_int32(env, jsRepMode, &distMeasureParams.reportMode);
    if (status != napi_ok) {
        FI_HILOGE("Get reportMode failed");
        ThrowErr(env, PARAMETER_EXCEPTION, "Get reportMode failed");
        return false;
    }
    if (distMeasureParams.reportMode != ReportingMode::REPORT_MODE_PERIODIC_REPORTING &&
        distMeasureParams.reportMode !=ReportingMode::REPORT_MODE_TRIGGERED_REPORTING) {
        FI_HILOGE("reportMode error, reportMode=%{public}d", distMeasureParams.reportMode);
        ThrowErr(env, PARAMETER_EXCEPTION, "reportMode must be one of the values in the enum ReportingMode");
        return false;
    }
    return true;
}

bool DistanceMeasurementNapi::isValidReportFrequency(napi_env env,
    napi_value jsParams, DistanceMeasurementConfigParams& distMeasureParams)
{
    napi_value jsRepRreq;
    napi_status status  = napi_get_named_property(env, jsParams, "reportFrequency", &jsRepRreq);
    if (status != napi_ok) {
        FI_HILOGE("get reportFrequency failed");
        return false;
    }
    status = napi_get_value_int32(env, jsRepRreq, &distMeasureParams.reportFrequency);
    if (status != napi_ok) {
        FI_HILOGE("Get reportFrequency failed");
        ThrowErr(env, PARAMETER_EXCEPTION, "Get reportFrequency failed");
        return false;
    }
    if (distMeasureParams.reportFrequency < REPORT_FREQUENCY_MIN_VALUE ||
        distMeasureParams.reportFrequency > REPORT_FREQUENCY_MAX_VALUE) {
        FI_HILOGE("reportFrequency error, reportFrequency=%{public}d", distMeasureParams.reportFrequency);
        ThrowErr(env, PARAMETER_EXCEPTION, "reportFrequency must be between 0 and 999999.");
        return false;
    }
    FI_HILOGI("Input reportFrequency: %{public}d", distMeasureParams.reportFrequency);
    return true;
}

napi_value DistanceMeasurementNapi::OnDistanceMeasurement(napi_env env, napi_callback_info info)
{
    FI_HILOGI("OnDistanceMeasurement Enter");
    size_t argc = NAPI_INDEX_TWO;
    napi_value args[NAPI_INDEX_TWO] = { 0 };
    napi_value jsThis;
    void *data = nullptr;
    napi_value result = nullptr;

    if (napi_get_cb_info(env, info, &argc, args, &jsThis, &data) != napi_ok) {
        ThrowErr(env, PARAMETER_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    FI_HILOGI("argc=%{public}zu", argc);

    if (!ValidateArgsType(env, args, argc, EXPECTED_STATIC_ARG_TYPES_R1)) {
        ThrowErr(env, PARAMETER_EXCEPTION, "ValidateArgsType failed");
        return nullptr;
    }
  
    DistanceMeasurementConfigParams distMeasureParams;
    if (!ParseParams(env, args[NAPI_INDEX_ZERO], distMeasureParams)) {
        ThrowErr(env, PARAMETER_EXCEPTION, "Get configParams failed");
        return nullptr;
    }
    CDistMeasureData cdistMeasureData {
        .type = INPUT_TYPE_RANK_MEASUREMENT,
        .deviceIds = distMeasureParams.deviceList,
        .technologyType = distMeasureParams.techType,
        .reportMode = distMeasureParams.reportMode,
        .reportFreq = distMeasureParams.reportFrequency
    };
    if (!DoSubscribe(env, jsThis, args[NAPI_INDEX_ONE], NAPI_INDEX_ONE, cdistMeasureData)) {
        return nullptr;
    }
    if (napi_get_undefined(env, &result) != napi_ok) {
        ThrowErr(env, SUBSCRIBE_EXCEPTION, "napi_get_undefined failed");
    }
    FI_HILOGI("OnDistanceMeasurement Exit");
    return result;
}

napi_value DistanceMeasurementNapi::OnIndoorOrOutdoorIdentify(napi_env env, napi_callback_info info)
{
    FI_HILOGI("OnIndoorOrOutdoorIdentify Enter");
    size_t argc = NAPI_INDEX_TWO;
    napi_value args[NAPI_INDEX_TWO] = { 0 };
    napi_value jsThis;
    void *data = nullptr;
    napi_value result = nullptr;

    if (napi_get_cb_info(env, info, &argc, args, &jsThis, &data) != napi_ok) {
        ThrowErr(env, PARAMETER_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    FI_HILOGI("argc=%{public}zu", argc);

    if (!ValidateArgsType(env, args, argc, EXPECTED_STATIC_ARG_TYPES_R1)) {
        ThrowErr(env, PARAMETER_EXCEPTION, "ValidateArgsType failed");
        return nullptr;
    }
   
    DistanceMeasurementConfigParams distMeasureParams;
    if (!ParseParams(env, args[NAPI_INDEX_ZERO], distMeasureParams)) {
        ThrowErr(env, PARAMETER_EXCEPTION, "Get configParams failed");
        return nullptr;
    }
    CDistMeasureData cdistMeasureData {
        .type = INPUT_TYPE_INDOOR_OR_OUTDOOR_IDENTIFY,
        .deviceIds = distMeasureParams.deviceList,
        .technologyType = distMeasureParams.techType,
        .reportMode = distMeasureParams.reportMode,
        .reportFreq = distMeasureParams.reportFrequency
    };
    if (!DoSubscribe(env, jsThis, args[NAPI_INDEX_ONE], NAPI_INDEX_ONE, cdistMeasureData)) {
        return nullptr;
    }
    if (napi_get_undefined(env, &result) != napi_ok) {
        ThrowErr(env, SUBSCRIBE_EXCEPTION, "napi_get_undefined failed");
    }
    FI_HILOGI("OnIndoorOrOutdoorIdentify Exit");
    return result;
}

bool DistanceMeasurementNapi::DoSubscribe(napi_env env, napi_value jsThis,
    napi_value callback, const int32_t callbackIdx, const CDistMeasureData &cdistMeasureData)
{
    std::lock_guard<std::mutex> guard(g_mutex);
    if (!ConstructDistanceMeasurement(env, jsThis, callbackIdx)) {
        ThrowErr(env, SUBSCRIBE_EXCEPTION, "Failed to get g_DistanceMeasurementNapi");
        return false;
    }
    if (g_DistanceMeasurementNapi->g_distanceMeasurementHandle == nullptr && !LoadLibrary()) {
        ThrowErr(env, DEVICE_EXCEPTION, "Device not support");
        return false;
    }

    if (!CreateDistMeasureCallback(env, callback, cdistMeasureData)) {
        ThrowErr(env, SERVICE_EXCEPTION, "Create distance measurement callback failed");
        return false;
    }
    return true;
}

bool DistanceMeasurementNapi::CreateDistMeasureCallback(napi_env env,
    napi_value callback, CDistMeasureData cdistMeasureData)
{
    FI_HILOGI("Enter");
    if (g_DistanceMeasurementNapi == nullptr) {
        return false;
    }
    if (!g_DistanceMeasurementNapi->AddCallback(cdistMeasureData, callback)) {
        return false;
    }
    if (distMeasureCallback_ == nullptr) {
        FI_HILOGI("Don't find callback, to create");
        if (g_DistanceMeasurementNapi->g_subscribeDistanceMeasurementFunc == nullptr) {
            FI_HILOGI("g_subscribeDistanceMeasurementFunc create start");
            g_DistanceMeasurementNapi->g_subscribeDistanceMeasurementFunc =
                reinterpret_cast<SubscribeDistanceMeasurementFunc>(
                dlsym(g_DistanceMeasurementNapi->g_distanceMeasurementHandle, SUBSCRIBE_FUNC_NAME.data()));
            FI_HILOGI("g_subscribeDistanceMeasurementFunc create end");
            if (g_DistanceMeasurementNapi->g_subscribeDistanceMeasurementFunc == nullptr) {
                FI_HILOGE("%{public}s find symbol failed, error: %{public}s", SUBSCRIBE_FUNC_NAME.data(), dlerror());
                return false;
            }
        }
    } else {
        distMeasureCallback_->UpdateEnv(env);
    }
    std::shared_ptr<OHOS::Msdp::IDistanceMeasurementListener> listener =
        std::make_shared<DistMeasureListener>(env);
    FI_HILOGI("g_subscribeDistanceMeasurementFunc call start");
    int32_t ret = g_DistanceMeasurementNapi->g_subscribeDistanceMeasurementFunc(
        listener, cdistMeasureData);
    FI_HILOGI("g_subscribeDistanceMeasurementFunc call end");
    if (ret != 0) {
        FI_HILOGE("Subscribe distance measurement callback failed");
        g_DistanceMeasurementNapi->RemoveCallback(cdistMeasureData);
        return false;
    }
    distMeasureCallback_ = listener;
    return true;
}

bool DistanceMeasurementNapi::DeleteDistMeasureCallback(napi_value callback,
    CDistMeasureData cdistMeasureData)
{
    FI_HILOGI("Enter");
    if (distMeasureCallback_ == nullptr) {
        FI_HILOGI("never before Subscribe  distance measurement callback");
        return true;
    }
    if (g_DistanceMeasurementNapi == nullptr) {
        return false;
    }
    if (g_DistanceMeasurementNapi->g_unsubscribeDistanceMeasurementFunc == nullptr) {
        g_DistanceMeasurementNapi->g_unsubscribeDistanceMeasurementFunc =
            reinterpret_cast<UnsubscribeDistanceMeasurementFunc>(
            dlsym(g_DistanceMeasurementNapi->g_distanceMeasurementHandle, UNSUBSCRIBE_FUNC_NAME.data()));
        if (g_DistanceMeasurementNapi->g_unsubscribeDistanceMeasurementFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", UNSUBSCRIBE_FUNC_NAME.data(), dlerror());
            return false;
        }
    }
    int32_t ret = g_DistanceMeasurementNapi->g_unsubscribeDistanceMeasurementFunc(cdistMeasureData);
    if (ret != 0) {
        FI_HILOGE("Unsubscribe distance measurement callback failed");
        return false;
    }
    g_DistanceMeasurementNapi->RemoveCallback(cdistMeasureData);
    return true;
}

napi_value DistanceMeasurementNapi::OffDistanceMeasurement(napi_env env, napi_callback_info info)
{
    FI_HILOGI("OffDistanceMeasurement Enter");
    if (g_DistanceMeasurementNapi == nullptr) {
        ThrowErr(env, UNSUBSCRIBE_EXCEPTION, "g_DistanceMeasurementNapi is nullptr");
        return nullptr;
    }
    size_t argc = NAPI_INDEX_TWO;
    napi_value args[NAPI_INDEX_TWO] = { 0 };
    napi_value jsThis;
    void *data = nullptr;
    napi_value result = nullptr;

    if (napi_get_cb_info(env, info, &argc, args, &jsThis, &data) != napi_ok) {
        ThrowErr(env, PARAMETER_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    FI_HILOGI("argc=%{public}zu", argc);
    std::vector<std::string> expectedTypes;
    if (argc == NAPI_INDEX_TWO) {
        expectedTypes = EXPECTED_STATIC_ARG_TYPES_R1;
    } else {
        expectedTypes = EXPECTED_STATIC_ARG_TYPES_R2;
    }
    if (!ValidateArgsType(env, args, argc, expectedTypes)) {
        ThrowErr(env, PARAMETER_EXCEPTION, "ValidateArgsType failed");
        return nullptr;
    }
    if (!DoUnsubscribe(env, args[NAPI_INDEX_ZERO], args[NAPI_INDEX_ONE],
        INPUT_TYPE_RANK_MEASUREMENT)) {
        return nullptr;
    }
    if (napi_get_undefined(env, &result) != napi_ok) {
        ThrowErr(env, UNSUBSCRIBE_EXCEPTION, "napi_get_undefined failed");
    }
    FI_HILOGI("OffDistanceMeasurement Exit");
    return result;
}

napi_value DistanceMeasurementNapi::OffIndoorOrOutdoorIdentify(napi_env env, napi_callback_info info)
{
    FI_HILOGI("OffIndoorOrOutdoorIdentify Enter");
    if (g_DistanceMeasurementNapi == nullptr) {
        ThrowErr(env, UNSUBSCRIBE_EXCEPTION, "g_DistanceMeasurementNapi is nullptr");
        return nullptr;
    }
    size_t argc = NAPI_INDEX_TWO;
    napi_value args[NAPI_INDEX_TWO] = { 0 };
    napi_value jsThis;
    void *data = nullptr;
    napi_value result = nullptr;

    if (napi_get_cb_info(env, info, &argc, args, &jsThis, &data) != napi_ok) {
        ThrowErr(env, PARAMETER_EXCEPTION, "napi_get_cb_info failed");
        return nullptr;
    }
    FI_HILOGI("argc=%{public}zu", argc);
    std::vector<std::string> expectedTypes;
    if (argc == NAPI_INDEX_TWO) {
        expectedTypes = EXPECTED_STATIC_ARG_TYPES_R1;
    } else {
        expectedTypes = EXPECTED_STATIC_ARG_TYPES_R2;
    }
    if (!ValidateArgsType(env, args, argc, expectedTypes)) {
        ThrowErr(env, PARAMETER_EXCEPTION, "ValidateArgsType failed");
        return nullptr;
    }
    if (!DoUnsubscribe(env, args[NAPI_INDEX_ZERO], args[NAPI_INDEX_ONE],
        INPUT_TYPE_INDOOR_OR_OUTDOOR_IDENTIFY)) {
        return nullptr;
    }
    if (napi_get_undefined(env, &result) != napi_ok) {
        ThrowErr(env, UNSUBSCRIBE_EXCEPTION, "napi_get_undefined failed");
    }
    FI_HILOGI("OffIndoorOrOutdoorIdentify Exit");
    return result;
}

bool DistanceMeasurementNapi::DoUnsubscribe(napi_env env, napi_value jsParams,
    napi_value callback, const std::string &typeStr)
{
    DistanceMeasurementConfigParams distMeasureParams;
    if (!ParseParams(env, jsParams, distMeasureParams)) {
        ThrowErr(env, PARAMETER_EXCEPTION, "Get configParams failed");
        return false;
    }
    std::lock_guard<std::mutex> guard(g_mutex);
    if (g_DistanceMeasurementNapi->g_distanceMeasurementHandle == nullptr && !LoadLibrary()) {
        ThrowErr(env, DEVICE_EXCEPTION, "Device not support");
        return false;
    }
    CDistMeasureData cdistMeasureData {
        .type = typeStr,
        .deviceIds = distMeasureParams.deviceList,
        .technologyType = distMeasureParams.techType,
        .reportMode = distMeasureParams.reportMode,
        .reportFreq = distMeasureParams.reportFrequency
    };
    if (!DeleteDistMeasureCallback(callback, cdistMeasureData)) {
        ThrowErr(env, SERVICE_EXCEPTION, "Delete distance measurement callback failed");
        return false;
    }
    return true;
}

napi_value DistanceMeasurementNapi::ModeInit(napi_env env, napi_value exports)
{
    FI_HILOGI("ModeInit Enter");
    DefineDistanceRank(env, exports);
    FI_HILOGI("Exit");
    return exports;
}

void DistanceMeasurementNapi::SetPropertyName(napi_env env, napi_value targetObj,
    const char *propName, napi_value propValue)
{
    napi_status status = napi_set_named_property(env, targetObj, propName, propValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set the name property");
        return;
    }
}

void DistanceMeasurementNapi::SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_int32(env, value, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        return;
    }
    SetPropertyName(env, targetObj, propName, prop);
}

void DistanceMeasurementNapi::SetUtf8StringProperty(napi_env env, napi_value targetObj,
    const std::string &value, const char *propName)
{
    napi_value prop = nullptr;
    napi_status ret = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &prop);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_string_utf8 failed");
        return;
    }
    SetPropertyName(env, targetObj, propName, prop);
}

void DistanceMeasurementNapi::DefineDistanceRank(napi_env env, napi_value exports)
{
    napi_value distanceRank;
    napi_status status = napi_create_object(env, &distanceRank);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create object");
        return;
    }
    SetUtf8StringProperty(env, distanceRank, "rank_ultra_short", "TYPE_RANK_ULTRA_SHORT_RANGE");
    SetUtf8StringProperty(env, distanceRank, "rank_short", "TYPE_RANK_SHORT_RANGE");
    SetUtf8StringProperty(env, distanceRank, "rank_medium_short", "TYPE_RANK_SHORT_MEDIUM_RANGE");
    SetUtf8StringProperty(env, distanceRank, "rank_medium", "TYPE_RANK_MEDIUM_RANGE");
    SetPropertyName(env, exports, "DistanceRank", distanceRank);
}

napi_value DistanceMeasurementNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("onDistanceMeasure", OnDistanceMeasurement),
        DECLARE_NAPI_STATIC_FUNCTION("offDistanceMeasure", OffDistanceMeasurement),
        DECLARE_NAPI_STATIC_FUNCTION("onIndoorOrOutdoorIdentify", OnIndoorOrOutdoorIdentify),
        DECLARE_NAPI_STATIC_FUNCTION("offIndoorOrOutdoorIdentify", OffIndoorOrOutdoorIdentify)
    };

    FI_HILOGI("DistanceMeasurementNapi init is called");
    MSDP_CALL(napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    ModeInit(env, exports);
    return exports;
}

DistanceMeasurementNapi::DistanceMeasurementNapi(napi_env env, napi_value thisVar,
    int32_t callbackIdx) : DistanceMeasurementEventNapi(env, thisVar, callbackIdx) {}

DistanceMeasurementNapi::~DistanceMeasurementNapi()
{
    if (g_distanceMeasurementHandle != nullptr) {
        dlclose(g_distanceMeasurementHandle);
        g_distanceMeasurementHandle = nullptr;
        FI_HILOGI("Remove g_distanceMeasurementHandle.");
    }
    g_subscribeDistanceMeasurementFunc = nullptr;
    g_unsubscribeDistanceMeasurementFunc = nullptr;
}

/*
 * Function registering all props and functions of ohos.msdp
 */
static napi_value Export(napi_env env, napi_value exports)
{
    FI_HILOGI("Export is called");
    DistanceMeasurementNapi::Init(env, exports);
    return exports;
}

/*
 * Module define
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "multimodalAwareness.distanceMeasurement",
    .nm_register_func = Export,
    .nm_modname = "multimodalAwareness.distanceMeasurement",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

/*
 * Module registration
 */
extern "C" __attribute__((constructor)) void RegisterModuleDistanceMeasurement(void)
{
    FI_HILOGI("RegisterModuleDistanceMeasurement is called");
    napi_module_register(&g_module);
}
} // namespace Msdp
} // namespace OHOS
