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

#ifndef DISTANCE_MEASUREMENT_NAPI_H
#define DISTANCE_MEASUREMENT_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "distance_measurement_event_napi.h"
#include "distance_measurement_callback.h"

namespace OHOS {
namespace Msdp {
constexpr int32_t DEVICE_ID_MIN_LEN {1};
constexpr int32_t DEVICE_ID_MAX_LEN {128};
constexpr int32_t DEVICES_LIST_MIN_LEN {1};
constexpr int32_t DEVICES_LIST_MAX_LEN {128};
constexpr int32_t REPORT_FREQUENCY_MIN_VALUE {0};
constexpr int32_t REPORT_FREQUENCY_MAX_VALUE {999999};

using RankMaskType = DistanceMeasurementEventNapi::RankMaskType;
using DistanceRank = DistanceMeasurementEventNapi::DistanceRank;
using TechnologyType = DistanceMeasurementEventNapi::TechnologyType;
using ReportingMode = DistanceMeasurementEventNapi::ReportingMode;
using CDistMeasureResponse = DistanceMeasurementEventNapi::CDistMeasureResponse;
using CDoorPositionResponse = DistanceMeasurementEventNapi::CDoorPositionResponse;
using DistanceMeasurementConfigParams = DistanceMeasurementEventNapi::DistanceMeasurementConfigParams;

typedef int32_t (*SubscribeDistanceMeasurementFunc)(
    std::shared_ptr<OHOS::Msdp::IDistanceMeasurementListener> listener,
    const CDistMeasureData &cdistMeasureData);
typedef int32_t (*UnsubscribeDistanceMeasurementFunc)(const CDistMeasureData &cdistMeasureData);
class DistMeasureListener : public IDistanceMeasurementListener {
public:
    explicit DistMeasureListener(napi_env env) : env_(env) {}
    virtual ~DistMeasureListener() = default;
    void OnDistanceMeasurementChanged(const CDistMeasureResponse &distMeasureRes) const;
    void OnDoorIdentifyChanged(const CDoorPositionResponse &indentifyRes) const;
    void UpdateEnv(const napi_env &env);
private:
    std::atomic<napi_env> env_;
};

class DistanceMeasurementNapi : public DistanceMeasurementEventNapi {
public:
    explicit DistanceMeasurementNapi(napi_env env, napi_value thisVar, int32_t callbackIdx);
    virtual ~DistanceMeasurementNapi();

    static DistanceMeasurementNapi *GetDistanceMeasurementNapi();
    static napi_value ModeInit(napi_env env, napi_value exports);
    static napi_value Init(napi_env env, napi_value exports);
    static void DefineDistanceRank(napi_env env, napi_value exports);
    static napi_value OnDistanceMeasurement(napi_env env, napi_callback_info info);
    static napi_value OffDistanceMeasurement(napi_env env, napi_callback_info info);
    static napi_value OnIndoorOrOutdoorIdentify(napi_env env, napi_callback_info info);
    static napi_value OffIndoorOrOutdoorIdentify(napi_env env, napi_callback_info info);
    void OnDistanceMeasurementChangedDone(const CDistMeasureResponse &distMeasureRes);
    void OnDoorIdentifyChangedDone(const CDoorPositionResponse &indentifyRes);

private:
    static bool LoadLibrary();
    static void SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName);
    static void SetUtf8StringProperty(napi_env env, napi_value targetObj,
        const std::string &value, const char *propName);
    static void SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);
    static void SetValueUtf8String(const napi_env &env, const std::string &fieldStr,
        const std::string &str, napi_value &result);
    static void SetValueInt32(const napi_env &env, const std::string &fieldStr,
        const int32_t &intValue, napi_value &result);
    static void SetValueDouble(const napi_env &env, const std::string &fieldStr,
        const double &doubleValue, napi_value &result);
    static void SetValueBool(const napi_env &env, const std::string &fieldStr,
        const bool &boolValue, napi_value &result);
    static bool DoSubscribe(napi_env env, napi_value jsThis, napi_value callback, const int32_t callbackIdx,
        const CDistMeasureData &cdistMeasureData);
    static bool DoUnsubscribe(napi_env env, napi_value jsParams, napi_value callback,
        const std::string &typeStr);
    static bool ConstructDistanceMeasurement(napi_env env, napi_value jsThis, const int32_t callbackIdx);
    static bool GetDistanceMeasurementType(const std::string &type);
    static bool TransJsToStr(napi_env env, napi_value value, std::string &str);
    static bool ValidateArgsType(napi_env env, napi_value *args, size_t argc,
        const std::vector<std::string> &expectedTypes);
    static std::string JsObjectToString(const napi_env &env, const napi_value &object);
    static bool GetRankMask(napi_env env, napi_value mask, RankMaskType &rankfilter);
    static bool GetDeviceIdList(napi_env env, napi_value deviceValue, std::vector<std::string> &deviceIds);
    static bool ParseParams(napi_env env, napi_value jsParams,
        DistanceMeasurementConfigParams& distMeasureParams);
    static bool CreateDistMeasureCallback(napi_env env, napi_value callback,
        CDistMeasureData cdistMeasureData);
    static bool DeleteDistMeasureCallback(napi_value callback, CDistMeasureData cdistMeasureData);
    static bool IsValidTechnologyType(int32_t techType);
    static bool isValidReportMode(napi_env env, napi_value jsParams,
        DistanceMeasurementConfigParams& distMeasureParams);
    static bool isValidReportFrequency(napi_env env, napi_value jsParams,
        DistanceMeasurementConfigParams& distMeasureParams);

private:
    void* g_distanceMeasurementHandle = nullptr;
    SubscribeDistanceMeasurementFunc g_subscribeDistanceMeasurementFunc = nullptr;
    UnsubscribeDistanceMeasurementFunc g_unsubscribeDistanceMeasurementFunc = nullptr;
    static std::shared_ptr<OHOS::Msdp::IDistanceMeasurementListener> distMeasureCallback_;
};
} // namespace Msdp
} // namespace OHOS
#endif // DISTANCE_MEASUREMENT_NAPI_H