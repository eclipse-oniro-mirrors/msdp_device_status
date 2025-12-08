/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <dlfcn.h>

#include "ets_spatialawareness_manager.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "EtsSpatialAwarenessManager"

namespace OHOS {
namespace Msdp {
constexpr int32_t DEVICE_ID_MIN_LEN { 1 };
constexpr int32_t DEVICE_ID_MAX_LEN { 128 };
constexpr int32_t DEVICES_LIST_MIN_LEN { 1 };
constexpr int32_t DEVICES_LIST_MAX_LEN { 128 };
constexpr int32_t TECHNOLOGY_TYPE_MIN_VALUE { 0 };
constexpr int32_t TECHNOLOGY_TYPE_MAX_VALUE { 4 };
constexpr int32_t REPORT_MODE_MIN_VALUE { 0 };
constexpr int32_t REPORT_MODE_MAX_VALUE { 1 };
constexpr int32_t REPORT_FREQUENCY_MIN_VALUE { 0 };
constexpr int32_t REPORT_FREQUENCY_MAX_VALUE { 999999 };
constexpr int32_t DEVICE_EXCEPTION { 801 };
constexpr int32_t SERVICE_EXCEPTION { 35100001 };
constexpr int32_t PARAMETER_EXCEPTION { 35100004 };
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

void EtsSpatialAwarenessManager::OnDistanceMeasurementChanged(const CDistMeasureResponse &distMeasureRes)
{
    FI_HILOGI("Enter");
    FI_HILOGI("rank=%{public}d, distance=%{public}f",
        static_cast<int32_t>(distMeasureRes.rank), distMeasureRes.distance);

    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (jsCbMap_.empty()) {
        FI_HILOGE("The listener list is empty");
        return;
    }

    distMeasureDataSet_.type = INPUT_TYPE_RANK_MEASUREMENT;
    auto changeEvent = jsCbMap_.find(distMeasureDataSet_);
    if (changeEvent == jsCbMap_.end()) {
        FI_HILOGE("OnDistanceMeasurementChanged find distMeasureDataSet_ failed");
        return;
    }
    for (auto &item : changeEvent->second) {
        auto &func = std::get<taihe::callback<void(DistMeasureResponse const&)>>(item->callback);
        DistMeasureResponse response = {
            .rank = DistanceRank::from_value(std::string_view("rankMediumShort")),
            .distance = distMeasureRes.distance,
            .confidence = distMeasureRes.confidence,
            .deviceId = std::string_view(distMeasureRes.deviceId)
        };
        func(response);
    }
    FI_HILOGI("Exit");
}

void EtsSpatialAwarenessManager::OnDoorIdentifyChanged(const CDoorPositionResponse &identifyRes)
{
    FI_HILOGI("Enter");
    FI_HILOGI("door position=%{public}d", static_cast<int32_t>(identifyRes.position));

    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (jsCbMap_.empty()) {
        FI_HILOGE("The listener list is empty");
        return;
    }

    distMeasureDataSet_.type = INPUT_TYPE_INDOOR_OR_OUTDOOR_IDENTIFY;
    auto changeEvent = jsCbMap_.find(distMeasureDataSet_);
    if (changeEvent == jsCbMap_.end()) {
        FI_HILOGE("OnDoorIdentifyChanged find distMeasureDataSet_ failed");
        return;
    }
    for (auto &item : changeEvent->second) {
        auto &func = std::get<taihe::callback<void(DoorPositionResponse const&)>>(item->callback);
        DoorPositionResponse response = {
            .doorLockCode = identifyRes.pinCode,
            .position = PositionRelativeToDoor::from_value(static_cast<int32_t>(identifyRes.position)),
            .deviceId = std::string_view(identifyRes.deviceId)
        };
        func(response);
    }
    FI_HILOGI("Exit");
}

std::shared_ptr<EtsSpatialAwarenessManager> EtsSpatialAwarenessManager::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<EtsSpatialAwarenessManager> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<EtsSpatialAwarenessManager>();
    });
    return instance_;
}

bool EtsSpatialAwarenessManager::LoadLibrary()
{
    FI_HILOGI("Enter");
    if (distanceMeasurementHandle == nullptr) {
        distanceMeasurementHandle = dlopen(SPATIAL_AWARENESS_CLIENT_SO_PATH.c_str(), RTLD_LAZY);
        if (distanceMeasurementHandle == nullptr) {
            FI_HILOGE("Load failed, error after: %{public}s", dlerror());
            return false;
        }
    }
    FI_HILOGI("Exit");
    return true;
}

void EtsSpatialAwarenessManager::OnDistanceMeasure(DistanceMeasurementConfigParams const& configParams,
    callback_view<void(DistMeasureResponse const&)> callback, uintptr_t opq)
{
    FI_HILOGI("Enter");
    Subscribe(configParams, callback, opq, INPUT_TYPE_RANK_MEASUREMENT);
    FI_HILOGI("Exit");
}

void EtsSpatialAwarenessManager::OffDistanceMeasure(DistanceMeasurementConfigParams const& configParams,
    optional_view<uintptr_t> opq)
{
    FI_HILOGI("Enter");
    Unsubscribe(configParams, opq, INPUT_TYPE_RANK_MEASUREMENT);
    FI_HILOGI("Exit");
}

void EtsSpatialAwarenessManager::OnIndoorOrOutdoorIdentify(DistanceMeasurementConfigParams const& configParams,
    callback_view<void(DoorPositionResponse const&)> callback, uintptr_t opq)
{
    FI_HILOGI("Enter");
    Subscribe(configParams, callback, opq, INPUT_TYPE_INDOOR_OR_OUTDOOR_IDENTIFY);
    FI_HILOGI("Exit");
}

void EtsSpatialAwarenessManager::OffIndoorOrOutdoorIdentify(DistanceMeasurementConfigParams const& configParams,
    optional_view<uintptr_t> opq)
{
    FI_HILOGI("Enter");
    Unsubscribe(configParams, opq, INPUT_TYPE_INDOOR_OR_OUTDOOR_IDENTIFY);
    FI_HILOGI("Exit");
}

void EtsSpatialAwarenessManager::Subscribe(DistanceMeasurementConfigParams const& configParams, callbackType &&f,
    uintptr_t opq, const std::string &type)
{
    FI_HILOGI("Enter");
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        FI_HILOGE("ani_env is nullptr or GlobalReference_Create failed");
        return;
    }

    if (!VerifyParams(configParams, distMeasureDataSet_)) {
        FI_HILOGE("Subscribe parameter validation failed!");
        return;
    }
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        distMeasureDataSet_.type = type;
        auto &cbVec = jsCbMap_[distMeasureDataSet_];
        bool isDuplicate = std::any_of(cbVec.begin(), cbVec.end(), [env, callbackRef](
            std::shared_ptr<CallbackObject> &obj) {
            ani_boolean isEqual = false;
            return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
        });
        if (isDuplicate) {
            env->GlobalReference_Delete(callbackRef);
            FI_HILOGD("Subscribe callback already registered");
            return;
        }
        cbVec.emplace_back(std::make_shared<CallbackObject>(f, callbackRef));
    }
    FI_HILOGI("Subscribe add callback success");

    InitDependencyLibrary();
    if (!SubscribeDistanceMeasurement(distMeasureDataSet_)) {
        RemoveFailCallback(env, distMeasureDataSet_, opq, jsCbMap_);
        taihe::set_business_error(SERVICE_EXCEPTION, "Call subscribeDistanceMeasurement failed.");
        return;
    }
    FI_HILOGI("Exit");
}

void EtsSpatialAwarenessManager::Unsubscribe(DistanceMeasurementConfigParams const& configParams,
    optional_view<uintptr_t> opq, const std::string &type)
{
    FI_HILOGI("Enter");
    if (!VerifyParams(configParams, distMeasureDataSet_)) {
        FI_HILOGE("Unsubscribe parameter validation failed!");
        return;
    }
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        distMeasureDataSet_.type = type;
        const auto iter = jsCbMap_.find(distMeasureDataSet_);
        if (iter == jsCbMap_.end()) {
            FI_HILOGE("Not exist distMeasureDataSet_");
            return;
        }
        if (!opq.has_value()) {
            jsCbMap_.erase(iter);
            FI_HILOGD("Unsubscribe callback is nullptr!");
            return;
        }
        if (!RemoveCallback(iter, opq)) {
            FI_HILOGD("Remove callback failed!");
            return;
        }
    }
    FI_HILOGI("Unsubscribe delete callback success");

    InitDependencyLibrary();
    if (!UnsubscribeDistanceMeasurement(distMeasureDataSet_)) {
        taihe::set_business_error(SERVICE_EXCEPTION, "Call unsubscribeDistanceMeasurement failed.");
        return;
    }
    FI_HILOGI("Exit");
}

bool EtsSpatialAwarenessManager::RemoveCallback(const std::map<CDistMeasureData,
    std::vector<std::shared_ptr<CallbackObject>>>::iterator &iter, optional_view<uintptr_t> opq)
{
    FI_HILOGI("Enter");
    auto env = taihe::get_env();
    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (env == nullptr || !guard) {
        FI_HILOGE("env is nullptr or GlobalRefGuard is false!");
        return false;
    }
    const auto pred = [env, targetRef = guard.get()](std::shared_ptr<CallbackObject> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &is_equal)) && is_equal;
    };
    auto &callbacks = iter->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        FI_HILOGI("Unsubscribe callback success");
        callbacks.erase(it);
    }
    if (callbacks.empty()) {
        jsCbMap_.erase(iter);
    }
    FI_HILOGI("Exit");
    return true;
}

bool EtsSpatialAwarenessManager::VerifyParams(DistanceMeasurementConfigParams const& configParams,
    CDistMeasureData &distMeasureDataSet)
{
    FI_HILOGI("Enter");
    uint32_t count = configParams.deviceList.size();
    if (count < DEVICES_LIST_MIN_LEN || count > DEVICES_LIST_MAX_LEN) {
        FI_HILOGE("deviceList error, count=%{public}d", count);
        taihe::set_business_error(PARAMETER_EXCEPTION, "deviceIdList array length must be between 1 and 128.");
        return false;
    }

    for (uint32_t i = 0; i < count; i++) {
        std::string deviceId = configParams.deviceList[i].c_str();
        if (deviceId.length() < DEVICE_ID_MIN_LEN || deviceId.length() > DEVICE_ID_MAX_LEN) {
            FI_HILOGE("device id length error, length=%{public}lu", static_cast<unsigned long>(deviceId.length()));
            taihe::set_business_error(PARAMETER_EXCEPTION, "device id length must be between 1 and 128.");
            return false;
        }
        distMeasureDataSet.deviceIds.push_back(deviceId);
    }

    // 选择的测距技术类型
    int32_t techType = static_cast<int32_t>(configParams.techType);
    if (!IsValidTechnologyType(techType)) {
        taihe::set_business_error(PARAMETER_EXCEPTION,
            "techType must be one of the values in the enum TechnologyType.");
        return false;
    }
    distMeasureDataSet.technologyType = techType;

    // 结果上报模式
    int32_t reportMode = static_cast<int32_t>(configParams.reportMode);
    if (!IsValidReportMode(reportMode)) {
        taihe::set_business_error(PARAMETER_EXCEPTION,
            "reportMode must be one of the values in the enum ReportingMode.");
        return false;
    }
    distMeasureDataSet.reportMode = reportMode;

    // 结果上报频率
    int32_t reportFreq = static_cast<int32_t>(configParams.reportFrequency);
    if (!IsValidReportFrequency(reportFreq)) {
        taihe::set_business_error(PARAMETER_EXCEPTION, "reportFrequency must be between 0 and 999999.");
        return false;
    }
    distMeasureDataSet.reportFreq = reportFreq;
    FI_HILOGI("Exit");
    return true;
}

bool EtsSpatialAwarenessManager::IsValidTechnologyType(int32_t techType)
{
    FI_HILOGI("Enter");
    if (techType < TECHNOLOGY_TYPE_MIN_VALUE || techType > TECHNOLOGY_TYPE_MAX_VALUE) {
        FI_HILOGE("techType must be one of the values in the enum TechnologyType, techType=%{public}d",
            techType);
        return false;
    }
    FI_HILOGI("Exit");
    return true;
}

bool EtsSpatialAwarenessManager::IsValidReportMode(int32_t reportMode)
{
    FI_HILOGI("Enter");
    if (reportMode < REPORT_MODE_MIN_VALUE || reportMode > REPORT_MODE_MAX_VALUE) {
        FI_HILOGE("reportMode must be one of the values in the enum ReportingMode, reportMode=%{public}d",
            reportMode);
        return false;
    }
    FI_HILOGI("Exit");
    return true;
}

bool EtsSpatialAwarenessManager::IsValidReportFrequency(int32_t reportFrequency)
{
    FI_HILOGI("Enter");
    if (reportFrequency < REPORT_FREQUENCY_MIN_VALUE || reportFrequency > REPORT_FREQUENCY_MAX_VALUE) {
        FI_HILOGE("reportFrequency must be between 0 and 999999, reportFrequency=%{public}d", reportFrequency);
        return false;
    }
    FI_HILOGI("Input reportFrequency: %{public}d", reportFrequency);
    FI_HILOGI("Exit");
    return true;
}

void EtsSpatialAwarenessManager::InitDependencyLibrary()
{
    FI_HILOGI("Enter");
    if (!LoadLibrary()) {
        FI_HILOGE("load library failed.");
        taihe::set_business_error(DEVICE_EXCEPTION, "Device not support.");
    }
    FI_HILOGI("Exit");
}

bool EtsSpatialAwarenessManager::SubscribeDistanceMeasurement(const CDistMeasureData &cdistMeasureData)
{
    FI_HILOGI("Enter");
    if (subscribeDistanceMeasurementFunc == nullptr) {
        FI_HILOGI("subscribeDistanceMeasurementFunc create start");
        subscribeDistanceMeasurementFunc = reinterpret_cast<SubscribeDistanceMeasurementFunc>(
            dlsym(distanceMeasurementHandle, SUBSCRIBE_FUNC_NAME.data()));
        FI_HILOGI("subscribeDistanceMeasurementFunc create end");
        if (subscribeDistanceMeasurementFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", SUBSCRIBE_FUNC_NAME.data(), dlerror());
            return false;
        }
    }

    FI_HILOGI("subscribeDistanceMeasurementFunc call start");
    int32_t ret = subscribeDistanceMeasurementFunc(shared_from_this(), cdistMeasureData);
    if (ret != 0) {
        FI_HILOGE("Subscribe distance measurement callback failed");
        return false;
    }
    FI_HILOGI("Subscribe distance measurement callback success.");
    FI_HILOGI("Exit");
    return true;
}

bool EtsSpatialAwarenessManager::UnsubscribeDistanceMeasurement(const CDistMeasureData &cdistMeasureData)
{
    FI_HILOGI("Enter");
    if (unsubscribeDistanceMeasurementFunc == nullptr) {
        FI_HILOGI("unsubscribeDistanceMeasurementFunc create start");
        unsubscribeDistanceMeasurementFunc = reinterpret_cast<UnsubscribeDistanceMeasurementFunc>(
            dlsym(distanceMeasurementHandle, UNSUBSCRIBE_FUNC_NAME.data()));
        FI_HILOGI("unsubscribeDistanceMeasurementFunc create end");
        if (unsubscribeDistanceMeasurementFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", UNSUBSCRIBE_FUNC_NAME.data(), dlerror());
            return false;
        }
    }

    FI_HILOGI("unsubscribeDistanceMeasurementFunc call start");
    int32_t ret = unsubscribeDistanceMeasurementFunc(cdistMeasureData);
    if (ret != 0) {
        FI_HILOGE("Unsubscribe distance measurement callback failed");
        return false;
    }
    FI_HILOGI("Unsubscribe distance measurement callback success.");
    FI_HILOGI("Exit");
    return true;
}

void EtsSpatialAwarenessManager::RemoveFailCallback(ani_env *env, const CDistMeasureData &distMeasureDataSet,
    uintptr_t opq, std::map<CDistMeasureData, std::vector<std::shared_ptr<CallbackObject>>> &jsCbMap)
{
    FI_HILOGI("Enter");
    if (env == nullptr) {
        FI_HILOGE("ani_env is nullptr!");
        return;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    const auto cbVec = jsCbMap.find(distMeasureDataSet);
    if (cbVec == jsCbMap.end()) {
        FI_HILOGE("distMeasureDataSet is invalid");
        return;
    }
    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq));
    if (!guard) {
        FI_HILOGE("GlobalRefGuard is false!");
        return;
    }
    const auto pred = [env, targetRef = guard.get()](std::shared_ptr<CallbackObject> &obj) {
        ani_boolean is_equal = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &is_equal)) && is_equal;
    };
    auto &callbacks = cbVec->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        FI_HILOGI("remove callback success");
        callbacks.erase(it);
    }
    FI_HILOGI("Exit");
}
} // namespace Msdp
} // namespace OHOS
