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
#include "distance_measurement_event_napi.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DistanceMeasurementEventNapi"

namespace OHOS {
namespace Msdp {
DistanceMeasurementEventNapi::DistanceMeasurementEventNapi(napi_env env,
    napi_value thisVar, int32_t callbackIdx)
{
    std::lock_guard<std::mutex> lock(mutex_);
    env_ = env;
    callbackIdx_ = callbackIdx;
    thisVarRef_ = nullptr;
    napi_status status = napi_create_reference(env, thisVar, 1, &thisVarRef_);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create the reference");
        return;
    }
}

DistanceMeasurementEventNapi::~DistanceMeasurementEventNapi()
{
    FI_HILOGI("Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    napi_status status = napi_delete_reference(env_, thisVarRef_);
    if (status != napi_ok) {
        FI_HILOGE("Failed to delete the reference");
        return;
    }
    FI_HILOGI("Exit");
}

void DistanceMeasurementEventNapi::ClearEnv()
{
    FI_HILOGI("ClearEnv Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    distMeasureEventMap_.clear();
}

void DistanceMeasurementEventNapi::UpdateEnv(napi_env env, napi_value jsThis)
{
    FI_HILOGI("UpdateEnv Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    env_ = env;
    if (thisVarRef_ != nullptr) {
        napi_delete_reference(env_, thisVarRef_);
        thisVarRef_ = nullptr;
    }
    napi_status status = napi_create_reference(env, jsThis, 1, &thisVarRef_);
    if (status != napi_ok) {
        FI_HILOGE("Failed to update env");
        return;
    }
    FI_HILOGI("Exit");
}

bool DistanceMeasurementEventNapi::AddCallback(
    const CDistMeasureData &cdistMeasureData, napi_value handler)
{
    FI_HILOGI("AddCallback Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    distMeasureDataSet_ = cdistMeasureData;
    auto iter = distMeasureEventMap_.find(cdistMeasureData);
    if (iter == distMeasureEventMap_.end()) {
        FI_HILOGI("not found cdistMeasureData");
        napi_ref newHandlerRef = nullptr;
        napi_status status = napi_create_reference(env_, handler, 1, &newHandlerRef);
        if (status != napi_ok || newHandlerRef == nullptr) {
            FI_HILOGE("napi_create_reference failed");
            return false;
        }
        auto listener = std::make_shared<DistanceMeasurementListener>();
        listener->handlerRef = newHandlerRef;
        distMeasureEventMap_.insert(std::make_pair(cdistMeasureData, listener));
        FI_HILOGI("Insert finish");
        return true;
    }
    FI_HILOGI("find cdistMeasureData");
    if (iter->second == nullptr || iter->second->handlerRef == nullptr) {
        FI_HILOGE("listener or handlerRef is nullptr");
        distMeasureEventMap_.erase(iter);
        return false;
    }
    FI_HILOGI("check cdistMeasureData same handle");
    if (!InsertRef(iter->second, handler)) {
        FI_HILOGE("Failed to insert ref");
        distMeasureEventMap_.erase(iter);
        return false;
    }
    return true;
}

bool DistanceMeasurementEventNapi::InsertRef(
    std::shared_ptr<DistanceMeasurementListener> listener, const napi_value &handler)
{
    if (listener == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    napi_value onHandler = nullptr;
    napi_status status = napi_get_reference_value(env_, listener->handlerRef, &onHandler);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_reference_value failed");
        status = napi_delete_reference(env_, listener->handlerRef);
        if (status != napi_ok) {
            FI_HILOGE("napi_delete_reference failed");
        }
        return false;
    }
    if (IsSameValue(env_, handler, onHandler)) {
        return true;
    }
    napi_ref handlerRef = nullptr;
    status = napi_create_reference(env_, handler, 1, &handlerRef);
    if (status != napi_ok) {
        FI_HILOGE("napi_create_reference failed");
        return false;
    }
    FI_HILOGD("Insert new ref");
    status = napi_delete_reference(env_, listener->handlerRef);
    if (status != napi_ok) {
        FI_HILOGE("napi_delete_reference failed!");
    }
    listener->handlerRef = handlerRef;
    return true;
}

bool DistanceMeasurementEventNapi::IsSameValue(const napi_env &env,
    const napi_value &lhs, const napi_value &rhs)
{
    FI_HILOGD("IsSameValue Enter");
    bool result = false;
    napi_status status = napi_strict_equals(env, lhs, rhs, &result);
    if (status != napi_ok) {
        FI_HILOGE("napi_strict_equals failed");
    }
    return result;
}

void DistanceMeasurementEventNapi::RemoveCallback(const CDistMeasureData &cdistMeasureData)
{
    FI_HILOGI("RemoveCallback Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = distMeasureEventMap_.find(cdistMeasureData);
    if (iter == distMeasureEventMap_.end()) {
        FI_HILOGE("cdistMeasureData not found");
        return;
    }
    if (iter->second == nullptr || iter->second->handlerRef == nullptr) {
        FI_HILOGE("listener or handlerRef is nullptr");
        distMeasureEventMap_.erase(iter);
        return;
    }

    napi_status status = napi_delete_reference(env_, iter->second->handlerRef);
    if (status != napi_ok) {
        FI_HILOGE("napi_delete_reference failed");
    }
    distMeasureEventMap_.erase(iter);
    return;
}

void DistanceMeasurementEventNapi::OnDistMeasureEvent(size_t argc, const napi_value *argv,
    const std::string &type)
{
    FI_HILOGI("OnDistMeasureEvent Enter");
    std::lock_guard<std::mutex> lock(mutex_);
    if (distMeasureEventMap_.empty()) {
        FI_HILOGE("distMeasureEventMap_ is empty");
        return;
    }
    distMeasureDataSet_.type = type;
    FI_HILOGI("current distMeasureDataSet_.type: %{public}s", distMeasureDataSet_.type.c_str());

    #ifndef NDEBUG
    for (const auto &pair : distMeasureEventMap_) {
        FI_HILOGI("distMeasureEventMap_ item.type: %{public}s", pair.first.type.c_str());
    }
    #endif

    auto iter = distMeasureEventMap_.find(distMeasureDataSet_);
    if (iter == distMeasureEventMap_.end()) {
        FI_HILOGE("distMeasureDataSet_ not found");
        return;
    }
    if (iter->second == nullptr || iter->second->handlerRef == nullptr) {
        FI_HILOGE("listener or handlerRef is nullptr");
        return;
    }
    napi_value handler = nullptr;
    napi_status ret = napi_get_reference_value(env_, iter->second->handlerRef, &handler);
    if (ret != napi_ok) {
        FI_HILOGE("napi_get_reference_value for distMeasureDataSet_ failed, status: %{public}d", ret);
        return;
    }

    napi_value callResult = nullptr;
    if (napi_call_function(env_, nullptr, handler, argc, argv, &callResult) != napi_ok) {
        FI_HILOGE("napi_call_function failed");
    }
    FI_HILOGI("Exit");
}
} // namespace Msdp
} // namespace OHOS
