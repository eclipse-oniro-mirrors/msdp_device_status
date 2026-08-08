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

#include "car_awareness_mgr_napi.h"
#include "napi_constants.h"
#include "util_napi.h"

#include <nlohmann/json.hpp>

#undef LOG_TAG
#define LOG_TAG "CarAwarenessMgrNapi"

namespace OHOS {
namespace Msdp {
CarAwarenessMgrNapi::CarAwarenessMgrNapi(napi_env env, napi_value thisVar)
{
    env_ = env;
    thisVarRef_ = nullptr;
    napi_create_reference(env, thisVar, 1, &thisVarRef_);

#ifdef CAR_AWARENESS_ENABLE
    // 初始化Public回调数据处理函数注册表
    triggerMap_[TYPE_SPATIAL_MOTION] =
        [this](napi_value handler, const std::string &data) { return ConvertSpatialMotionInfo(handler, data); };
    triggerMap_[TYPE_REALTIME_WEATHER] =
        [this](napi_value handler, const std::string &data) { return ConvertWeatherInfo(handler, data); };
    triggerMap_[TYPE_REFUELING] =
        [this](napi_value handler, const std::string &data) { return ConvertRefulingInfo(handler, data); };
#endif // CAR_AWARENESS_ENABLE
}

CarAwarenessMgrNapi::~CarAwarenessMgrNapi()
{
    {
        std::lock_guard<std::mutex> lock(listenersMutex_);
#ifdef CAR_AWARENESS_ENABLE
        // 释放 native 侧持有的所有 JS 回调引用（napi_ref）,防止napi_ref泄露
        for (auto &typePair : listenerMap_) {
            auto &listener = typePair.second;
            if (!listener) {
                continue;
            }
            for (auto it = listener->onRefSets.begin(); it != listener->onRefSets.end();) {
                napi_ref ref = *it;
                if (env_ != nullptr && ref != nullptr) {
                    (void)napi_delete_reference(env_, ref);
                }
                it = listener->onRefSets.erase(it);
            }
        }
#endif // CAR_AWARENESS_ENABLE
        listenerMap_.clear();
    }
    triggerMap_.clear();
    if (env_ != nullptr && thisVarRef_ != nullptr) {
        napi_delete_reference(env_, thisVarRef_);
    }
}

#ifdef CAR_AWARENESS_ENABLE
bool CarAwarenessMgrNapi::HasCapListener(const int32_t eventType)
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> lock(listenersMutex_);
    auto typeIter = listenerMap_.find(eventType);
    if (typeIter == listenerMap_.end()) {
        FI_HILOGD("eventType listener not find");
        return false;
    }
    if (typeIter->second->onRefSets.empty()) {
        return false;
    }
    return true;
}

bool CarAwarenessMgrNapi::IsSameValue(const napi_env &env,
    const napi_value &newHandler, const napi_value &existHandler)
{
    FI_HILOGD("Enter");
    bool result = false;
    napi_status status = napi_strict_equals(env, newHandler, existHandler, &result);
    if (status != napi_ok) {
        FI_HILOGE("napi_strict_equals failed");
        return result;
    }
    return result;
}

bool CarAwarenessMgrNapi::InsertRefEx(std::shared_ptr<CarAwarenessListener> listener,
    const napi_value &handler, bool &isNewHandler)
{
    isNewHandler = false;
    if (listener == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    bool hasHandler = false;
    for (auto item : listener->onRefSets) {
        napi_value onHandler = nullptr;
        napi_status status = napi_get_reference_value(env_, item, &onHandler);
        if (status != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed");
            status = napi_delete_reference(env_, item);
            if (status != napi_ok) {
                FI_HILOGE("napi_delete_reference failed");
                continue;
            }
            continue;
        }
        if (IsSameValue(env_, handler, onHandler)) {
            hasHandler = true;
            break;
        }
    }
    if (hasHandler) {
        FI_HILOGD("napi repeat subscribe");
        return true;
    }
    napi_ref onHandlerRef = nullptr;
    napi_status status = napi_create_reference(env_, handler, 1, &(onHandlerRef));
    if (status != napi_ok) {
        FI_HILOGE("napi_create_reference failed");
        return false;
    }

    FI_HILOGD("Insert new ref");
    auto ret = listener->onRefSets.insert(onHandlerRef);
    if (!ret.second) {
        FI_HILOGE("Failed to insert");
        return false;
    }
    isNewHandler = true;
    FI_HILOGD("ref size %{public}zu", listener->onRefSets.size());
    return true;
}

bool CarAwarenessMgrNapi::AddCallbackEx(int32_t eventType, napi_value listenerHandler, bool isNewHandler)
{
    FI_HILOGD("Enter");
    isNewHandler = false;
    std::lock_guard<std::mutex> lock(listenersMutex_);
    auto iter = listenerMap_.find(eventType);
    if (iter == listenerMap_.end()) {
        FI_HILOGD("Not found type:%{public}d", eventType);
        auto listener = std::make_shared<CarAwarenessListener>();
        std::set<napi_ref> onRefSets;
        listener->onRefSets = onRefSets;
        napi_ref onHandlerRef = nullptr;
        napi_status status = napi_create_reference(env_, listenerHandler, 1, &onHandlerRef);
        if (status != napi_ok) {
            FI_HILOGE("napi_create_reference failed");
            return false;
        }
        listener->onRefSets.insert(onHandlerRef);
        listenerMap_.insert(std::make_pair(eventType, listener));
        isNewHandler = true;
        FI_HILOGD("Insert finish");
        return true;
    }
    FI_HILOGD("Found type: %{public}d", eventType);
    if (iter->second == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    FI_HILOGD("Check type: %{public}d same handle", eventType);
    if (!InsertRefEx(iter->second, listenerHandler, isNewHandler)) {
        FI_HILOGE("Failed to insert ref");
        return false;
    }
    return true;
}

bool CarAwarenessMgrNapi::RemoveAllCallbackEx(int32_t eventType)
{
    FI_HILOGD("RemoveAllCallbackEx in, event:%{public}d", eventType);
    std::lock_guard<std::mutex> lock(listenersMutex_);
    auto iter = listenerMap_.find(eventType);
    if (iter == listenerMap_.end()) {
        FI_HILOGW("EventType %{public}d not found", eventType);
        return false;
    }
    if (iter->second == nullptr) {
        FI_HILOGW("listener is nullptr");
        return false;
    }
    if (iter->second->onRefSets.empty()) {
        FI_HILOGW("onRefSets is empty");
        return false;
    }
    FI_HILOGI("Remove callback from onRefSets");
    for (auto it = iter->second->onRefSets.begin(); it != iter->second->onRefSets.end();) {
        if (*it == nullptr) {
            ++it;
            continue;
        }
        napi_status status = napi_delete_reference(env_, *it);
        if (status != napi_ok) {
            FI_HILOGE("napi_delete_reference failed");
            ++it;
            continue;
        }
        it = iter->second->onRefSets.erase(it);
    }
    if (iter->second->onRefSets.empty()) {
        FI_HILOGI("onRefSets is empty");
        listenerMap_.erase(iter);
    }
    return true;
}

bool CarAwarenessMgrNapi::RemoveCallbackEx(int32_t eventType, napi_value listenerHandler)
{
    FI_HILOGD("RemoveCallbackEx in, event:%{public}d", eventType);
    std::lock_guard<std::mutex> lock(listenersMutex_);
    auto iter = listenerMap_.find(eventType);
    if (iter == listenerMap_.end()) {
        FI_HILOGW("EventType %{public}d not found", eventType);
        return false;
    }
    if (iter->second == nullptr) {
        FI_HILOGW("listener is nullptr");
        return false;
    }
    if (iter->second->onRefSets.empty()) {
        FI_HILOGW("onRefSets is empty");
        return false;
    }
    for (auto it = iter->second->onRefSets.begin(); it != iter->second->onRefSets.end();) {
        if (*it == nullptr) {
            ++it;
            continue;
        }
        napi_value deleteHandler;
        napi_status status = napi_get_reference_value(env_, *it, &deleteHandler);
        if (status != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed");
            ++it;
            continue;
        }
        if (IsSameValue(env_, listenerHandler, deleteHandler)) {
            status = napi_delete_reference(env_, *it);
            if (status != napi_ok) {
                FI_HILOGE("napi_delete_reference failed");
                ++it;
                continue;
            }
            iter->second->onRefSets.erase(it++);
            break;
        }
        ++it;
    }
    if (iter->second->onRefSets.empty()) {
        listenerMap_.erase(iter);
    }
    return true;
}

void CarAwarenessMgrNapi::TriggerEvent(int32_t type, const std::string &data)
{
    FI_HILOGD("eventType: %{public}d", type);
    if (data.empty() || !nlohmann::json::accept(data)) {
        FI_HILOGE("invalid event data");
        return;
    }
    std::set<napi_ref> onRefSets;
    {
        std::lock_guard<std::mutex> lock(listenersMutex_);
        auto typeIter = listenerMap_.find(type);
        if (typeIter == listenerMap_.end() || typeIter->second == nullptr) {
            FI_HILOGE("eventType: %{public}d not found", type);
            return;
        }
        onRefSets = typeIter->second->onRefSets;
    }
    for (auto item : onRefSets) {
        napi_value handler = nullptr;
        napi_status ret = napi_get_reference_value(env_, item, &handler);
        if (ret != napi_ok) {
            FI_HILOGE("napi_get_reference_value for %{public}d failed, status: %{public}d", type, ret);
            continue;
        }
        // 按照Type进行对象的封装,返回至ArkTs线程
        auto it = triggerMap_.find(type);
        if (it == triggerMap_.end()) {
            FI_HILOGE("Trigger Func not registered");
            continue;
        }
        it->second(handler, data);
    }
}

void CarAwarenessMgrNapi::ConvertWeatherInfo(napi_value handler, const std::string &data)
{
    nlohmann::json weatherInfo = nlohmann::json::parse(data);
    if (!weatherInfo.contains("timestamp") || !weatherInfo.contains("weather")) {
        FI_HILOGW("WeatherInfo is invalid");
        return;
    }
    if (!weatherInfo["timestamp"].is_number_integer() || !weatherInfo["weather"].is_number_integer()) {
        FI_HILOGW("WeatherInfo Format error");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(env_, napi_create_object(env_, &result), DeviceStatus::CREATE_OBJECT, scope);
    napi_value value = nullptr;
    CHKRV_SCOPE(env_, napi_create_int64(env_, weatherInfo["timestamp"].get<int64_t>(), &value),
        DeviceStatus::CREATE_INT32, scope);
    CHKRV_SCOPE(env_, napi_set_named_property(env_, result, "timestamp", value),
        DeviceStatus::SET_NAMED_PROPERTY, scope);
    int32_t weatherValue = weatherInfo["weather"].get<int32_t>();
    CHKRV_SCOPE(env_, napi_create_int32(env_, weatherValue, &value), DeviceStatus::CREATE_INT32, scope);
    CHKRV_SCOPE(env_, napi_set_named_property(env_, result, "weather", value),
        DeviceStatus::SET_NAMED_PROPERTY, scope);
    napi_value callResult = nullptr;
    CHKRV_SCOPE(env_, napi_call_function(env_, nullptr, handler, 1, &result, &callResult),
        DeviceStatus::CALL_FUNCTION, scope);
    napi_close_handle_scope(env_, scope);
}

void CarAwarenessMgrNapi::ConvertSpatialMotionInfo(napi_value handler, const std::string &data)
{
    nlohmann::json motionInfo = nlohmann::json::parse(data);
    if (!motionInfo.contains("timestamp") || !motionInfo.contains("pointX")
        || !motionInfo.contains("pointY") || !motionInfo.contains("event")) {
        FI_HILOGW("SpatialMotionInfo is invalid");
        return;
    }
    if (!motionInfo["timestamp"].is_number_integer() || !motionInfo["pointX"].is_number_float()
        || !motionInfo["pointY"].is_number_float() || !motionInfo["event"].is_number_integer()) {
        FI_HILOGW("SpatialMotionInfo Format error");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(env_, napi_create_object(env_, &result), DeviceStatus::CREATE_OBJECT, scope);
    napi_value value = nullptr;
    CHKRV_SCOPE(env_, napi_create_int64(env_, motionInfo["timestamp"].get<int64_t>(), &value),
       DeviceStatus::CREATE_INT64, scope);
    CHKRV_SCOPE(env_, napi_set_named_property(env_, result, "timestamp", value),
        DeviceStatus::SET_NAMED_PROPERTY, scope);
    CHKRV_SCOPE(env_, napi_create_double(env_, motionInfo["pointX"].get<double>(), &value),
        DeviceStatus::CREATE_INT64, scope);
    CHKRV_SCOPE(env_, napi_set_named_property(env_, result, "pointX", value),
        DeviceStatus::SET_NAMED_PROPERTY, scope);
    CHKRV_SCOPE(env_, napi_create_double(env_, motionInfo["pointY"].get<double>(), &value),
        DeviceStatus::CREATE_INT64, scope);
    CHKRV_SCOPE(env_, napi_set_named_property(env_, result, "pointY", value),
        DeviceStatus::SET_NAMED_PROPERTY, scope);
    int32_t eventValue = motionInfo["event"].get<int32_t>();
    CHKRV_SCOPE(env_, napi_create_int32(env_, eventValue, &value), DeviceStatus::CREATE_INT32, scope);
    CHKRV_SCOPE(env_, napi_set_named_property(env_, result, "event", value),
        DeviceStatus::SET_NAMED_PROPERTY, scope);
    napi_value callResult = nullptr;
    CHKRV_SCOPE(env_, napi_call_function(env_, nullptr, handler, 1, &result, &callResult),
        DeviceStatus::CALL_FUNCTION, scope);
    napi_close_handle_scope(env_, scope);
}

void CarAwarenessMgrNapi::ConvertRefulingInfo(napi_value handler, const std::string &data)
{
    nlohmann::json refulingInfo = nlohmann::json::parse(data);
    if (!refulingInfo.contains("timestamp") || !refulingInfo.contains("status")) {
        FI_HILOGW("RefulingInfo is invalid");
        return;
    }
    if (!refulingInfo["timestamp"].is_number_integer() || !refulingInfo["status"].is_number_integer()) {
        FI_HILOGW("RefulingInfo Format error");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    napi_value result = nullptr;
    CHKRV_SCOPE(env_, napi_create_object(env_, &result), DeviceStatus::CREATE_OBJECT, scope);
    napi_value value = nullptr;
    CHKRV_SCOPE(env_, napi_create_int64(env_, refulingInfo["timestamp"].get<int64_t>(), &value),
        DeviceStatus::CREATE_INT64, scope);
    CHKRV_SCOPE(env_, napi_set_named_property(env_, result, "timestamp", value),
        DeviceStatus::SET_NAMED_PROPERTY, scope);
    int32_t statusValue = refulingInfo["status"].get<int32_t>();
    CHKRV_SCOPE(env_, napi_create_int32(env_, statusValue, &value), DeviceStatus::CREATE_INT32, scope);
    CHKRV_SCOPE(env_, napi_set_named_property(env_, result, "status", value),
        DeviceStatus::SET_NAMED_PROPERTY, scope);
    napi_value callResult = nullptr;
    CHKRV_SCOPE(env_, napi_call_function(env_, nullptr, handler, 1, &result, &callResult),
        DeviceStatus::CALL_FUNCTION, scope);
    napi_close_handle_scope(env_, scope);
}
#endif // CAR_AWARENESS_ENABLE
} // namespace Msdp
} // namespace OHOS