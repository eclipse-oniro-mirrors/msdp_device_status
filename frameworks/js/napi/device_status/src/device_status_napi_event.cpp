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

#include "device_status_napi_event.h"

#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusNapiEvent"

namespace OHOS {
namespace Msdp {
namespace DeviceStatusV1 {
namespace {
static constexpr int32_t STATUS_EXIT = 0;
static constexpr int32_t STATUS_ENTER = 1;
static constexpr int32_t STATUS_UNKNOWN = -1;
} // namespace

DeviceStatusNapiEvent::DeviceStatusNapiEvent(napi_env env, napi_value thisVar)
{
    env_ = env;
    thisVarRef_ = nullptr;
    napi_create_reference(env, thisVar, 1, &thisVarRef_);
}

DeviceStatusNapiEvent::~DeviceStatusNapiEvent()
{
    events_.clear();
    if (env_ != nullptr && thisVarRef_ != nullptr) {
        napi_delete_reference(env_, thisVarRef_);
    }
}

bool DeviceStatusNapiEvent::AddCallback(DeviceStatus::Type eventType, napi_value handler)
{
    FI_HILOGD("Enter");
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGD("found event:%{public}d", eventType);
        std::shared_ptr<DeviceStatusEventListener> listener = std::make_shared<DeviceStatusEventListener>();
        std::vector<std::pair<napi_ref, DeviceStatus::OnChangedValue>> onRefSets;
        listener->onRefSets = onRefSets;
        napi_ref onHandlerRef = nullptr;
        napi_status status = napi_create_reference(env_, handler, 1, &onHandlerRef);
        if (status != napi_ok) {
            FI_HILOGE("napi_create_reference failed");
            return false;
        }
        listener->onRefSets.push_back(std::make_pair(onHandlerRef, DeviceStatus::OnChangedValue::VALUE_INVALID));
        events_.insert(std::make_pair(eventType, listener));
        FI_HILOGD("Insert finish");
        return true;
    }
    FI_HILOGD("found event: %{public}d", eventType);
    if (iter->second == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    if (iter->second->onRefSets.empty()) {
        FI_HILOGE("Refs is empty()");
        return false;
    }

    FI_HILOGD("Check type: %{public}d same handle", eventType);
    if (!InsertRef(iter->second, handler)) {
        FI_HILOGE("Failed to insert ref");
        return false;
    }
    return true;
}

bool DeviceStatusNapiEvent::RemoveCallback(DeviceStatus::Type eventType)
{
    FI_HILOGD("Enter, event:%{public}d", eventType);
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("EventType %{public}d not found", eventType);
        return false;
    }

    if (iter->second == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }

    if (iter->second->onRefSets.empty()) {
        FI_HILOGE("Refs is empty");
        return false;
    }

    for (auto it = iter->second->onRefSets.begin(); it != iter->second->onRefSets.end();) {
        if (it->first == nullptr) {
            ++it;
            continue;
        }
        napi_status status = napi_delete_reference(env_, it->first);
        if (status != napi_ok) {
            FI_HILOGE("napi_delete_reference failed");
            ++it;
            continue;
        }
        it = iter->second->onRefSets.erase(it);
    }
    if (iter->second->onRefSets.empty()) {
        FI_HILOGE("onRefSets is empty");
        events_.erase(iter);
    }
    return true;
}

bool DeviceStatusNapiEvent::RemoveCallback(DeviceStatus::Type eventType, napi_value handler)
{
    FI_HILOGD("Enter, event:%{public}d", eventType);
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("EventType %{public}d not found", eventType);
        return false;
    }
    if (iter->second == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    if (iter->second->onRefSets.empty()) {
        FI_HILOGE("Refs is empty");
        return false;
    }
    bool isSubscribe = false;
    for (auto it = iter->second->onRefSets.begin(); it != iter->second->onRefSets.end();) {
        if (it->first == nullptr) {
            ++it;
            continue;
        }
        napi_value onHandler = nullptr;
        napi_status status = napi_get_reference_value(env_, it->first, &onHandler);
        if (status != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed");
            napi_delete_reference(env_, it->first);
            it = iter->second->onRefSets.erase(it);
            continue;
        }
        if (IsSameValue(env_, onHandler, handler)) {
            napi_status status = napi_delete_reference(env_, it->first);
            if (status != napi_ok) {
                FI_HILOGE("napi_delete_reference failed");
            }
            it = iter->second->onRefSets.erase(it);
            isSubscribe = true;
        } else {
            ++it;
        }
    }
    if (!isSubscribe) {
        FI_HILOGE("dont find the callback, return err");
        return false;
    }
    if (iter->second->onRefSets.empty()) {
        FI_HILOGE("onRefSets is empty");
        events_.erase(iter);
    }
    return true;
}

bool DeviceStatusNapiEvent::InsertRef(std::shared_ptr<DeviceStatusEventListener> listener, const napi_value &handler)
{
    if (listener == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    bool hasHandler = false;
    for (auto item : listener->onRefSets) {
        napi_value onHandler = nullptr;
        napi_status status = napi_get_reference_value(env_, item.first, &onHandler);
        if (status != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed");
            status = napi_delete_reference(env_, item.first);
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
        FI_HILOGE("napi repeat subscribe, return failed");
        return false;
    }
    napi_ref onHandlerRef = nullptr;
    napi_status status = napi_create_reference(env_, handler, 1, &(onHandlerRef));
    if (status != napi_ok) {
        FI_HILOGE("napi_create_reference failed");
        return false;
    }

    FI_HILOGD("Insert new ref");
    listener->onRefSets.push_back(std::make_pair(onHandlerRef, DeviceStatus::OnChangedValue::VALUE_INVALID));
    FI_HILOGD("ref size %{public}zu", listener->onRefSets.size());
    return true;
}

void DeviceStatusNapiEvent::OnEvent(DeviceStatus::Type eventType, size_t argc, const DeviceStatus::Data event)
{
    FI_HILOGD("eventType: %{public}d", eventType);
    auto typeIter = events_.find(eventType);
    if (typeIter == events_.end()) {
        FI_HILOGE("eventType: %{public}d not found", eventType);
        return;
    }
    for (auto &item : typeIter->second->onRefSets) {
        if (item.second != event.value) {
            napi_value handler = nullptr;
            napi_status ret = napi_get_reference_value(env_, item.first, &handler);
            if (ret != napi_ok) {
                FI_HILOGE("napi_get_reference_value for %{public}d failed, status: %{public}d", eventType, ret);
                return;
            }
            ConvertEventData(handler, argc, event);
            item.second = event.value;
        }
    }
}

void DeviceStatusNapiEvent::ConvertEventData(napi_value handler, size_t argc, const DeviceStatus::Data event)
{
    napi_value result;
    int32_t status = 0;
    switch (event.value) {
        case DeviceStatus::OnChangedValue::VALUE_ENTER:
            status = STATUS_ENTER;
            break;
        case DeviceStatus::OnChangedValue::VALUE_EXIT:
            status = STATUS_EXIT;
            break;
        default:
            status = STATUS_UNKNOWN;
            break;
    }
    napi_status ret = napi_create_int32(env_, status, &result);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        return;
    }
    napi_value callResult = nullptr;
    ret = napi_call_function(env_, nullptr, handler, argc, &result, &callResult);
    if (ret != napi_ok) {
        FI_HILOGE("napi_call_function ret %{public}d", ret);
        return;
    }
}

void DeviceStatusNapiEvent::CreateIntData(napi_env env, napi_value status, napi_value result, std::string name,
    int32_t value)
{
    napi_status ret = napi_create_int32(env, value, &status);
    if (ret != napi_ok) {
        FI_HILOGE("napi_create_int32 failed");
        return;
    }

    ret = napi_set_named_property(env, result, name.c_str(), status);
    if (ret != napi_ok) {
        FI_HILOGE("napi_set_named_property failed");
        return;
    }
}

bool DeviceStatusNapiEvent::IsSameValue(const napi_env &env, const napi_value &lhs, const napi_value &rhs)
{
    FI_HILOGD("Enter");
    bool result = false;
    napi_status status = napi_strict_equals(env, lhs, rhs, &result);
    if (status != napi_ok) {
        FI_HILOGE("napi_strict_equals failed");
        return result;
    }
    return result;
}

bool DeviceStatusNapiEvent::CheckEvents(DeviceStatus::Type eventType)
{
    FI_HILOGD("Enter");
    auto typeIter = events_.find(eventType);
    if (typeIter == events_.end()) {
        FI_HILOGD("eventType not find");
        return true;
    }
    if (typeIter->second->onRefSets.empty()) {
        return true;
    }
    return false;
}
} // namespace DeviceStatusV1
} // namespace Msdp
} // namespace OHOS
