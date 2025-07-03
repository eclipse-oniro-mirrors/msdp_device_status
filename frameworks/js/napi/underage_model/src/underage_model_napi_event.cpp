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

#include "underage_model_napi_event.h"

#include <iostream>
#include <iomanip>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "napi_constants.h"
#include "util_napi.h"

#undef LOG_TAG
#define LOG_TAG "DeviceUnderageModelNapiEvent"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int16_t ONE_PARAMETER = 1;
constexpr int16_t TWO_PARAMETER = 2;
constexpr int16_t FLOAT_PRECSION = 3;
} // namespace

UnderageModelNapiEvent::UnderageModelNapiEvent(napi_env env, napi_value thisVar)
{
    env_ = env;
    thisVarRef_ = nullptr;
    napi_create_reference(env, thisVar, ONE_PARAMETER, &thisVarRef_);
}

UnderageModelNapiEvent::~UnderageModelNapiEvent()
{
    if (env_ == nullptr) {
        FI_HILOGW("env_ is nullptr");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(eventsMutex_);
        for (auto& iter : events_) {
            if (iter.second == nullptr) {
                continue;
            }
            for (auto it = iter.second->onRefSets.begin(); it != iter.second->onRefSets.end();) {
                if (*it == nullptr) {
                    ++it;
                    continue;
                }
                napi_status status = napi_delete_reference(env_, *it);
                if (status != napi_ok) {
                    FI_HILOGE("napi_delete_reference failed");
                }
                it = iter.second->onRefSets.erase(it);
            }
            iter.second = nullptr;
        }
        events_.clear();
    }
    if (env_ != nullptr && thisVarRef_ != nullptr) {
        napi_delete_reference(env_, thisVarRef_);
    }
}

bool UnderageModelNapiEvent::AddCallback(uint32_t eventType, napi_value handler)
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> lock(eventsMutex_);
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGD("found event:%{public}d", eventType);
        napi_ref onHandlerRef = nullptr;
        napi_status status = napi_create_reference(env_, handler, ONE_PARAMETER, &onHandlerRef);
        if (status != napi_ok) {
            FI_HILOGE("napi_create_reference failed");
            return false;
        }
        auto listener = std::make_shared<UnderageModelEventListener>();
        std::set<napi_ref> onRefSets;
        listener->onRefSets = onRefSets;
        auto ret = listener->onRefSets.insert(onHandlerRef);
        if (!ret.second) {
            FI_HILOGE("Failed to insert refs");
            return false;
        }
        events_.insert(std::make_pair(eventType, listener));
        FI_HILOGD("Insert finish");
        return true;
    }
    FI_HILOGD("found event: %{public}d", eventType);
    if (iter->second == nullptr || iter->second->onRefSets.empty()) {
        FI_HILOGE("listener or onRefSets is nullptr");
        events_.erase(iter);
        return false;
    }
    FI_HILOGD("Check type: %{public}d same handle", eventType);
    if (!InsertRef(iter->second, handler)) {
        FI_HILOGE("Failed to insert ref");
        events_.erase(iter);
        return false;
    }
    return true;
}

bool UnderageModelNapiEvent::RemoveAllCallback(uint32_t eventType)
{
    FI_HILOGD("RemoveAllCallback in, event:%{public}d", eventType);
    std::lock_guard<std::mutex> lock(eventsMutex_);
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("EventType %{public}d not found", eventType);
        return false;
    }
    if (iter->second == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    for (auto it = iter->second->onRefSets.begin(); it != iter->second->onRefSets.end();) {
        if (*it == nullptr) {
            ++it;
            continue;
        }
        napi_status status = napi_delete_reference(env_, *it);
        if (status != napi_ok) {
            FI_HILOGE("napi_delete_reference failed");
        }
        it = iter->second->onRefSets.erase(it);
    }
    if (iter->second->onRefSets.empty()) {
        FI_HILOGE("onRefSets is empty");
        events_.erase(iter);
    }
    return true;
}

bool UnderageModelNapiEvent::RemoveCallback(uint32_t eventType, napi_value handler)
{
    FI_HILOGD("Enter, event:%{public}d", eventType);
    std::lock_guard<std::mutex> lock(eventsMutex_);
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("EventType %{public}d not found", eventType);
        return false;
    }
    if (iter->second == nullptr) {
        FI_HILOGE("listener is nullptr");
        events_.erase(iter);
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
        if (IsSameValue(env_, handler, deleteHandler)) {
            status = napi_delete_reference(env_, *it);
            if (status != napi_ok) {
                FI_HILOGE("napi_delete_reference failed");
            }
            iter->second->onRefSets.erase(it++);
            break;
        }
        ++it;
    }
    if (iter->second->onRefSets.empty()) {
        events_.erase(eventType);
    }
    return true;
}

bool UnderageModelNapiEvent::InsertRef(std::shared_ptr<UnderageModelEventListener> listener, const napi_value &handler)
{
    if (listener == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    for (auto item = listener->onRefSets.begin(); item != listener->onRefSets.end();) {
        if (*item == nullptr) {
            ++item;
            continue;
        }
        napi_value onHandler = nullptr;
        napi_status status = napi_get_reference_value(env_, *item, &onHandler);
        if (status != napi_ok) {
            FI_HILOGE("napi_get_reference_value failed");
            status = napi_delete_reference(env_, *item);
            if (status != napi_ok) {
                FI_HILOGE("napi_delete_reference failed");
                ++item;
                continue;
            }
            listener->onRefSets.erase(item++);
            continue;
        }
        if (IsSameValue(env_, handler, onHandler)) {
            FI_HILOGD("napi repeat subscribe");
            return true;
        }
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
    FI_HILOGD("ref size %{public}zu", listener->onRefSets.size());
    return true;
}

void UnderageModelNapiEvent::OnEventChanged(uint32_t eventType, int32_t result, float confidence)
{
    
    std::lock_guard<std::mutex> lock(eventsMutex_);
    auto typeIter = events_.find(eventType);
    if (typeIter == events_.end()) {
        FI_HILOGE("eventType: %{public}d not found", eventType);
        return;
    }
    if (typeIter->second == nullptr) {
        FI_HILOGE("listener is nullptr.");
        return;
    }
    for (auto item : typeIter->second->onRefSets) {
        napi_value handler = nullptr;
        napi_status ret = napi_get_reference_value(env_, item, &handler);
        if (ret != napi_ok) {
            FI_HILOGE("napi_get_reference_value for %{public}d failed, status: %{public}d", eventType, ret);
            continue;
        }
        ConvertUserAgeGroup(handler, result, confidence);
    }
}

void UnderageModelNapiEvent::ConvertUserAgeGroup(napi_value handler, int32_t result, float confidence)
{
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env_, &scope);
    CHKPV(scope);

    napi_value napiResult = nullptr;
    CHKRV_SCOPE(env_, napi_create_object(env_, &napiResult), CREATE_OBJECT, scope);
    napi_value tmpValue = nullptr;
    CHKRV_SCOPE(env_, napi_create_int32(env_, result, &tmpValue), CREATE_INT32, scope);
    CHKRV_SCOPE(env_, napi_set_named_property(env_, napiResult, "ageGroup", tmpValue), SET_NAMED_PROPERTY, scope);

    double temp = confidence;
    std::stringstream ss;
    ss << std::fixed << std::setprecision(FLOAT_PRECSION) << temp;
    ss >> temp;
    CHKRV_SCOPE(env_, napi_create_double(env_, temp, &tmpValue), "napi_create_double", scope);
    CHKRV_SCOPE(env_, napi_set_named_property(env_, napiResult, "confidence", tmpValue), SET_NAMED_PROPERTY, scope);
    napi_value callResult = nullptr;
    CHKRV_SCOPE(env_, napi_call_function(env_, nullptr, handler, TWO_PARAMETER, &napiResult, &callResult),
        CALL_FUNCTION, scope);
    napi_close_handle_scope(env_, scope);
}

bool UnderageModelNapiEvent::IsSameValue(const napi_env &env, const napi_value &lhs, const napi_value &rhs)
{
    FI_HILOGD("Enter");
    bool result = false;
    napi_status status = napi_strict_equals(env, lhs, rhs, &result);
    if (status != napi_ok) {
        FI_HILOGE("napi_strict_equals failed");
    }
    return result;
}

bool UnderageModelNapiEvent::CheckEvents(uint32_t eventType)
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> lock(eventsMutex_);
    auto typeIter = events_.find(eventType);
    if (typeIter == events_.end()) {
        FI_HILOGD("eventType %{public}d not find", eventType);
        return false;
    }
    if (typeIter->second->onRefSets.empty()) {
        return false;
    }
    return true;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS