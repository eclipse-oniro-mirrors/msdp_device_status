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
    events_.clear();
    if (env_ != nullptr && thisVarRef_ != nullptr) {
        napi_delete_reference(env_, thisVarRef_);
    }
}

bool UnderageModelNapiEvent::AddCallback(uint32_t eventType, napi_value handler)
{
    FI_HILOGD("Enter");
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
        listener->onHandlerRef = onHandlerRef;
        events_.insert(std::make_pair(eventType, listener));
        FI_HILOGD("Insert finish");
        return true;
    }
    FI_HILOGD("found event: %{public}d", eventType);
    if (iter->second == nullptr || iter->second->onHandlerRef == nullptr) {
        FI_HILOGE("listener or onHandlerRef is nullptr");
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

bool UnderageModelNapiEvent::RemoveCallback(uint32_t eventType)
{
    FI_HILOGD("Enter, event:%{public}d", eventType);
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("EventType %{public}d not found", eventType);
        return false;
    }
    if (iter->second == nullptr || iter->second->onHandlerRef == nullptr) {
        FI_HILOGE("listener or onHandlerRef is nullptr");
        events_.erase(iter);
        return false;
    }

    napi_status status = napi_delete_reference(env_, iter->second->onHandlerRef);
    if (status != napi_ok) {
        FI_HILOGW("napi_delete_reference failed");
    }
    events_.erase(iter);
    return true;
}

bool UnderageModelNapiEvent::InsertRef(std::shared_ptr<UnderageModelEventListener> listener, const napi_value &handler)
{
    if (listener == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    napi_value onHandler = nullptr;
    napi_status status = napi_get_reference_value(env_, listener->onHandlerRef, &onHandler);
    if (status != napi_ok) {
        FI_HILOGE("napi_get_reference_value failed");
        status = napi_delete_reference(env_, listener->onHandlerRef);
        if (status != napi_ok) {
            FI_HILOGE("napi_delete_reference failed");
        }
        return false;
    }
    if (IsSameValue(env_, handler, onHandler)) {
        return true;
    }
    napi_ref onHandlerRef = nullptr;
    status = napi_create_reference(env_, handler, ONE_PARAMETER, &onHandlerRef);
    if (status != napi_ok) {
        FI_HILOGE("napi_create_reference failed");
        return false;
    }
    FI_HILOGD("Insert new ref");
    listener->onHandlerRef = onHandlerRef;
    return true;
}

void UnderageModelNapiEvent::OnEventChanged(uint32_t eventType, int32_t result, float confidence)
{
    auto typeIter = events_.find(eventType);
    if (typeIter == events_.end()) {
        FI_HILOGE("eventType: %{public}d not found", eventType);
        return;
    }
    if (typeIter->second == nullptr || typeIter->second->onHandlerRef == nullptr) {
        FI_HILOGE("listener or onHandlerRef is nullptr.");
        return;
    }
    napi_value handler = nullptr;
    napi_status ret = napi_get_reference_value(env_, typeIter->second->onHandlerRef, &handler);
    if (ret != napi_ok) {
        FI_HILOGE("napi_get_reference_value for %{public}d failed, status: %{public}d", eventType, ret);
        return;
    }
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

bool UnderageModelNapiEvent::CheckEvents(int32_t eventType)
{
    FI_HILOGD("Enter");
    auto typeIter = events_.find(eventType);
    if (typeIter == events_.end()) {
        FI_HILOGD("eventType %{public}d not find", eventType);
        return true;
    }
    return false;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS