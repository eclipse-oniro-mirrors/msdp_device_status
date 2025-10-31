/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
 
#include "ani_boomerang.h"
 
#include <map>
 
#include "devicestatus_define.h"
#include "fi_log.h"
 
#undef LOG_TAG
#define LOG_TAG "AniBoomerangEvent"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t EVENT_MAP_MAX { 20 };
constexpr size_t EVENT_LIST_MAX { 30 };
} // namespace
 
bool AniBoomerangEvent::On(int32_t eventType, ani_ref handler, bool isOnce)
{
    FI_HILOGD("%{public}s On for event:%{public}d, isOnce:%{public}d", LOG_TAG, eventType, isOnce);
    std::lock_guard<std::mutex> guard(mutex_);
    if ((events_.size() > EVENT_MAP_MAX) || (eventOnces_.size() > EVENT_MAP_MAX)) {
        FI_HILOGE("%{public}s events_ or eventOnces_ size over", LOG_TAG);
        return false;
    }
    if (events_[eventType].size() > EVENT_LIST_MAX || eventOnces_[eventType].size() > EVENT_LIST_MAX) {
        FI_HILOGE("%{public}s list size over", LOG_TAG);
        return false;
    }
    if (isOnce) {
        if (!SaveCallbackByEvent(eventType, handler, isOnce, eventOnces_)) {
            FI_HILOGE("%{public}s Failed to save eventOnces_ callback", LOG_TAG);
            return false;
        }
    } else {
        if (!SaveCallbackByEvent(eventType, handler, isOnce, events_)) {
            FI_HILOGE("%{public}s Failed to save events_ callback", LOG_TAG);
            return false;
        }
    }
    return true;
}
 
bool AniBoomerangEvent::SaveCallbackByEvent(int32_t eventType, ani_ref handler, bool isOnce,
    std::map<int32_t, std::list<std::shared_ptr<AniBoomerangEventListener>>> &events)
{
    CALL_DEBUG_ENTER;
    ani_ref onHandlerRef = nullptr;
    ani_env *env = taihe::get_env();
    ani_status status = env->GlobalReference_Create(handler, &onHandlerRef);
    if (status != ANI_OK) {
        FI_HILOGE("%{public}s Failed to napi_create_reference", LOG_TAG);
        return false;
    }
    auto iter = events.find(eventType);
    if (iter == events.end()) {
        FI_HILOGE("%{public}s eventType:%{public}d not exists", LOG_TAG, eventType);
        events[eventType] = std::list<std::shared_ptr<AniBoomerangEventListener>>();
    }
    if (events[eventType].empty()) {
        FI_HILOGE("%{public}s events save callback", LOG_TAG);
        SaveCallback(eventType, onHandlerRef, isOnce);
        return true;
    }
    if (!IsNoExistCallback(events[eventType], handler, eventType)) {
        events_.erase(eventType);
        FI_HILOGE("%{public}s Callback already exists", LOG_TAG);
        return false;
    }
    SaveCallback(eventType, onHandlerRef, isOnce);
    return true;
}
 
bool AniBoomerangEvent::IsNoExistCallback(std::list<std::shared_ptr<AniBoomerangEventListener>> listeners,
    ani_ref handler, int32_t eventType)
{
    CALL_DEBUG_ENTER;
    for (const auto &item : listeners) {
        ani_boolean isEqual = false;
        auto isDuplicate = taihe::get_env()->Reference_StrictEquals(handler, item->onHandlerRef, &isEqual);
        if (isDuplicate != ANI_OK) {
            taihe::get_env()->GlobalReference_Delete(handler);
            FI_HILOGD("%{public}s callback already registered", LOG_TAG);
            return true;
        }
    }
    return false;
}
 
void AniBoomerangEvent::SaveCallback(int32_t eventType, ani_ref onHandlerRef, bool isOnce)
{
    auto listener = std::make_shared<AniBoomerangEventListener>();
    listener->onHandlerRef = onHandlerRef;
    if (isOnce) {
        eventOnces_[eventType].push_back(listener);
    } else {
        events_[eventType].push_back(listener);
    }
    FI_HILOGD("%{public}s Add handler to list %{public}d", LOG_TAG, eventType);
}
 
bool AniBoomerangEvent::Off(int32_t eventType)
{
    FI_HILOGD("%{public}s Unregister handler of event(%{public}d)", LOG_TAG, eventType);
    std::lock_guard<std::mutex> guard(mutex_);
    return RemoveAllCallback(eventType);
}
 
bool AniBoomerangEvent::OffOnce(int32_t eventType, ani_ref handler)
{
    FI_HILOGD("%{public}s AniBoomerangEvent OffOnce in for event:%{public}d", LOG_TAG, eventType);
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = eventOnces_.find(eventType);
    if (iter == eventOnces_.end()) {
        FI_HILOGE("%{public}s eventType %{public}d not found", LOG_TAG, eventType);
        return false;
    }
    for (const auto &listener : eventOnces_[eventType]) {
        ani_boolean is_equal = false;
        if (ANI_OK == taihe::get_env()->Reference_StrictEquals(handler, listener->onHandlerRef, &is_equal)
             && is_equal) {
            eventOnces_[eventType].remove(listener);
            eventOnces_.erase(eventType);
            break;
        }
    }
    return events_[eventType].empty();
}
 
bool AniBoomerangEvent::RemoveAllCallback(int32_t eventType)
{
    CALL_DEBUG_ENTER;
    events_.erase(eventType);
    eventOnces_.erase(eventType);
    return true;
}
 
void AniBoomerangEvent::OnEvent(int32_t eventType, int32_t value, bool isOnce)
{
    CALL_DEBUG_ENTER;
    FI_HILOGD("%{public}s OnEvent for %{public}d, isOnce:%{public}d", LOG_TAG, eventType, isOnce);
    std::lock_guard<std::mutex> guard(mutex_);
    std::map<int32_t, std::list<std::shared_ptr<AniBoomerangEventListener>>>::iterator typeHandler;
    if (isOnce) {
        typeHandler = eventOnces_.find(eventType);
        if (typeHandler == eventOnces_.end()) {
            FI_HILOGE("%{public}s OnEvent eventType %{public}d not found", LOG_TAG, eventType);
            return;
        }
    } else {
        typeHandler = events_.find(eventType);
        if (typeHandler == events_.end()) {
            FI_HILOGE("%{public}s OnEvent eventType %{public}d not found", LOG_TAG, eventType);
            return;
        }
    }
    FI_HILOGD("%{public}s %{public}zu callbacks of eventType %{public}d are sent", LOG_TAG,
        typeHandler->second.size(), eventType);
    for (auto handler : typeHandler->second) {
        BoomerangData data = {
            .type = static_cast<BoomerangType>(eventType),
            .status = static_cast<BoomerangStatus>(value)
        };
        data_.push_back(data);
    }
}
 
void AniBoomerangEvent::ClearEventMap()
{
    std::lock_guard<std::mutex> guard(mutex_);
    events_.clear();
    eventOnces_.clear();
}
 
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS