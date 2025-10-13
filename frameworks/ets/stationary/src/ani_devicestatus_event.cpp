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

#include "ani_devicestatus_event.h"
#include "devicestatus_define.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "AniDeviceStatusEvent"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t ARG_1 { 1 };
constexpr size_t EVENT_MAP_MAX { 20 };
constexpr size_t EVENT_LIST_MAX { 30 };
} // namespace

AniDeviceStatusEvent::~AniDeviceStatusEvent()
{
    eventOnces_.clear();
    events_.clear();
}

std::shared_ptr<AniDeviceStatusEvent> AniDeviceStatusEvent::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<AniDeviceStatusEvent> instance_;

    std::call_once(flag, []() {
        instance_ = std::make_shared<AniDeviceStatusEvent>();
    });
    return instance_;
}

bool AniDeviceStatusEvent::On(int32_t eventType, ani_ref handler, bool isOnce)
{
    FI_HILOGD("On for event:%{public}d, isOnce:%{public}d", eventType, isOnce);
    std::lock_guard<std::mutex> guard(mapMutex_);
    if ((events_.size() > EVENT_MAP_MAX) || (eventOnces_.size() > EVENT_MAP_MAX)) {
        FI_HILOGE("events_ or eventOnces_ size over");
        return false;
    }
    if (events_[eventType].size() > EVENT_LIST_MAX || eventOnces_[eventType].size() > EVENT_LIST_MAX) {
        FI_HILOGE("list size over");
        return false;
    }
    if (isOnce) {
        if (!SaveCallbackByEvent(eventType, handler, isOnce, eventOnces_)) {
            FI_HILOGE("Failed to save eventOnces_ callback");
            return false;
        }
    } else {
        if (!SaveCallbackByEvent(eventType, handler, isOnce, events_)) {
            FI_HILOGE("Failed to save events_ callback");
            return false;
        }
    }
    return true;
}

bool AniDeviceStatusEvent::SaveCallbackByEvent(int32_t eventType, ani_ref handler, bool isOnce,
    std::map<int32_t, std::list<std::shared_ptr<AniDeviceStatusEventListener>>> events)
{
    CALL_DEBUG_ENTER;
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        FI_HILOGE("ani_env is nullptr");
        return false;
    }
    ani_ref onHandlerRef = nullptr;
    if (ANI_OK != env->GlobalReference_Create(handler, &onHandlerRef)) {
        FI_HILOGE("GlobalReference_Create failed");
        return false;
    }
    auto iter = events.find(eventType);
    if (iter == events.end()) {
        FI_HILOGE("eventType:%{public}d not exists", eventType);
        events[eventType] = std::list<std::shared_ptr<AniDeviceStatusEventListener>>();
    }
    if (events[eventType].empty()) {
        FI_HILOGE("events save callback");
        SaveCallback(eventType, onHandlerRef, isOnce);
        return true;
    }
    if (!IsNoExistCallback(events[eventType], handler, eventType)) {
        FI_HILOGE("Callback already exists");
        return false;
    }
    SaveCallback(eventType, onHandlerRef, isOnce);
    return true;
}

bool AniDeviceStatusEvent::IsNoExistCallback(std::list<std::shared_ptr<AniDeviceStatusEventListener>>,
    ani_ref handler, int32_t eventType)
{
    CALL_DEBUG_ENTER;
    for (const auto &item : events_[eventType]) {
        ani_boolean isEqual = false;
        auto isDuplicate =
            (ANI_OK == taihe::get_env()->Reference_StrictEquals(handler, item->onHandlerRef, &isEqual)) && isEqual;
        if (isDuplicate) {
            taihe::get_env()->GlobalReference_Delete(handler);
            FI_HILOGD("%{public}s callback already registered", LOG_TAG);
            return false;
        }
    }
    return true;
}

void AniDeviceStatusEvent::SaveCallback(int32_t eventType, ani_ref handler, bool isOnce)
{
    auto listener = std::make_shared<AniDeviceStatusEventListener>();
    listener->onHandlerRef = handler;
    if (isOnce) {
        eventOnces_[eventType].push_back(listener);
    } else {
        events_[eventType].push_back(listener);
    }
    FI_HILOGD("Add handler to list %{public}d", eventType);
}

void AniDeviceStatusEvent::CheckRet(int32_t eventType, size_t argc, int32_t value,
    std::shared_ptr<AniDeviceStatusEventListener> &typeHandler)
{
    CHKPV(typeHandler);
    ani_ref handler = typeHandler->onHandlerRef;
    if (handler == nullptr) {
        FI_HILOGE("OnEvent handler for %{public}d failed", eventType);
        return;
    }
    Data data = {
        .type = static_cast<Type>(eventType),
        .value = static_cast<OnChangedValue>(value)
    };
    data_.push_back(data);
}

void AniDeviceStatusEvent::OnEvent(int32_t eventType, size_t argc, int32_t value, bool isOnce)
{
    CALL_DEBUG_ENTER;
    FI_HILOGD("OnEvent for %{public}d, isOnce:%{public}d", eventType, isOnce);
    std::map<int32_t, std::list<std::shared_ptr<AniDeviceStatusEventListener>>>::iterator typeHandler;
    if (isOnce) {
        typeHandler = eventOnces_.find(eventType);
        if (typeHandler == eventOnces_.end()) {
            FI_HILOGE("OnEvent eventType %{public}d not found", eventType);
            return;
        }
    } else {
        typeHandler = events_.find(eventType);
        if (typeHandler == events_.end()) {
            FI_HILOGE("OnEvent eventType %{public}d not found", eventType);
            return;
        }
    }
    FI_HILOGD("%{public}zu callbacks of eventType %{public}d are sent",
        typeHandler->second.size(), eventType);
    for (auto handler : typeHandler->second) {
        CheckRet(eventType, argc, value, handler);
    }
}

void AniDeviceStatusEvent::OnDeviceStatusChangedDone(int32_t type, int32_t value, bool isOnce)
{
    CALL_DEBUG_ENTER;
    FI_HILOGD("value:%{public}d", value);
    OnEvent(type, ARG_1, value, isOnce);
}

bool AniDeviceStatusEvent::OffOnce(int32_t eventType, ani_ref handler)
{
    FI_HILOGD("AniDeviceStatusEvent OffOnce in for event:%{public}d", eventType);
    auto iter = eventOnces_.find(eventType);
    if (iter == eventOnces_.end()) {
        FI_HILOGE("eventType %{public}d not found", eventType);
        return false;
    }
    for (const auto &listener : eventOnces_[eventType]) {
        ani_boolean isEqual = false;
        auto isDuplicate =
            (ANI_OK == taihe::get_env()->Reference_StrictEquals(handler, listener->onHandlerRef, &isEqual)) && isEqual;
        if (isDuplicate) {
            FI_HILOGI("Delete once handler from list %{public}d", eventType);
            // 删除？
            taihe::get_env()->GlobalReference_Delete(handler);
            eventOnces_[eventType].remove(listener);
            break;
        }
    }
    FI_HILOGI("%{public}zu listeners in the once list of %{public}d",
        eventOnces_[eventType].size(), eventType);
    return events_[eventType].empty();
}

bool AniDeviceStatusEvent::RemoveAllCallback(int32_t eventType)
{
    CALL_DEBUG_ENTER;
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("evenType %{public}d not found", eventType);
        return false;
    }
    events_.erase(eventType);
    return true;
}

bool AniDeviceStatusEvent::Off(int32_t eventType, ani_ref handler)
{
    FI_HILOGD("Unregister handler of event(%{public}d)", eventType);
    std::lock_guard<std::mutex> guard(mapMutex_);
    return RemoveAllCallback(eventType);
}

void AniDeviceStatusEvent::ClearEventMap()
{
    for (auto &iter : events_) {
        iter.second.clear();
    }
    for (auto &iter : eventOnces_) {
        iter.second.clear();
    }
    events_.clear();
    eventOnces_.clear();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS