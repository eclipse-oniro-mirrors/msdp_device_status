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

#include "ani_motion_event.h"

#ifdef MOTION_ENABLE
#include "motion_client.h"
#endif

#undef LOG_TAG
#define LOG_TAG "AniMotionEvent"

namespace OHOS {
namespace Msdp {
std::mutex g_mutex;

#ifdef MOTION_ENABLE
void AniMotionCallback::OnMotionChanged(const MotionEvent &event)
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> guard(g_mutex);
    auto* data = new (std::nothrow) MotionEvent();
    CHKPV(data);
    data->type = event.type;
    data->status = event.status;
    data->dataLen = event.dataLen;
    data->data = event.data;
    EmitOnEvent(data);
    FI_HILOGD("Exit");
}

void AniMotionCallback::EmitOnEvent(MotionEvent* data)
{
    if (data == nullptr) {
        FI_HILOGE("data is nullptr");
        return;
    }
 
    AniMotionEvent::GetInstance()->OnEventOperatingHand(data->type, 1, *data);
    delete data;
}
#endif

std::shared_ptr<AniMotionEvent> AniMotionEvent::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<AniMotionEvent> instance_;
 
    std::call_once(flag, []() {
        instance_ = std::make_shared<AniMotionEvent>();
    });
    return instance_;
}

#ifdef MOTION_ENABLE
bool AniMotionEvent::CheckEvents(int32_t eventType)
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

bool AniMotionEvent::SubscribeCallback(int32_t type)
{
    auto iter = callbacks_.find(type);
    if (iter != callbacks_.end()) {
        return true;
    }
    FI_HILOGD("Don't find callback, to create");
    sptr<IMotionCallback> callback = new (std::nothrow) AniMotionCallback();
    if (callback == nullptr) {
        FI_HILOGE("callback is null");
        taihe::set_business_error(SUBSCRIBE_EXCEPTION, "Subscribe failed");
        return false;
    }
    int32_t ret = g_motionClient.SubscribeCallback(type, callback);
    if (ret == RET_OK) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            callbacks_.insert(std::make_pair(type, callback));
        }
        return true;
    }
    
    if (ret == PERMISSION_DENIED) {
        FI_HILOGE("failed to subscribe");
        taihe::set_business_error(PERMISSION_EXCEPTION, "Permission denined");
        return false;
    } else if (ret == DEVICE_EXCEPTION || ret == HOLDING_HAND_FEATURE_DISABLE) {
        FI_HILOGE("failed to subscribe");
        taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
        return false;
    } else {
        FI_HILOGE("failed to subscribe");
        taihe::set_business_error(SUBSCRIBE_EXCEPTION, "Subscribe failed");
        return false;
    }

    return true;
}

bool AniMotionEvent::UnSubscribeCallback(int32_t type)
{
    if (!CheckEvents(type)) {
        return false;
    }
    auto iter = callbacks_.find(type);
    if (iter == callbacks_.end()) {
        FI_HILOGE("faild to find callback");
        taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
        return false;
    }
    
    int32_t ret = g_motionClient.UnsubscribeCallback(type, iter->second);
    if (ret == RET_OK) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            callbacks_.erase(iter);
        }
        return true;
    }
    if (ret == PERMISSION_DENIED) {
        FI_HILOGE("failed to unsubscribe");
        taihe::set_business_error(PERMISSION_EXCEPTION, "Permission denined");
        return false;
    } else if (ret == DEVICE_EXCEPTION || ret == HOLDING_HAND_FEATURE_DISABLE) {
        FI_HILOGE("failed to unsubscribe");
        taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
        return false;
    } else {
        FI_HILOGE("failed to unsubscribe");
        taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
        return false;
    }

    return false;
}

bool AniMotionEvent::InsertRef(std::shared_ptr<MotionEventListener> listener, ani_ref onHandlerRef)
{
    if (listener == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    for (auto item : listener->onRefSets) {
        ani_boolean isEqual = false;
        auto isDuplicate =
            (ANI_OK == taihe::get_env()->Reference_StrictEquals(onHandlerRef, *item, &isEqual)) && isEqual;
        if (isDuplicate) {
            taihe::get_env()->GlobalReference_Delete(onHandlerRef);
            FI_HILOGD("callback already registered");
            return true;
        }
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

bool AniMotionEvent::AddCallback(int32_t eventType, taihe::callback_view<void(OperatingHandStatus_t)> f, uintptr_t opq)
{
    FI_HILOGD("Enter");
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        FI_HILOGE("ani_env is nullptr");
        return false;
    }
    ani_ref onHandlerRef = nullptr;
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    if (ANI_OK != env->GlobalReference_Create(callbackObj, &onHandlerRef)) {
        FI_HILOGE("GlobalReference_Create failed");
        return false;
    }

    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGD("found event:%{public}d", eventType);
        std::shared_ptr<MotionEventListener> listener = std::make_shared<MotionEventListener>();
        std::set<ani_ref> onRefSets;
        listener->onRefSets = onRefSets;

        auto ret = listener->onRefSets.insert(onHandlerRef);
        if (!ret.second) {
            FI_HILOGE("Failed to insert refs");
            return false;
        }
        std::lock_guard<std::mutex> guard(mutex_);
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
    if (!InsertRef(iter->second, onHandlerRef)) {
        FI_HILOGE("Failed to insert ref");
        return false;
    }
    return true;
}

bool AniMotionEvent::RemoveAllCallback(int32_t eventType)
{
    FI_HILOGD("RemoveAllCallback in, event:%{public}d", eventType);
    std::lock_guard<std::mutex> guard(mutex_);
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
        FI_HILOGE("onRefSets is empty");
        return false;
    }
    iter->second->onRefSets.clear();
    if (iter->second->onRefSets.empty()) {
        FI_HILOGE("onRefSets is empty");
        events_.erase(iter);
    }
    return true;
}

bool AniMotionEvent::RemoveCallback(int32_t eventType, uintptr_t opq)
{
    FI_HILOGD("RemoveCallback in, event:%{public}d", eventType);
    std::lock_guard<std::mutex> guard(mutex_);
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
        FI_HILOGE("onRefSets is empty");
        return false;
    }
    for (auto &item : iter->second->onRefSets) {
        ani_boolean isEqual = false;
        ani_ref onHandlerRef = nullptr;
        ani_object callbackObj = reinterpret_cast<ani_object>(opq);
        if (ANI_OK != taihe::get_env()->GlobalReference_Create(callbackObj, &onHandlerRef)) {
            FI_HILOGE("GlobalReference_Create failed");
            return false;
        }
        auto isDuplicate =
            (ANI_OK == taihe::get_env()->Reference_StrictEquals(onHandlerRef, *item, &isEqual)) && isEqual;
        if (isDuplicate) {
            iter->second->onRefSets.erase(item);
            FI_HILOGD("callback already remove");
            break;
        }
    }
    if (iter->second->onRefSets.empty()) {
        events_.erase(eventType);
    }
    return true;
}

void AniMotionEvent::OnEventOperatingHand(int32_t eventType, size_t argc, const MotionEvent &event)
{
    FI_HILOGD("eventType: %{public}d", eventType);
    auto typeIter = events_.find(eventType);
    if (typeIter == events_.end()) {
        FI_HILOGE("eventType: %{public}d not found", eventType);
        return;
    }
    for (auto item : typeIter->second->onRefSets) {
        ani_ref handler = *item;
        handler(event.status);
    }
}
#endif
} // namespace Msdp
} // namespace OHOS