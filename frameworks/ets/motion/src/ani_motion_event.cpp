/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "devicestatus_define.h"
#undef LOG_TAG
#define LOG_TAG "AniMotionEvent"

namespace OHOS {
namespace Msdp {
std::mutex g_mutex;
#ifdef MOTION_ENABLE
auto &g_motionClient = MotionClient::GetInstance();
#endif

ani_env* AniMotionEvent::env_ {nullptr};
ani_vm* AniMotionEvent::vm_ {nullptr};
#ifdef MOTION_ENABLE
void AniMotionCallback::OnMotionChanged(const MotionEvent &event)
{
    FI_HILOGD("Enter");
    std::lock_guard<std::mutex> guard(g_mutex);
    auto data = std::make_shared<MotionEvent>();
    CHKPV(data);
    data->type = event.type;
    data->status = event.status;
    data->dataLen = event.dataLen;
    data->data = event.data;
    EmitOnEvent(data);
    FI_HILOGD("Exit");
}

void AniMotionCallback::EmitOnEvent(std::shared_ptr<MotionEvent> data)
{
    if (data == nullptr) {
        FI_HILOGE("data is nullptr");
        return;
    }
 
    AniMotionEvent::GetInstance()->OnEventOperatingHand(data->type, 1, data);
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
    return typeIter->second->onRefSets.empty();
}

bool AniMotionEvent::SubscribeCallback(int32_t type)
{
    auto iter = callbacks_.find(type);
    if (iter != callbacks_.end()) {
        return true;
    }
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
        taihe::set_business_error(PERMISSION_DENIED, "Permission denined");
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
    if (CheckEvents(type)) {
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
        taihe::set_business_error(PERMISSION_DENIED, "Permission denined");
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
    for (const auto &item : listener->onRefSets) {
        ani_boolean isEqual = false;
        auto isDuplicate =
            (taihe::get_env()->Reference_StrictEquals(onHandlerRef, item, &isEqual) == ANI_OK) && isEqual;
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

bool AniMotionEvent::AddCallback(int32_t eventType, uintptr_t opq, ani_vm* vm)
{
    FI_HILOGD("Enter");
    vm_ = vm;
    ani_ref onHandlerRef = nullptr;
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    if (taihe::get_env()->GlobalReference_Create(callbackObj, &onHandlerRef) != ANI_OK) {
        FI_HILOGE("GlobalReference_Create failed");
        return false;
    }
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGD("found event: %{public}d", eventType);
        std::shared_ptr<MotionEventListener> listener = std::make_shared<MotionEventListener>();
        std::set<ani_ref> onRefSets;
        listener->onRefSets = onRefSets;

        auto ret = listener->onRefSets.insert(onHandlerRef);
        if (!ret.second) {
            FI_HILOGE("Failed to insert refs");
            taihe::get_env()->GlobalReference_Delete(onHandlerRef);
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
    FI_HILOGI("RemoveAllCallback in, event: %{public}d", eventType);
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("EventType: %{public}d not found", eventType);
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
    for (const auto item : iter->second->onRefSets) {
        taihe::get_env()->GlobalReference_Delete(item);
    }
    iter->second->onRefSets.clear();
    events_.erase(iter);
    return true;
}

bool AniMotionEvent::RemoveCallback(int32_t eventType, uintptr_t opq)
{
    FI_HILOGI("RemoveCallback in, event: %{public}d", eventType);
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("EventType: %{public}d not found", eventType);
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
    ani_ref onHandlerRef = nullptr;
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    if (taihe::get_env()->GlobalReference_Create(callbackObj, &onHandlerRef) != ANI_OK) {
        FI_HILOGE("GlobalReference_Create failed");
        return false;
    }
    auto& refSet = iter->second->onRefSets;
    for (auto it = refSet.begin(); it != refSet.end();) {
        ani_boolean isEqual = false;
        auto isDuplicate =
            (taihe::get_env()->Reference_StrictEquals(onHandlerRef, *it, &isEqual) == ANI_OK) && isEqual;
        if (isDuplicate) {
            it = refSet.erase(it);
            FI_HILOGD("callback already remove");
        } else {
            ++it;
        }
    }
    if (iter->second->onRefSets.empty()) {
        events_.erase(eventType);
    }
    taihe::get_env()->GlobalReference_Delete(onHandlerRef);
    return true;
}

ani_object AniMotionEvent::CreateAniUndefined(ani_env* env)
{
    ani_ref aniRef;
    if (env == nullptr) {
        FI_HILOGE("null env");
        return nullptr;
    }
    env->GetUndefined(&aniRef);
    return static_cast<ani_object>(aniRef);
}

ani_enum_item AniMotionEvent::CreateAniOperatingHandStatus(ani_env* env, int32_t status)
{
    ani_enum enumType;
    ani_enum_item enumItem = nullptr;
    ani_status ret = env->FindEnum("@ohos.multimodalAwareness.motion.motion.OperatingHandStatus", &enumType);
    if (ret != ANI_OK) {
        FI_HILOGE("[ANI] WindowStatusType not found");
        return enumItem;
    }
    ret = env->Enum_GetEnumItemByIndex(enumType, ani_int(status), &enumItem);
    if (ret != ANI_OK) {
        FI_HILOGE("env Enum_GetEnumItemByIndex failed");
        return enumItem;
    }
    return enumItem;
}

ani_enum_item AniMotionEvent::CreateAniHoldingHandStatus(ani_env* env, int32_t status)
{
    ani_enum enumType;
    ani_enum_item enumItem = nullptr;
    ani_status ret = env->FindEnum("@ohos.multimodalAwareness.motion.motion.HoldingHandStatus", &enumType);
    if (ret != ANI_OK) {
        FI_HILOGE("[ANI] WindowStatusType not found");
        return enumItem;
    }
    ret = env->Enum_GetEnumItemByIndex(enumType, ani_int(status), &enumItem);
    if (ret != ANI_OK) {
        FI_HILOGE("env Enum_GetEnumItemByIndex failed");
        return enumItem;
    }
    return enumItem;
}

void AniMotionEvent::OnEventOperatingHand(int32_t eventType, size_t argc, const std::shared_ptr<MotionEvent> &event)
{
    FI_HILOGD("eventType: %{public}d,%{public}d", eventType, event->status);
    std::lock_guard<std::mutex> guard(mutex_);
    if (vm_ == nullptr) {
        FI_HILOGE("vm_ is nullptr");
        return;
    }
    auto typeIter = events_.find(eventType);
    if (typeIter == events_.end()) {
        FI_HILOGE("eventType: %{public}d not found", eventType);
        return;
    }

    ani_env* env = AttachAniEnv(vm_);
    if (env == nullptr) {
        FI_HILOGE("AttachAniEnv get env is nullptr");
        return;
    }
    for (auto item : typeIter->second->onRefSets) {
        ani_ref handler = item;
        std::vector<ani_ref> args;
        if (eventType == MOTION_TYPE_HOLDING_HAND) {
            auto statusAni = CreateAniHoldingHandStatus(env, event->status);
            args.push_back(static_cast<ani_ref>(statusAni));
        } else if (eventType == MOTION_TYPE_OPERATING_HAND) {
            auto statusAni = CreateAniOperatingHandStatus(env, event->status);
            args.push_back(static_cast<ani_ref>(statusAni));
        } else {
            FI_HILOGE("status is err. eventType: %{public}d ", eventType);
            return;
        }
        ani_ref result;
        if (env->FunctionalObject_Call(static_cast<ani_fn_object>(handler), args.size(), args.data(),
            &result) != ANI_OK) {
            HILOG_ERROR(LOG_CORE, "Excute CallBack failed. %{public}d",
                env->FunctionalObject_Call(static_cast<ani_fn_object>(handler), args.size(), args.data(),
                &result));
            vm_->DetachCurrentThread();
            return;
        }
    }
    vm_->DetachCurrentThread();
}

ani_vm* AniMotionEvent::GetAniVm(ani_env* env)
{
    if (env == nullptr) {
        FI_HILOGE("null env");
        return nullptr;
    }
    ani_vm* vm = nullptr;
    if (env->GetVM(&vm) != ANI_OK) {
        FI_HILOGE("GetVM failed");
        return nullptr;
    }
    return vm;
}

ani_env* AniMotionEvent::GetAniEnv(ani_vm* vm)
{
    if (vm == nullptr) {
        FI_HILOGE("null vm");
        return nullptr;
    }
    ani_env* env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        FI_HILOGE("GetEnv failed: %{public}d", vm->GetEnv(ANI_VERSION_1, &env));
        return nullptr;
    }
    return env;
}

ani_env* AniMotionEvent::AttachAniEnv(ani_vm* vm)
{
    if (vm == nullptr) {
        FI_HILOGE("null vm");
        return nullptr;
    }
    ani_env *workerEnv = nullptr;
    ani_options aniArgs {0, nullptr};
    if (vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &workerEnv) != ANI_OK) {
        FI_HILOGE("Attach Env failed: %{public}d", vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &workerEnv));
        return nullptr;
    }
    return workerEnv;
}
#endif
} // namespace Msdp
} // namespace OHOS