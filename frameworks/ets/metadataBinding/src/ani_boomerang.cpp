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
#include "securec.h"
#undef LOG_TAG
#define LOG_TAG "AniBoomerangEvent"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t EVENT_MAP_MAX { 20 };
constexpr size_t EVENT_LIST_MAX { 30 };
} // namespace

ani_env* AniBoomerangEvent::env_ {nullptr};
ani_vm* AniBoomerangEvent::vm_ {nullptr};
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
        env_ = env;
        vm_ = AniBoomerangCommon::GetInstance()->GetAniVm(env);
        return true;
    }
    if (!IsNoExistCallback(events[eventType], handler, eventType)) {
        env->GlobalReference_Delete(onHandlerRef);
        FI_HILOGE("%{public}s Callback already exists", LOG_TAG);
        return false;
    }
    SaveCallback(eventType, onHandlerRef, isOnce);
    env_ = env;
    vm_ = AniBoomerangCommon::GetInstance()->GetAniVm(env);
    return true;
}

bool AniBoomerangEvent::IsNoExistCallback(const std::list<std::shared_ptr<AniBoomerangEventListener>> &listeners,
    ani_ref handler, int32_t eventType)
{
    CALL_DEBUG_ENTER;
    for (const auto &item : listeners) {
        ani_boolean isEqual = false;
        auto isDuplicate = taihe::get_env()->Reference_StrictEquals(handler, item->onHandlerRef, &isEqual);
        if ((isDuplicate == ANI_OK) && isEqual) {
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
    return RemoveAllCallback(eventType, true) && RemoveAllCallback(eventType, false);
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
    bool removed = false;
    auto& listeners = eventOnces_[eventType];
    for (auto it = listeners.begin(); it != listeners.end(); ) {
        ani_boolean is_equal = false;
        if (ANI_OK == taihe::get_env()->Reference_StrictEquals(handler, (*it)->onHandlerRef, &is_equal)
             && is_equal) {
            taihe::get_env()->GlobalReference_Delete((*it)->onHandlerRef);
            it = listeners.erase(it);
            removed = true;
        } else {
            ++it;
        }
    }
    return removed;
}

bool AniBoomerangEvent::RemoveAllCallback(int32_t eventType, bool isEvent)
{
    std::list<std::shared_ptr<AniBoomerangEventListener>> eventList;
    if (isEvent) {
        if (events_.find(eventType) == events_.end()) {
            return false;
        }
        eventList = events_[eventType];
    } else {
        if (eventOnces_.find(eventType) == eventOnces_.end()) {
            return false;
        }
        eventList = eventOnces_[eventType];
    }
    for (auto listener : eventList) {
        if (listener == nullptr || listener->onHandlerRef == nullptr) {
            continue;
        }
        taihe::get_env()->GlobalReference_Delete(listener->onHandlerRef);
        listener->onHandlerRef = nullptr;
    }
    if (isEvent) {
        events_.erase(eventType);
    } else {
        eventOnces_.erase(eventType);
    }
    return true;
}

void AniBoomerangEvent::CheckRet(int32_t eventType, size_t argc, int32_t value,
    std::shared_ptr<AniBoomerangEventListener> &typeHandler)
{
    ani_env* env = AniBoomerangCommon::GetInstance()->AttachAniEnv(vm_);
    if (env == nullptr) {
        FI_HILOGE("AttachAniEnv get env is nullptr");
        return;
    }
    ani_ref onHandlerRef = nullptr;
    if (ANI_OK != env->GlobalReference_Create(typeHandler->onHandlerRef, &onHandlerRef)) {
        FI_HILOGE("GlobalReference_Create failed");
        return;
    }

    ani_object statusAni = AniBoomerangCommon::GetInstance()->CreateAniInt(env, value);
    std::vector<ani_ref> args;
    args.push_back(static_cast<ani_ref>(statusAni));
    ani_ref result;
    if (env->FunctionalObject_Call(static_cast<ani_fn_object>(onHandlerRef), args.size(), args.data(), &result)
        != ANI_OK) {
        HILOG_ERROR(LOG_CORE, "Excute CallBack failed.");
    }
}

void AniBoomerangEvent::OnEvent(int32_t eventType, int32_t value, bool isOnce)
{
    CALL_DEBUG_ENTER;
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
    CheckRet(eventType, 1, value, typeHandler->second.back());
}
 
void AniBoomerangEvent::ClearEventMap()
{
    std::lock_guard<std::mutex> guard(mutex_);
    std::vector<int32_t> eventTypes;
    for (const auto& item : events_) {
        eventTypes.push_back(item.first);
    }

    for (const auto& type : eventTypes) {
        RemoveAllCallback(type, true);
    }

    std::vector<int32_t> onceEventTypes;
    for (const auto& item : eventOnces_) {
        onceEventTypes.push_back(item.first);
    }

    for (const auto& type : onceEventTypes) {
        RemoveAllCallback(type, false);
    }
    events_.clear();
    eventOnces_.clear();
}

std::shared_ptr<AniBoomerangCommon> AniBoomerangCommon::GetInstance()
{
    static std::shared_ptr<AniBoomerangCommon> install_ = nullptr;
    if (install_ == nullptr) {
        install_ = std::make_shared<AniBoomerangCommon>();
    }
    return install_;
}

ani_object AniBoomerangCommon::CreateAniUndefined(ani_env* env)
{
    ani_ref aniRef;
    if (env == nullptr) {
        FI_HILOGE("null env");
        return nullptr;
    }
    env->GetUndefined(&aniRef);
    return static_cast<ani_object>(aniRef);
}

ani_object AniBoomerangCommon::CreateAniInt(ani_env* env, int32_t status)
{
    if (env == nullptr) {
        FI_HILOGE("env is nullptr");
        return CreateAniUndefined(env);
    }
    ani_class aniClass;
    ani_status ret = env->FindClass("std.core.Int", &aniClass);
    if (ret != ANI_OK) {
        FI_HILOGE("[ANI] class not found");
        return CreateAniUndefined(env);
    }
    ani_method aniCtor;
    ret = env->Class_FindMethod(aniClass, "<ctor>", "i:", &aniCtor);
    if (ret != ANI_OK) {
        FI_HILOGE("[ANI] ctor not found");
        return CreateAniUndefined(env);
    }
    ani_object aniStatus;
    ret = env->Object_New(aniClass, aniCtor, &aniStatus, ani_int(status));
    if (ret != ANI_OK) {
        FI_HILOGE("[ANI] fail to create new obj");
        return CreateAniUndefined(env);
    }
    return aniStatus;
}

ani_vm* AniBoomerangCommon::GetAniVm(ani_env* env)
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

ani_env* AniBoomerangCommon::GetAniEnv(ani_vm* vm)
{
    if (vm == nullptr) {
        FI_HILOGE("null vm");
        return nullptr;
    }
    ani_env* env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        FI_HILOGE("GetEnv failed");
        return nullptr;
    }
    return env;
}

ani_env* AniBoomerangCommon::AttachAniEnv(ani_vm* vm)
{
    if (vm == nullptr) {
        FI_HILOGE("null vm");
        return nullptr;
    }
    ani_env *workerEnv = nullptr;
    ani_options aniArgs {0, nullptr};
    if (vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &workerEnv) != ANI_OK) {
        FI_HILOGE("Attach Env failed");
        return nullptr;
    }
    return workerEnv;
}

ani_object AniBoomerangCommon::Uint8ArrayToObject(ani_env *env, const std::vector<uint8_t> values)
{
    ani_object aniObject = nullptr;
    ani_class arrayClass;
    if (env == nullptr) {
        FI_HILOGE("null env");
        return aniObject;
    }
    ani_status retCode = env->FindClass("escompat.Uint8Array", &arrayClass);
    if (retCode != ANI_OK) {
        FI_HILOGE("Failed: env->FindClass()");
        return aniObject;
    }
    ani_method arrayCtor;
    retCode = env->Class_FindMethod(arrayClass, "<ctor>", "i:", &arrayCtor);
    if (retCode != ANI_OK) {
        FI_HILOGE("Failed: env->Class_FindMethod()");
        return aniObject;
    }
    auto valueSize = values.size();
    retCode = env->Object_New(arrayClass, arrayCtor, &aniObject, valueSize);
    if (retCode != ANI_OK) {
        FI_HILOGE("Failed: env->Object_New()");
        return aniObject;
    }
    ani_ref buffer;
    env->Object_GetFieldByName_Ref(aniObject, "buffer", &buffer);
    void *bufData;
    size_t bufLength;
    retCode = env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &bufData, &bufLength);
    if (retCode != ANI_OK) {
        FI_HILOGE("Failed: env->ArrayBuffer_GetInfo()");
    }
    if (bufLength < values.size()) {
        FI_HILOGE("Buffer overflow prevented: required=%{public}zu, available=%{public}zu",
            values.size(), bufLength);
        return nullptr;
    }
    auto ret = memcpy_s(bufData, bufLength, values.data(), values.size());
    if (ret != 0) {
        FI_HILOGE("Failed: memcpy_s");
        return nullptr;
    }
    return aniObject;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
