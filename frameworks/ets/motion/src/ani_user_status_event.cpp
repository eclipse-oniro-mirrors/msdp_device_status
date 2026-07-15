/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ani_user_status_event.h"

#ifdef MOTION_ENABLE

#include <dlfcn.h>

#include <string_view>
#include <utility>

#include "ani_motion_event.h"
#include "ohos.multimodalAwareness.motion.HoverHandDetectionArea.ani.1.hpp"
#include "ohos.multimodalAwareness.motion.impl.hpp"
#include "ohos.multimodalAwareness.motion.proj.hpp"

namespace OHOS {
namespace Msdp {
constexpr uint32_t HOVER_HAND_FEATURE_ID = 14;
constexpr int32_t MAX_ERROR_CODE = 1000;
constexpr int32_t UNSUPP_FRATURE_ERR = 0x3A1000D;
constexpr int32_t DEVICE_UNSUPPORT_ERR = 0x3A10028;
constexpr int32_t NOT_SYSTEM_ERR = 0x3A10006;
constexpr int32_t DEVICE_NOT_SUPPORT = 0x3A10029;
constexpr int32_t POINTER_ACTION_DOWN = 2;
constexpr int32_t POINTER_ACTION_UP = 4;
const constexpr char *USER_STATUS_CLIENT_SO_PATH = "libuser_status_client.z.so";
const std::string_view SUBSCRIBE_CALLBACK_FUNC_NAME = { "SubscribeCallback" };
const std::string_view SUBSCRIBE_HOVER_HAND_FUNC_NAME = { "SubscribeHoverHandEvent" };
const std::string_view UNSUBSCRIBE_FUNC_NAME = { "UnsubscribeHoverHandEvent" };
ani_vm *AniUserStatusEvent::vm_ = nullptr;
void AniUserStatusDataCallback::OnReceiveData(std::shared_ptr<UserStatusData> userStatusData)
{
    AniUserStatusEvent::GetInstance().OnUserStatusData(std::move(userStatusData));
}

AniUserStatusEvent &AniUserStatusEvent::GetInstance()
{
    static AniUserStatusEvent instance;
    return instance;
}

AniUserStatusEvent::~AniUserStatusEvent()
{
    if (userStatusHandle_ != nullptr) {
        dlclose(userStatusHandle_);
        userStatusHandle_ = nullptr;
    }
    subscribeCallbackFunc_ = nullptr;
    subscribeHoverHandFunc_ = nullptr;
    unsubscribeFunc_ = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto &iter : callbacks_) {
            if (iter.second == nullptr) {
                continue;
            }
            for (auto item : iter.second->onRefSets) {
                auto env = taihe::get_env();
                if (env == nullptr || ANI_OK != env->GlobalReference_Delete(item)) {
                    FI_HILOGE("Global Reference delete fail");
                }
            }
            iter.second->onRefSets.clear();
            iter.second = nullptr;
        }
        callbacks_.clear();
    }
}

bool AniUserStatusEvent::SubscribeHoverHandEvent(const HoverHandDetectionArea &area, uint32_t duration, uintptr_t opq)
{
    FI_HILOGI("enter");
    if (userStatusHandle_ == nullptr && !LoadLibrary()) {
        FI_HILOGE("LoadLibrary failed");
        return false;
    }
    if (!InitializeCallback()) {
        FI_HILOGE("InitializeCallback failed");
        return false;
    }
    if (!SubscribeToUserStatus(area, duration)) {
        FI_HILOGE("SubscribeToUserStatus failed");
        return false;
    }
    if (!AddCallback(HOVER_HAND_FEATURE_ID, opq)) {
        FI_HILOGE("AddCallback failed");
        taihe::set_business_error(SUBSCRIBE_EXCEPTION, "AddCallback failed");
        return false;
    }
    return true;
}

bool AniUserStatusEvent::UnsubscribeHoverHandEvent(uintptr_t opq)
{
    if (opq == 0) {
        if (!RemoveAllCallback(HOVER_HAND_FEATURE_ID)) {
            FI_HILOGE("RemoveAllCallback failed");
            taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "RemoveAllCallback failed");
            return false;
        }
    } else {
        if (!RemoveCallback(HOVER_HAND_FEATURE_ID, opq)) {
            FI_HILOGE("RemoveCallback failed");
            taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "RemoveCallback failed");
            return false;
        }
    }

    if (IsFeatureEventsEmpty(HOVER_HAND_FEATURE_ID)) {
        if (!UnsubscribeFromUserStatus()) {
            FI_HILOGE("UnsubscribeFromUserStatus failed");
            return false;
        }
    } else {
        FI_HILOGD("no need to call unsubscribe yet");
    }

    if (IsEmptyEvents()) {
        ResetCallback();
    }
    return true;
}

void AniUserStatusEvent::OnUserStatusData(std::shared_ptr<UserStatusData> userStatusData)
{
    if (userStatusData == nullptr) {
        FI_HILOGE("userStatusData is nullptr");
        return;
    }
    uint32_t featureId = userStatusData->GetFeature();
    HoverHandAction action = ConvertToHoverHandAction(userStatusData->GetPointerAction());
    if (action == HoverHandAction::INVALID) {
        return;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    if (vm_ == nullptr) {
        FI_HILOGE("vm_ is nullptr");
        return;
    }
    auto typeIter = callbacks_.find(featureId);
    if (typeIter == callbacks_.end() || typeIter->second == nullptr) {
        FI_HILOGE("featureId: %{public}d not found or callback is nullptr", featureId);
        return;
    }
    ani_env *env = AttachAniEnv(vm_);
    if (env == nullptr) {
        FI_HILOGE("AttachAniEnv get env is nullptr");
        return;
    }
    for (auto handler : typeIter->second->onRefSets) {
        std::vector<ani_ref> args;
        ani_object actionAni = CreateHoverHandActionAni(env, action);
        if (actionAni == nullptr) {
            HILOG_ERROR(LOG_CORE, "Failed to create actionAni object.");
            continue;
        }
        args.push_back(static_cast<ani_ref>(actionAni));
        ani_ref callResult;
        if (env->FunctionalObject_Call(static_cast<ani_fn_object>(handler), args.size(), args.data(), &callResult) !=
            ANI_OK) {
            HILOG_ERROR(LOG_CORE, "Execute CallBack failed.");
            if (ANI_OK != vm_->DetachCurrentThread()) {
                HILOG_ERROR(LOG_CORE, "detach current thread.");
            }
            return;
        }
    }
    if (ANI_OK != vm_->DetachCurrentThread()) {
        HILOG_ERROR(LOG_CORE, "detach current thread.");
    }
}

bool AniUserStatusEvent::LoadLibrary()
{
    if (userStatusHandle_ == nullptr) {
        userStatusHandle_ = dlopen(USER_STATUS_CLIENT_SO_PATH, RTLD_LAZY);
        if (userStatusHandle_ == nullptr) {
            FI_HILOGE("Load failed: %{private}s, error after: %{public}s", USER_STATUS_CLIENT_SO_PATH, dlerror());
            taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
            return false;
        }
    }
    return true;
}

bool AniUserStatusEvent::InitializeCallback()
{
    if (callback_ == nullptr) {
        auto userStatusDataCallback = std::make_shared<AniUserStatusDataCallback>();
        callback_ = [userStatusDataCallback](int32_t callbackId, std::shared_ptr<UserStatusData> data) -> void {
            if (userStatusDataCallback == nullptr) {
                FI_HILOGE("userStatusDataCallback is nullptr, callbackId: %{public}d", callbackId);
                return;
            }
            userStatusDataCallback->OnReceiveData(std::move(data));
        };
        if (subscribeCallbackFunc_ == nullptr) {
            subscribeCallbackFunc_ =
                reinterpret_cast<SubscribeCallbackFunc>(dlsym(userStatusHandle_, SUBSCRIBE_CALLBACK_FUNC_NAME.data()));
            if (subscribeCallbackFunc_ == nullptr) {
                FI_HILOGE("find symbol failed, error: %{public}s", dlerror());
                taihe::set_business_error(SERVICE_EXCEPTION, "Find symbol failed");
                return false;
            }
        }
        int32_t ret = std::abs(subscribeCallbackFunc_(HOVER_HAND_FEATURE_ID, callback_));
        if (ret < MAX_ERROR_CODE) {
            FI_HILOGE("Subscribe Callback failed, ret: %{public}d", ret);
            taihe::set_business_error(SUBSCRIBE_EXCEPTION, "SubscribeCallback failed");
            callback_ = nullptr;
            return false;
        } else if (ret == NOT_SYSTEM_ERR) {
            FI_HILOGE("Not system app, ret:%{public}d", ret);
            taihe::set_business_error(NO_SYSTEM_API, "Not system app");
            callback_ = nullptr;
            return false;
        }
    }
    return true;
}

bool AniUserStatusEvent::SubscribeToUserStatus(const HoverHandDetectionArea &area, uint32_t duration)
{
    if (subscribeHoverHandFunc_ == nullptr) {
        subscribeHoverHandFunc_ =
            reinterpret_cast<SubscribeHoverHandFunc>(dlsym(userStatusHandle_, SUBSCRIBE_HOVER_HAND_FUNC_NAME.data()));
        if (subscribeHoverHandFunc_ == nullptr) {
            FI_HILOGE(
                "%{public}s find symbol failed, error: %{public}s", SUBSCRIBE_HOVER_HAND_FUNC_NAME.data(), dlerror());
            taihe::set_business_error(SERVICE_EXCEPTION, "Find symbol failed");
            return false;
        }
    }
    int32_t ret = subscribeHoverHandFunc_(HOVER_HAND_FEATURE_ID, area, duration);
    if (ret == RET_OK) {
        return true;
    } else if (ret == DEVICE_UNSUPPORT_ERR || ret == UNSUPP_FRATURE_ERR || ret == DEVICE_NOT_SUPPORT) {
        FI_HILOGE("failed to subscribe: %{public}d", ret);
        taihe::set_business_error(DEVICE_EXCEPTION, "The device does not support this API.");
        return false;
    } else if (ret == NOT_SYSTEM_ERR) {
        FI_HILOGE("Not system app, ret:%{public}d", ret);
        taihe::set_business_error(NO_SYSTEM_API, "Not system app");
        return false;
    }
    FI_HILOGE("failed to subscribe: %{public}d", ret);
    taihe::set_business_error(SUBSCRIBE_EXCEPTION, "Subscribe failed");
    return false;
}

bool AniUserStatusEvent::UnsubscribeFromUserStatus()
{
    if (unsubscribeFunc_ == nullptr) {
        unsubscribeFunc_ = reinterpret_cast<UnsubscribeFunc>(dlsym(userStatusHandle_, UNSUBSCRIBE_FUNC_NAME.data()));
        if (unsubscribeFunc_ == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", UNSUBSCRIBE_FUNC_NAME.data(), dlerror());
            taihe::set_business_error(SERVICE_EXCEPTION, "Find symbol failed");
            return false;
        }
    }
    auto ret = unsubscribeFunc_(HOVER_HAND_FEATURE_ID);
    if (ret == RET_OK) {
        FI_HILOGI("success");
        return true;
    } else if (ret == DEVICE_UNSUPPORT_ERR || ret == UNSUPP_FRATURE_ERR || ret == DEVICE_NOT_SUPPORT) {
        FI_HILOGE("failed to unsubscribe");
        taihe::set_business_error(DEVICE_EXCEPTION, "The device does not support this API.");
        return false;
    } else if (ret == NOT_SYSTEM_ERR) {
        FI_HILOGE("Not system app, ret:%{public}d", ret);
        taihe::set_business_error(NO_SYSTEM_API, "Not system app");
        return false;
    }
    FI_HILOGE("Unsubscribe failed, ret: %{public}d", ret);
    taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
    return false;
}

bool AniUserStatusEvent::AddCallback(uint32_t eventType, uintptr_t opq)
{
    std::lock_guard<std::mutex> guard(mutex_);
    FI_HILOGI("event: %{public}u", eventType);
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        FI_HILOGE("ani_env is nullptr");
        return false;
    }
    vm_ = GetAniVm(env);
    ani_ref onHandlerRef = nullptr;
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    if (ANI_OK != env->GlobalReference_Create(callbackObj, &onHandlerRef)) {
        FI_HILOGE("GlobalReference_Create failed");
        return false;
    }
    auto iter = callbacks_.find(eventType);
    if (iter == callbacks_.end()) {
        FI_HILOGD("found event: %{public}u", eventType);
        auto listener = std::make_shared<JsUserStatusEventCallback>();
        std::set<ani_ref> onRefSets;
        listener->onRefSets = onRefSets;

        auto ret = listener->onRefSets.insert(onHandlerRef);
        if (!ret.second) {
            FI_HILOGE("Failed to insert refs");
            return false;
        }
        callbacks_.insert(std::make_pair(eventType, listener));
        FI_HILOGD("Insert finish");
        return true;
    }
    FI_HILOGD("found event: %{public}u", eventType);
    if (iter->second == nullptr || iter->second->onRefSets.empty()) {
        FI_HILOGE("listener is nullptr or onRefSets empty");
        callbacks_.erase(iter);
        return false;
    }
    FI_HILOGD("Check type: %{public}u same handle", eventType);
    if (!InsertRef(iter->second, onHandlerRef)) {
        FI_HILOGE("Failed to insert ref");
        callbacks_.erase(iter);
        return false;
    }
    return true;
}

bool AniUserStatusEvent::RemoveCallback(uint32_t eventType, uintptr_t opq)
{
    std::lock_guard<std::mutex> guard(mutex_);
    FI_HILOGI("event: %{public}u", eventType);
    auto iter = callbacks_.find(eventType);
    if (iter == callbacks_.end()) {
        FI_HILOGE("EventType: %{public}u not found", eventType);
        return false;
    }
    if (iter->second == nullptr || iter->second->onRefSets.empty()) {
        FI_HILOGE("listener is nullptr or onRefSets is empty");
        return false;
    }
    ani_ref onHandlerRef = nullptr;
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    auto env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &onHandlerRef)) {
        FI_HILOGE("GlobalReference_Create failed");
        return false;
    }
    bool isCallbackRegistered = false;
    auto &refSet = iter->second->onRefSets;
    for (auto it = refSet.begin(); it != refSet.end();) {
        ani_boolean isEqual = false;
        auto isDuplicate = (env->Reference_StrictEquals(onHandlerRef, *it, &isEqual) == ANI_OK) && isEqual;
        if (isDuplicate) {
            isCallbackRegistered = true;
            it = refSet.erase(it);
            FI_HILOGD("callback already remove");
        } else {
            ++it;
        }
    }
    if (iter->second->onRefSets.empty()) {
        callbacks_.erase(eventType);
    }
    if (ANI_OK != env->GlobalReference_Delete(onHandlerRef)) {
        FI_HILOGE("Global Reference delete fail");
        return false;
    }
    return isCallbackRegistered;
}

bool AniUserStatusEvent::RemoveAllCallback(uint32_t eventType)
{
    std::lock_guard<std::mutex> guard(mutex_);
    FI_HILOGI("event: %{public}u", eventType);
    auto iter = callbacks_.find(eventType);
    if (iter == callbacks_.end()) {
        FI_HILOGE("EventType: %{public}u not found", eventType);
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
    for (auto item : iter->second->onRefSets) {
        auto env = taihe::get_env();
        if (env == nullptr || ANI_OK != env->GlobalReference_Delete(item)) {
            FI_HILOGE("Global Reference delete fail");
            continue;
        }
    }
    iter->second->onRefSets.clear();
    callbacks_.erase(iter);
    return true;
}

bool AniUserStatusEvent::IsEmptyEvents()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return callbacks_.empty();
}

bool AniUserStatusEvent::IsFeatureEventsEmpty(uint32_t featureId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = callbacks_.find(featureId);
    if (iter == callbacks_.end()) {
        return true;
    }
    if (iter->second == nullptr || iter->second->onRefSets.empty()) {
        callbacks_.erase(iter);
        return true;
    }
    return false;
}

void AniUserStatusEvent::ResetCallback()
{
    callback_ = nullptr;
}

bool AniUserStatusEvent::InsertRef(std::shared_ptr<JsUserStatusEventCallback> callback, ani_ref onHandlerRef)
{
    if (callback == nullptr) {
        FI_HILOGE("listener is nullptr");
        return false;
    }
    for (const auto &item : callback->onRefSets) {
        ani_boolean isEqual = false;
        auto env = taihe::get_env();
        if (env == nullptr) {
            FI_HILOGE("env is nullptr");
            return false;
        }
        auto isDuplicate = (env->Reference_StrictEquals(onHandlerRef, item, &isEqual) == ANI_OK) && isEqual;
        if (isDuplicate) {
            if (env->GlobalReference_Delete(onHandlerRef) != ANI_OK) {
                FI_HILOGE("Global Reference delete fail");
                return false;
            }
            FI_HILOGD("callback already registered");
            return true;
        }
    }
    FI_HILOGD("Insert new ref");
    auto ret = callback->onRefSets.insert(onHandlerRef);
    if (!ret.second) {
        FI_HILOGE("Failed to insert");
        return false;
    }
    FI_HILOGD("ref size %{public}zu", callback->onRefSets.size());
    return true;
}

ani_vm *AniUserStatusEvent::GetAniVm(ani_env *env)
{
    if (env == nullptr) {
        FI_HILOGE("null env");
        return nullptr;
    }
    ani_vm *vm = nullptr;
    if (env->GetVM(&vm) != ANI_OK) {
        FI_HILOGE("GetVM failed");
        return nullptr;
    }
    return vm;
}

ani_env *AniUserStatusEvent::AttachAniEnv(ani_vm *vm)
{
    if (vm == nullptr) {
        FI_HILOGE("null vm");
        return nullptr;
    }
    ani_env *workerEnv = nullptr;
    ani_options aniArgs{ 0, nullptr };
    if (vm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &workerEnv) != ANI_OK) {
        FI_HILOGE("Attach Env failed");
        return nullptr;
    }
    return workerEnv;
}

ani_object AniUserStatusEvent::CreateHoverHandActionAni(ani_env *env, HoverHandAction action)
{
    if (env == nullptr) {
        FI_HILOGE("env is nullptr");
        return nullptr;
    }
    ani_enum enumType;
    ani_enum_item enumItem = nullptr;
    ani_status ret = env->FindEnum("@ohos.multimodalAwareness.motion.motion.HoverHandAction", &enumType);
    if (ret != ANI_OK) {
        FI_HILOGE("[ANI] HoverHandAction not found");
        return enumItem;
    }
    ret = env->Enum_GetEnumItemByIndex(enumType, ani_int(static_cast<int32_t>(action)), &enumItem);
    if (ret != ANI_OK) {
        FI_HILOGE("env Enum_GetEnumItemByIndex failed");
        return enumItem;
    }
    return enumItem;
}

HoverHandAction AniUserStatusEvent::ConvertToHoverHandAction(int32_t pointerAction)
{
    if (pointerAction == POINTER_ACTION_DOWN) {
        return HoverHandAction::DOWN;
    } else if (pointerAction == POINTER_ACTION_UP) {
        return HoverHandAction::UP;
    }
    return HoverHandAction::INVALID;
}
} // namespace Msdp
} // namespace OHOS

#endif // MOTION_ENABLE