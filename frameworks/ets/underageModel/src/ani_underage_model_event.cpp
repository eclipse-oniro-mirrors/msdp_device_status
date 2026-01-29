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
#include <dlfcn.h>

#include "ani_underage_model_event.h"
#include "devicestatus_define.h"
#include "ohos.multimodalAwareness.underageModel.UserClassification.ani.1.hpp"

#undef LOG_TAG
#define LOG_TAG "AniUnderageModelEvent"

namespace OHOS {
namespace Msdp {
std::mutex g_mutex;

ani_env* AniUnderageModelEvent::env_ {nullptr};
ani_vm* AniUnderageModelEvent::vm_ {nullptr};
constexpr int32_t MAX_ERROR_CODE = 1000;
constexpr int32_t UNSUPP_FRATURE_ERR = 0x3A1000D;
constexpr int32_t DEVICE_UNSUPPORT_ERR = 0x3A10028;
const std::string USER_STATUS_CLIENT_SO_PATH = "libuser_status_client.z.so";
const std::string_view REGISTER_LISTENER_FUNC_NAME = { "RegisterListener" };
const std::string_view SUBSCRIBE_FUNC_NAME = { "Subscribe" };
const std::string_view UNSUBSCRIBE_FUNC_NAME = { "Unsubscribe" };

void UnderageModelListener::OnUnderageModelListener(uint32_t eventType, int32_t result, float confidence) const
{
    FI_HILOGI("Enter");
    AniUnderageModelEvent::GetInstance()->OnEventChanged(eventType, result, confidence);
    FI_HILOGI("Exit");
}

bool AniUnderageModelEvent::LoadLibrary()
{
    if (AniUnderageModelEvent::GetInstance()->g_userStatusHandle == nullptr) {
        AniUnderageModelEvent::GetInstance()->g_userStatusHandle =
            dlopen(USER_STATUS_CLIENT_SO_PATH.c_str(), RTLD_LAZY);
        if (AniUnderageModelEvent::GetInstance()->g_userStatusHandle == nullptr) {
            FI_HILOGE("Load failed, path is %{private}s, error after: %{public}s",
                USER_STATUS_CLIENT_SO_PATH.c_str(), dlerror());
            return false;
        }
    }
    return true;
}

std::shared_ptr<AniUnderageModelEvent> AniUnderageModelEvent::GetInstance()
{
    static std::once_flag flag;
    static std::shared_ptr<AniUnderageModelEvent> instance_;
    std::call_once(flag, []() {
        instance_ = std::make_shared<AniUnderageModelEvent>();
    });
    return instance_;
}

AniUnderageModelEvent::~AniUnderageModelEvent()
{
    if (g_userStatusHandle != nullptr) {
        dlclose(g_userStatusHandle);
        g_userStatusHandle = nullptr;
    }
    g_registerListenerFunc = nullptr;
    g_subscribeFunc = nullptr;
    g_unsubscribeFunc = nullptr;
}

bool AniUnderageModelEvent::CheckEvents(int32_t eventType)
{
    FI_HILOGI("Enter");
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

bool AniUnderageModelEvent::SubscribeCallback(int32_t type)
{
    auto iter = callbacks_.find(type);
    if (iter != callbacks_.end()) {
        return true;
    }
    if (g_userStatusHandle == nullptr && !LoadLibrary()) {
        taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
        return false;
    }
    if (AniUnderageModelEvent::GetInstance()->g_registerListenerFunc == nullptr) {
        AniUnderageModelEvent::GetInstance()->g_registerListenerFunc = reinterpret_cast<RegisterListenerFunc>(
            dlsym(AniUnderageModelEvent::GetInstance()->g_userStatusHandle, REGISTER_LISTENER_FUNC_NAME.data()));
        if (AniUnderageModelEvent::GetInstance()->g_registerListenerFunc == nullptr) {
            FI_HILOGE("RegisterListener find symbol failed, error: %{public}s", dlerror());
            taihe::set_business_error(SUBSCRIBE_EXCEPTION, "Find symbol failed");
            return false;
        }
    }
    auto listener = std::make_shared<UnderageModelListener>();
    int32_t ret = std::abs(AniUnderageModelEvent::GetInstance()->g_registerListenerFunc(type, listener));
    if (ret < MAX_ERROR_CODE) {
        FI_HILOGE("RegisterListener failed, ret: %{public}d", ret);
        taihe::set_business_error(SUBSCRIBE_EXCEPTION, "RegisterListener failed");
        return false;
    }
    FI_HILOGI("RegisterListener failed, ret: %{public}d", ret);
    if (!Subscribe(type)) {
        FI_HILOGE("Subscribe type failed");
        return false;
    }
    AniUnderageModelEvent::GetInstance()->callbacks_.insert(std::make_pair(type, listener));
    return true;
}

bool AniUnderageModelEvent::Subscribe(uint32_t type)
{
    if (g_subscribeFunc == nullptr) {
        g_subscribeFunc = reinterpret_cast<SubscribeFunc>(
            dlsym(g_userStatusHandle, SUBSCRIBE_FUNC_NAME.data()));
        if (g_subscribeFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s", SUBSCRIBE_FUNC_NAME.data(), dlerror());
            taihe::set_business_error(SUBSCRIBE_EXCEPTION, "Find symbol failed");
            return false;
        }
    }
    int32_t ret = g_subscribeFunc(type);
    if (ret == RET_OK) {
        return true;
    } else if (ret == DEVICE_UNSUPPORT_ERR || ret == UNSUPP_FRATURE_ERR) {
        FI_HILOGE("failed to subscribe: %{public}d", ret);
        taihe::set_business_error(DEVICE_EXCEPTION, "The device does not support this API.");
        return false;
    }
    FI_HILOGE("failed to subscribe: %{public}d", ret);
    taihe::set_business_error(SUBSCRIBE_EXCEPTION, "Subscribe failed");
    return false;
}

bool AniUnderageModelEvent::UnSubscribeCallback(int32_t type)
{
    if (CheckEvents(type)) {
        auto iter = callbacks_.find(type);
        if (iter == callbacks_.end()) {
            FI_HILOGE("faild to find callback");
            taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
            return false;
        }
        if (g_unsubscribeFunc == nullptr) {
            g_unsubscribeFunc = reinterpret_cast<UnsubscribeFunc>(
                dlsym(g_userStatusHandle, UNSUBSCRIBE_FUNC_NAME.data()));
            if (g_unsubscribeFunc == nullptr) {
                FI_HILOGE("%{public}s find symbol failed, error: %{public}s", UNSUBSCRIBE_FUNC_NAME.data(), dlerror());
                taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "Find symbol failed");
                return false;
            }
        }
        auto ret = g_unsubscribeFunc(type);
        if (ret == RET_OK) {
            callbacks_.erase(iter);
            return true;
        } else if (ret == DEVICE_UNSUPPORT_ERR || ret == UNSUPP_FRATURE_ERR) {
            FI_HILOGE("failed to unsubscribe");
            taihe::set_business_error(DEVICE_EXCEPTION, "The device does not support this API.");
            return false;
        }
        FI_HILOGE("Unsubscribe failed, ret: %{public}d", ret);
    }
    taihe::set_business_error(UNSUBSCRIBE_EXCEPTION, "Unsubscribe failed");
    return false;
}

bool AniUnderageModelEvent::InsertRef(std::shared_ptr<UnderageModelEventListener> listener, ani_ref onHandlerRef)
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

bool AniUnderageModelEvent::AddCallback(int32_t eventType, uintptr_t opq)
{
    FI_HILOGI("Enter");
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        FI_HILOGE("ani_env is nullptr");
        return false;
    }
    env_ = env;
    vm_ = GetAniVm(env);
    ani_ref onHandlerRef = nullptr;
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    if (env->GlobalReference_Create(callbackObj, &onHandlerRef) != ANI_OK) {
        FI_HILOGE("GlobalReference_Create failed");
        return false;
    }
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGD("found event: %{public}d", eventType);
        auto listener = std::make_shared<UnderageModelEventListener>();
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

bool AniUnderageModelEvent::RemoveAllCallback(int32_t eventType)
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
    for (auto item : iter->second->onRefSets) {
        taihe::get_env()->GlobalReference_Delete(item);
    }
    iter->second->onRefSets.clear();
    events_.erase(iter);
    return true;
}

bool AniUnderageModelEvent::RemoveCallback(int32_t eventType, uintptr_t opq)
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

ani_object AniUnderageModelEvent::CreateAniUndefined(ani_env* env)
{
    ani_ref aniRef;
    if (env == nullptr) {
        FI_HILOGE("null env");
        return nullptr;
    }
    env->GetUndefined(&aniRef);
    return static_cast<ani_object>(aniRef);
}

ani_object AniUnderageModelEvent::CreateAniUserClassification(ani_env *env, int32_t result, float confidence)
{
    if (env == nullptr) {
        FI_HILOGE("env is nullptr");
        return CreateAniUndefined(env);
    }
    auto ageGroupTaihe = ::taihe::optional<::ohos::multimodalAwareness::underageModel::UserAgeGroup>::make(
        ::ohos::multimodalAwareness::underageModel::UserAgeGroup::from_value(result));
    ::taihe::optional<float> confidenceTaihe;
    confidenceTaihe.emplace(confidence);
    auto userClassification = ::ohos::multimodalAwareness::underageModel::UserClassification {
        std::move(ageGroupTaihe),
        std::move(confidenceTaihe),
    };
    return ::taihe::into_ani<::ohos::multimodalAwareness::underageModel::UserClassification>(
        env, userClassification);
}

void AniUnderageModelEvent::OnEventChanged(uint32_t eventType, int32_t result, float confidence)
{
    FI_HILOGI("eventType: %{public}d", eventType);
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
        ani_object confidenceAni = CreateAniUserClassification(env, result, confidence);
        args.push_back(static_cast<ani_ref>(confidenceAni));
        ani_ref callResult;
        if (env->FunctionalObject_Call(static_cast<ani_fn_object>(handler), args.size(), args.data(),
            &callResult) != ANI_OK) {
            HILOG_ERROR(LOG_CORE, "Excute CallBack failed.");
            vm_->DetachCurrentThread();
            return;
        }
    }
    vm_->DetachCurrentThread();
}

ani_vm* AniUnderageModelEvent::GetAniVm(ani_env* env)
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

ani_env* AniUnderageModelEvent::GetAniEnv(ani_vm* vm)
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

ani_env* AniUnderageModelEvent::AttachAniEnv(ani_vm* vm)
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
} // namespace Msdp
} // namespace OHOS