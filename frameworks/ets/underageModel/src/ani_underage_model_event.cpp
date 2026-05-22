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
#include <nlohmann/json.hpp>

#include "ani_underage_model_event.h"
#include "devicestatus_define.h"
#include "ohos.multimodalAwareness.underageModel.UserClassification.ani.1.hpp"
#include "ohos.multimodalAwareness.underageModel.UserStatusData.ani.1.hpp"
#include "ohos.multimodalAwareness.underageModel.UserFacesData.ani.1.hpp"
#include "ohos.multimodalAwareness.underageModel.UserGesturesData.ani.1.hpp"
#include "ohos.multimodalAwareness.underageModel.UserFaceAngleData.ani.1.hpp"
#include "ohos.multimodalAwareness.underageModel.UserBlowData.ani.1.hpp"
#include "ohos.multimodalAwareness.underageModel.UserEmotionData.ani.1.hpp"
#include "ohos.multimodalAwareness.underageModel.ComfortReminderData.ani.1.hpp"
#include "user_status_napi_util.h"
#include "play_ability_status_data.h"
#include "user_blow_data.h"
#include "user_mood_data.h"

#undef LOG_TAG
#define LOG_TAG "AniUnderageModelEvent"

namespace OHOS {
namespace Msdp {
std::mutex g_mutex;

ani_vm* AniUnderageModelEvent::vm_ {nullptr};
constexpr int32_t MAX_ERROR_CODE = 1000;
constexpr int32_t UNSUPP_FRATURE_ERR = 0x3A1000D;
constexpr int32_t DEVICE_UNSUPPORT_ERR = 0x3A10028;
const std::string USER_STATUS_CLIENT_SO_PATH = "libuser_status_client.z.so";
const std::string_view REGISTER_LISTENER_FUNC_NAME = { "RegisterListener" };
const std::string_view SUBSCRIBE_CALLBACK_FUNC_NAME = { "SubscribeCallback" };
const std::string_view SUBSCRIBE_FUNC_NAME = { "Subscribe" };
const std::string_view SUBSCRIBE_WITH_DEVICEINFO_FUNC_NAME = { "SubscribeWithDeviceInfo" };
const std::string_view UNSUBSCRIBE_FUNC_NAME = { "Unsubscribe" };
constexpr std::string_view CONFIGPARAMS_FUNC_NAME = { "ConfigParams" };
constexpr std::string_view QUERYCAPABILITIES_FUNC_NAME = { "QueryCapabilities" };

void UnderageModelListener::OnUnderageModelListener(uint32_t eventType, int32_t result, float confidence) const
{
    FI_HILOGI("Enter");
    AniUnderageModelEvent::GetInstance()->OnEventChanged(eventType, result, confidence);
    FI_HILOGI("Exit");
}

void UserStatusDataCallback::OnReceiveData(int32_t callbackId,
    std::shared_ptr<UserStatusAwareness::UserStatusData> userStatusData)
{
    FI_HILOGI("Enter");
    AniUnderageModelEvent::GetInstance()->OnUserStatusData(callbackId, userStatusData);
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
    g_subscribeCallbackFunc = nullptr;
    g_subscribeFunc = nullptr;
    g_subscribeWithdeviceInfoFunc = nullptr;
    g_unsubscribeFunc = nullptr;
    g_configParamsFunc = nullptr;
    g_queryCapabilitiesFunc = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& iter : events_) {
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
        events_.clear();
    }
}

bool AniUnderageModelEvent::CheckEvents(int32_t eventType)
{
    FI_HILOGI("Enter");
    std::lock_guard<std::mutex> lock(mutex_);
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
        if (type == UNDERAGE_MODEL_TYPE_KID && iter == callbacks_.end()) {
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
            if (type == UNDERAGE_MODEL_TYPE_KID) {
                callbacks_.erase(iter);
            }
            return true;
        } else if (ret == DEVICE_UNSUPPORT_ERR || ret == UNSUPP_FRATURE_ERR) {
            FI_HILOGE("failed to unsubscribe");
            taihe::set_business_error(DEVICE_EXCEPTION, "The device does not support this API.");
            return false;
        }
        FI_HILOGE("Unsubscribe failed, ret: %{public}d", ret);
    }
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
            auto env = taihe::get_env();
            if (env == nullptr || ANI_OK != env->GlobalReference_Delete(onHandlerRef)) {
                FI_HILOGE("Global Reference delete fail");
                return false;
            }
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
    std::lock_guard<std::mutex> guard(mutex_);
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        FI_HILOGE("ani_env is nullptr");
        return false;
    }
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
        auto env = taihe::get_env();
        if (env == nullptr || ANI_OK != env->GlobalReference_Delete(item)) {
            FI_HILOGE("Global Reference delete fail");
            continue;
        }
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
    auto env = taihe::get_env();
    if (env == nullptr || env->GlobalReference_Create(callbackObj, &onHandlerRef) != ANI_OK) {
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
    if (ANI_OK != env->GlobalReference_Delete(onHandlerRef)) {
        FI_HILOGE("Global Reference delete fail");
        return false;
    }
    return true;
}

ani_object AniUnderageModelEvent::CreateAniUndefined(ani_env* env)
{
    ani_ref aniRef;
    if (env == nullptr || ANI_OK != env->GetUndefined(&aniRef)) {
        FI_HILOGE("null env");
        return nullptr;
    }
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

void AniUnderageModelEvent::OnUserStatusData(
    int32_t callbackId, std::shared_ptr<UserStatusAwareness::UserStatusData> userStatusData)
{
    uint32_t featureId = userStatusData->GetFeature();
    std::lock_guard<std::mutex> guard(mutex_);
    if (vm_ == nullptr) {
        FI_HILOGE("vm_ is nullptr");
        return;
    }
    auto typeIter = events_.find(featureId);
    if (typeIter == events_.end()) {
        FI_HILOGE("featureId: %{public}d not found", featureId);
        return;
    }
    ani_env *env = AttachAniEnv(vm_);
    if (env == nullptr) {
        FI_HILOGE("AttachAniEnv get env is nullptr");
        return;
    }
    auto baseData = CreateBaseData(userStatusData);
    for (auto handler : typeIter->second->onRefSets) {
        std::vector<ani_ref> args;
        ani_object userDataAni = CreateUserDataAni(env, featureId, userStatusData, baseData);
        args.push_back(static_cast<ani_ref>(userDataAni));
        ani_ref callResult;
        if (env->FunctionalObject_Call(static_cast<ani_fn_object>(handler), args.size(), args.data(), &callResult) !=
            ANI_OK) {
            HILOG_ERROR(LOG_CORE, "Excute CallBack failed.");
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

::ohos::multimodalAwareness::underageModel::UserStatusData AniUnderageModelEvent::CreateBaseData(
    std::shared_ptr<UserStatusAwareness::UserStatusData> userStatusData)
{
    uint32_t featureId = userStatusData->GetFeature();
    return ::ohos::multimodalAwareness::underageModel::UserStatusData{
        .feature = ::ohos::multimodalAwareness::underageModel::UserStatusFeature::from_value(featureId),
        .status = userStatusData->GetStatus(),
        .result = ::taihe::optional<int32_t>(std::in_place_t{}, userStatusData->GetResult()),
        .errCode = userStatusData->GetErrorCode(),
    };
}

ani_object AniUnderageModelEvent::CreateUserDataAni(
    ani_env *env, uint32_t featureId, std::shared_ptr<UserStatusAwareness::UserStatusData> userStatusData,
    const ::ohos::multimodalAwareness::underageModel::UserStatusData &baseData)
{
    switch (featureId) {
        case UserStatusAwareness::FEATURE_USER_PLAYING:
        case UserStatusAwareness::FEATURE_USER_FACE:
            return HandlePlayAbilityOrFaceData(env, baseData, userStatusData);
        case UserStatusAwareness::FEATURE_USER_PLAY_ABILITY_FATIGUE:
        case UserStatusAwareness::FEATURE_USER_GESTURE:
            return HandlePlayAbilityOrGestureData(env, baseData, userStatusData);
        case UserStatusAwareness::FEATURE_USER_FACE_ANGLE:
            return HandleFaceAngleData(env, baseData, userStatusData);
        case UserStatusAwareness::FEATURE_USER_BLOW:
            return HandleBlowData(env, baseData, userStatusData);
        case UserStatusAwareness::FEATURE_COMFORT_REMINDER:
            return HandleComfortReminderData(env, baseData, userStatusData);
        case UserStatusAwareness::FEATURE_USER_MOOD:
            return HandleMoodData(env, baseData, userStatusData);
        default:
            return taihe::into_ani<ohos::multimodalAwareness::underageModel::UserStatusData>(env, baseData);
    }
}

ani_object AniUnderageModelEvent::HandlePlayAbilityOrFaceData(ani_env *env,
    const ohos::multimodalAwareness::underageModel::UserStatusData &baseData,
    std::shared_ptr<UserStatusAwareness::UserStatusData> userStatusData)
{
    auto playAbilityData =
        std::static_pointer_cast<UserStatusAwareness::PlayAbilityStatusData>(userStatusData);
    auto aniPlayAbilityData = ohos::multimodalAwareness::underageModel::UserFacesData{
        .base = baseData,
        .visualAngle = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetVisualAngle().data(),
                playAbilityData->GetVisualAngle().size())),
        .angularVelocity = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetAngularVelocity().data(),
                playAbilityData->GetAngularVelocity().size())),
        .gravityAcceleration = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetGravityAcc().data(),
                playAbilityData->GetGravityAcc().size())),
        .linearAcceleration = taihe::optional<taihe::array<taihe::array<float>>>(std::in_place_t{},
            taihe::array<taihe::array<float>>(
                taihe::copy_data_t{}, playAbilityData->GetLinearAcc().data(), playAbilityData->GetLinearAcc().size())),
        .azimuth = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetGameRotationData().data(),
                playAbilityData->GetGameRotationData().size())),
        .faceNum = taihe::optional<int32_t>(std::in_place_t{}, playAbilityData->GetFaceNum()),
    };
    return taihe::into_ani<ohos::multimodalAwareness::underageModel::UserFacesData>(env, aniPlayAbilityData);
}

ani_object AniUnderageModelEvent::HandlePlayAbilityOrGestureData(ani_env *env,
    const ohos::multimodalAwareness::underageModel::UserStatusData &baseData,
    std::shared_ptr<UserStatusAwareness::UserStatusData> userStatusData)
{
    auto playAbilityData =
        std::static_pointer_cast<UserStatusAwareness::PlayAbilityStatusData>(userStatusData);
    auto aniPlayAbilityData = ohos::multimodalAwareness::underageModel::UserFacesData{
        .base = baseData,
        .visualAngle = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetVisualAngle().data(),
                playAbilityData->GetVisualAngle().size())),
        .angularVelocity = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetAngularVelocity().data(),
                playAbilityData->GetAngularVelocity().size())),
        .gravityAcceleration = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetGravityAcc().data(),
                playAbilityData->GetGravityAcc().size())),
        .linearAcceleration = taihe::optional<taihe::array<taihe::array<float>>>(std::in_place_t{},
            taihe::array<taihe::array<float>>(
                taihe::copy_data_t{}, playAbilityData->GetLinearAcc().data(), playAbilityData->GetLinearAcc().size())),
        .azimuth = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetGameRotationData().data(),
                playAbilityData->GetGameRotationData().size())),
        .faceNum = taihe::optional<int32_t>(std::in_place_t{}, playAbilityData->GetFaceNum()),
    };
    auto aniGesturesData = ohos::multimodalAwareness::underageModel::UserGesturesData{
        .base = aniPlayAbilityData,
        .isHandExist = playAbilityData->GetHandExistFlag(),
        .handPosition = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetHandPosition().data(),
                playAbilityData->GetHandPosition().size())),
        .motionGesture = taihe::optional<int32_t>(std::in_place_t{}, playAbilityData->GetMotionGesture()),
        .handType = taihe::optional<int32_t>(std::in_place_t{}, playAbilityData->GetHandType()),
        .directionAngle = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetDirectionAngle().data(),
                playAbilityData->GetDirectionAngle().size())),
        .gestureSpeed = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(taihe::copy_data_t{},
                playAbilityData->GetGestureSpeed().data(),
                playAbilityData->GetGestureSpeed().size())),
    };
    return taihe::into_ani<ohos::multimodalAwareness::underageModel::UserGesturesData>(env, aniGesturesData);
}

ani_object AniUnderageModelEvent::HandleFaceAngleData(ani_env *env,
    const ohos::multimodalAwareness::underageModel::UserStatusData &baseData,
    std::shared_ptr<UserStatusAwareness::UserStatusData> userStatusData)
{
    auto aniFaceAngleData = ohos::multimodalAwareness::underageModel::UserFaceAngleData{
        .base = baseData,
        .hpeNetworkId = userStatusData->GetHpeDeviceId(),
    };
    return taihe::into_ani<ohos::multimodalAwareness::underageModel::UserFaceAngleData>(env, aniFaceAngleData);
}

ani_object AniUnderageModelEvent::HandleBlowData(ani_env *env,
    const ohos::multimodalAwareness::underageModel::UserStatusData &baseData,
    std::shared_ptr<UserStatusAwareness::UserStatusData> userStatusData)
{
    auto userBlowData =
        std::static_pointer_cast<UserStatusAwareness::UserBlowData>(userStatusData);
    auto aniUserBlowData = ohos::multimodalAwareness::underageModel::UserBlowData{
        .base = baseData,
        .facePosition = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(
                taihe::copy_data_t{}, userBlowData->GetFacePosition().data(), userBlowData->GetFacePosition().size())),
        .strengthLevel = taihe::optional<int32_t>(std::in_place_t{}, userBlowData->GetStrengthLevel()),
        .blowDirection = taihe::optional<int32_t>(std::in_place_t{}, userBlowData->GetDirection()),
        .emotion = taihe::optional<int32_t>(std::in_place_t{}, userBlowData->GetEmotion()),
        .isGazeStatus = userBlowData->GetEyesOn(),
        .gravityAcceleration = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(
                taihe::copy_data_t{}, userBlowData->GetGravityAcc().data(), userBlowData->GetGravityAcc().size())),
    };
    return taihe::into_ani<ohos::multimodalAwareness::underageModel::UserBlowData>(env, aniUserBlowData);
}

ani_object AniUnderageModelEvent::HandleComfortReminderData(ani_env *env,
    const ohos::multimodalAwareness::underageModel::UserStatusData &baseData,
    std::shared_ptr<UserStatusAwareness::UserStatusData> userStatusData)
{
    auto comfortReminderData =
        std::static_pointer_cast<UserStatusAwareness::ComfortReminderData>(userStatusData);
    auto aniComfortReminderData = ohos::multimodalAwareness::underageModel::ComfortReminderData{
        .base = baseData,
        .fusionReminderData = ohos::multimodalAwareness::underageModel::ReminderLevel::from_value(
            comfortReminderData->GetFusionReminderData()),
        .swingReminderData = ohos::multimodalAwareness::underageModel::ReminderLevel::from_value(
            comfortReminderData->GetSwingReminderData()),
        .eventType = comfortReminderData->GetEventType(),
    };
    return taihe::into_ani<ohos::multimodalAwareness::underageModel::ComfortReminderData>(env, aniComfortReminderData);
}

ani_object AniUnderageModelEvent::HandleMoodData(ani_env *env,
    const ohos::multimodalAwareness::underageModel::UserStatusData &baseData,
    std::shared_ptr<UserStatusAwareness::UserStatusData> userStatusData)
{
    auto moodData = std::static_pointer_cast<UserStatusAwareness::UserMoodData>(userStatusData);
    auto aniMoodData = ohos::multimodalAwareness::underageModel::UserEmotionData{
        .base = baseData,
        .emotionRealTime = taihe::optional<int32_t>(std::in_place_t{}, moodData->GetRealTimeEmotion()),
        .confidence = taihe::optional<int32_t>(std::in_place_t{}, moodData->GetConfidence()),
        .isRealTime = moodData->GetIsRealTimeTag(),
        .emotionNonRealTime = taihe::optional<taihe::array<int32_t>>(std::in_place_t{},
            taihe::array<int32_t>(taihe::copy_data_t{},
                moodData->GetNonRealTimeEmotion().data(),
                moodData->GetNonRealTimeEmotion().size())),
        .gravityAcceleration = taihe::optional<taihe::array<float>>(std::in_place_t{},
            taihe::array<float>(
                taihe::copy_data_t{}, moodData->GetGravityAcc().data(), moodData->GetGravityAcc().size())),
    };
    return taihe::into_ani<ohos::multimodalAwareness::underageModel::UserEmotionData>(env, aniMoodData);
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

int32_t AniUnderageModelEvent::SubscribeUserStatus(
    int32_t featureId, std::vector<UserStatusAwareness::DeviceInfo> deviceInfoList)
{
    FI_HILOGI("SubscribeUserStatus enter, feature: %{public}u", featureId);
    if (g_userStatusHandle == nullptr && !LoadLibrary()) {
        FI_HILOGE("LoadLibrary failed");
        return DEVICE_EXCEPTION;
    }
    if (g_callback == nullptr) {
        auto userStatusDataCallback = std::make_shared<UserStatusDataCallback>();
        g_callback = [userStatusDataCallback](
                         int32_t callbackId, std::shared_ptr<UserStatusAwareness::UserStatusData> data) -> void {
            if (userStatusDataCallback == nullptr) {
                FI_HILOGE("userStatusDataCallback is nullptr");
                return;
            }
            userStatusDataCallback->OnReceiveData(callbackId, data);
        };
        if (g_subscribeCallbackFunc == nullptr) {
            g_subscribeCallbackFunc = reinterpret_cast<SubscribeCallbackFunc>(
                dlsym(g_userStatusHandle, SUBSCRIBE_CALLBACK_FUNC_NAME.data()));
            if (g_subscribeCallbackFunc == nullptr) {
                FI_HILOGE("find symbol failed, error: %{public}s", dlerror());
                return SERVICE_EXCEPTION;
            }
        }
        g_subscribeCallbackFunc(featureId, g_callback);
    }
    if (g_subscribeWithdeviceInfoFunc == nullptr) {
        g_subscribeWithdeviceInfoFunc = reinterpret_cast<SubscribeWithdeviceInfoFunc>(
            dlsym(g_userStatusHandle, SUBSCRIBE_WITH_DEVICEINFO_FUNC_NAME.data()));
        if (g_subscribeWithdeviceInfoFunc == nullptr) {
            FI_HILOGE("%{public}s find symbol failed, error: %{public}s",
                SUBSCRIBE_WITH_DEVICEINFO_FUNC_NAME.data(),
                dlerror());
            return SERVICE_EXCEPTION;
        }
    }
    return g_subscribeWithdeviceInfoFunc(featureId, deviceInfoList);
}

int32_t AniUnderageModelEvent::ConfigParams(uint32_t feature, std::string& configParams)
{
    FI_HILOGI("ConfigParams enter, feature: %{public}u", feature);
    if (g_userStatusHandle == nullptr && !LoadLibrary()) {
        FI_HILOGE("LoadLibrary failed");
        return DEVICE_EXCEPTION;
    }
    if (g_configParamsFunc == nullptr) {
        g_configParamsFunc = reinterpret_cast<ConfigParamsFunc>(
            dlsym(g_userStatusHandle, CONFIGPARAMS_FUNC_NAME.data()));
        if (g_configParamsFunc == nullptr) {
            FI_HILOGE("find symbol failed, error: %{public}s", dlerror());
            return SERVICE_EXCEPTION;
        }
    }
    std::map<std::string, std::vector<int32_t>> details;
    if (!ParseConfigParams(configParams, details)) {
        FI_HILOGE("ParseConfigParams failed");
        return PARAM_EXCEPTION;
    }
    return g_configParamsFunc(feature, details);
}

bool AniUnderageModelEvent::QueryCapabilities(std::vector<int32_t>& capabilities)
{
    FI_HILOGI("QueryCapabilities enter");
    if (g_userStatusHandle == nullptr && !LoadLibrary()) {
        taihe::set_business_error(DEVICE_EXCEPTION, "Device not support");
        return false;
    }
    if (g_queryCapabilitiesFunc == nullptr) {
        g_queryCapabilitiesFunc = reinterpret_cast<QueryCapabilitiesFunc>(
            dlsym(g_userStatusHandle, QUERYCAPABILITIES_FUNC_NAME.data()));
        if (g_queryCapabilitiesFunc == nullptr) {
            FI_HILOGE("find symbol failed, error: %{public}s", dlerror());
            return false;
        }
    }
    int32_t ret = g_queryCapabilitiesFunc(capabilities);
    if (ret != RET_OK) {
        FI_HILOGE("failed to query capabilities, ret: %{public}d", ret);
        return false;
    }
    return true;
}

bool AniUnderageModelEvent::ParseConfigParams(
    std::string const &params, std::map<std::string, std::vector<int32_t>> &configMap)
{
    nlohmann::json root = nlohmann::json::parse(params);
    if (!root.contains("params") || !root["params"].is_array()) {
        return false;
    }
    for (const auto& param : root["params"]) {
        if (!param.contains("description") || !param.contains("value")) {
            FI_HILOGE("Skipping invalid param object");
            return false;
        }
        if (!param["description"].is_string() || !param["value"].is_array()) {
            FI_HILOGE("Skipping invalid param object11111");
            return false;
        }
        std::string key = param["description"].get<std::string>();
        std::vector<int32_t> values;
        for (const auto& num : param["value"]) {
            if (num == nullptr || !num.is_number()) {
                return false;
            }
            values.push_back(static_cast<int32_t>(num.get<int>()));
        }
        configMap.emplace(key, values);
    }
    return true;
}
} // namespace Msdp
} // namespace OHOS
