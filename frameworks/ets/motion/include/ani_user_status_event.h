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

#ifndef ANI_USER_STATUS_EVENT_H
#define ANI_USER_STATUS_EVENT_H

#ifdef MOTION_ENABLE

#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "ani.h"
#include "ani_error_utils.h"
#include "device_info.h"
#include "fi_log.h"
#include "hover_hand_data.h"
#include "taihe/runtime.hpp"
#include "user_status_data.h"

namespace OHOS {
namespace Msdp {
using UserStatusData = UserStatusAwareness::UserStatusData;
using HoverHandAction = UserStatusAwareness::HoverHandAction;
using HoverHandDetectionArea = UserStatusAwareness::HoverHandDetectionArea;
using HoverHandOptions = UserStatusAwareness::HoverHandOptions;

typedef int32_t (*SubscribeCallbackFunc)(uint32_t feature, UserStatusAwareness::UserStatusDataCallbackFunc &callback);
typedef int32_t (*SubscribeHoverHandFunc)(uint32_t feature, const HoverHandDetectionArea &area, uint32_t duration);
typedef int32_t (*UnsubscribeFunc)(uint32_t feature);

class AniUserStatusDataCallback {
public:
    AniUserStatusDataCallback()
    {
    }
    ~AniUserStatusDataCallback(){};
    void OnReceiveData(std::shared_ptr<UserStatusData> userStatusData);
};

struct JsUserStatusEventCallback {
    std::set<ani_ref> onRefSets;
};

class AniUserStatusEvent {
public:
    static AniUserStatusEvent &GetInstance();
    AniUserStatusEvent() = default;
    ~AniUserStatusEvent();
    bool SubscribeHoverHandEvent(const HoverHandDetectionArea &area, uint32_t duration, uintptr_t opq);
    bool UnsubscribeHoverHandEvent(uintptr_t opq);
    void OnUserStatusData(std::shared_ptr<UserStatusData> userStatusData);

private:
    // user status
    bool LoadLibrary();
    bool InitializeCallback();
    bool SubscribeToUserStatus(const HoverHandDetectionArea &area, uint32_t duration);
    bool UnsubscribeFromUserStatus();

    // callback management
    bool AddCallback(uint32_t eventType, uintptr_t opq);
    bool RemoveAllCallback(uint32_t eventType);
    bool RemoveCallback(uint32_t eventType, uintptr_t opq);
    bool IsEmptyEvents();
    bool IsFeatureEventsEmpty(uint32_t featureId);
    void ResetCallback();

    // util
    static bool InsertRef(std::shared_ptr<JsUserStatusEventCallback> callback, ani_ref onHandlerRef);
    static ani_vm *GetAniVm(ani_env *env);
    static ani_env *AttachAniEnv(ani_vm *vm);
    ani_object CreateHoverHandActionAni(ani_env *env, HoverHandAction action);
    static HoverHandAction ConvertToHoverHandAction(int32_t pointerAction);

private:
    static ani_vm *vm_;
    void *userStatusHandle_{ nullptr };

    // js callbacks
    std::mutex mutex_;
    std::map<uint32_t, std::shared_ptr<JsUserStatusEventCallback>> callbacks_;

    // callbacks to userStatus
    UserStatusAwareness::UserStatusDataCallbackFunc callback_{ nullptr };
    SubscribeCallbackFunc subscribeCallbackFunc_{ nullptr };
    SubscribeHoverHandFunc subscribeHoverHandFunc_{ nullptr };
    UnsubscribeFunc unsubscribeFunc_{ nullptr };
};
} // namespace Msdp
} // namespace OHOS

#endif // MOTION_ENABLE

#endif // ANI_USER_STATUS_EVENT_H
