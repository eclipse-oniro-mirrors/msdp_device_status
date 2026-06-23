/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef USER_STATUS_EVENT_NAPI_H
#define USER_STATUS_EVENT_NAPI_H

#include <map>
#include <memory>
#include <set>

#include "hover_hand_data.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "user_status_data.h"
#include "hover_hand_data.h"

namespace OHOS {
namespace Msdp {
using UserStatusData = UserStatusAwareness::UserStatusData;
using HoverHandAction = UserStatusAwareness::HoverHandAction;
using HoverHandDetectionArea = UserStatusAwareness::HoverHandDetectionArea;
using HoverHandEventData = UserStatusAwareness::HoverHandEventData;
using HoverHandOptions = UserStatusAwareness::HoverHandOptions;

typedef int32_t (*SubscribeCallbackFunc)(uint32_t feature, UserStatusAwareness::UserStatusDataCallbackFunc &callback);
typedef int32_t (*SubscribeHoverHandFunc)(uint32_t feature, const HoverHandDetectionArea &area, uint32_t duration);
typedef int32_t (*UnsubscribeFunc)(uint32_t feature);

struct JsHoverEventData {
    static napi_value Write(napi_env env, const HoverHandEventData &eventData);
};

struct JsHoverHandDetectionArea {
    static bool Read(napi_env env, napi_value object, HoverHandDetectionArea &area);
};

class UserStatusDataCallback {
public:
    explicit UserStatusDataCallback(napi_env env) : env_(env)
    {
    }
    ~UserStatusDataCallback(){};
    void OnReceiveData(int32_t callbackId, std::shared_ptr<UserStatusData> userStatusData);

private:
    napi_env env_;
};

struct JsUserStatusEventCallback {
    std::set<napi_ref> onRefSets;
};

class UserStatusEventNapi {
public:
    UserStatusEventNapi(napi_env env, napi_value thisVar);
    ~UserStatusEventNapi();

    static napi_value SubscribeHoverHandEvent(napi_env env, napi_callback_info info);
    static napi_value UnsubscribeHoverHandEvent(napi_env env, napi_callback_info info);
    static napi_value GetHoverHandAction(napi_env env);
    void OnReceiveData(int32_t callbackId, std::shared_ptr<UserStatusData> userStatusData);

public:
    bool AddCallback(uint32_t featureId, napi_value handler);
    bool RemoveCallback(uint32_t featureId, napi_value handler);
    bool RemoveAllCallback(uint32_t featureId);
    bool IsEmptyEvents();

private:
    // initialization
    static bool Construct(napi_env env, napi_value jsThis);
    static bool InitializeCallback(napi_env env, const std::string &eventType);

    // userStatus
    static bool LoadLibrary();
    static bool SubscribeToUserStatus(napi_env env, const HoverHandOptions &options);
    static bool UnsubscribeFromUserStatus(napi_env env, const std::string &eventType);

    // utils
    static bool ParseHoverHandParams(napi_env env, napi_value *args, size_t argc, HoverHandOptions &options);
    static bool TransJsToStr(napi_env env, napi_value value, std::string &str);
    static int32_t GetFeatureId(const std::string &eventName);
    static napi_value ConvertToHoverHandEventData(napi_env env, std::shared_ptr<UserStatusData> userStatusData);

    bool InsertRef(std::shared_ptr<JsUserStatusEventCallback> listener, napi_value handler);
    bool IsSameValue(napi_env env, const napi_value &lhs, const napi_value &rhs);

private:
    napi_env env_{ nullptr };
    napi_ref thisVarRef_ { nullptr };
    std::mutex jsCallbacksMutex_;
    std::map<uint32_t, std::shared_ptr<JsUserStatusEventCallback>> jsCallbacks_;

    int32_t callbackId_{ 0 };
    UserStatusAwareness::UserStatusDataCallbackFunc userStatusCallback_{ nullptr };

    void *handle_{ nullptr };
    SubscribeCallbackFunc registerListenerFunc_{ nullptr };
    SubscribeHoverHandFunc subscribeHoverHandFunc_{ nullptr };
    UnsubscribeFunc unsubscribeFunc_{ nullptr };
};
} // namespace Msdp
} // namespace OHOS
#endif // USER_STATUS_EVENT_NAPI_H
