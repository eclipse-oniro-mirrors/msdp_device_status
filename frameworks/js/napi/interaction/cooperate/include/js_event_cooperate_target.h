/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef JS_EVENT_COOPERATE_TARGET_H
#define JS_EVENT_COOPERATE_TARGET_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "nocopyable.h"
#include "uv.h"

#include "i_coordination_listener.h"
#include "js_util_cooperate.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class JsEventCooperateTarget : public ICoordinationListener,
                               public std::enable_shared_from_this<JsEventCooperateTarget> {
public:
    enum class CooperateMessage {
        INFO_START = 0,
        INFO_SUCCESS = 1,
        INFO_FAIL = 2,
        STATE_ON = 3,
        STATE_OFF = 4
    };

    JsEventCooperateTarget();
    DISALLOW_COPY_AND_MOVE(JsEventCooperateTarget);
    virtual ~JsEventCooperateTarget() = default;

    static void EmitJsEnable(sptr<JsUtilCooperate::CallbackInfo> cb,
        const std::string &networkId, const CoordinationMsgInfo &msgInfo);
    static void EmitJsStart(sptr<JsUtilCooperate::CallbackInfo> cb,
        const std::string &remoteNetworkId, const CoordinationMsgInfo &msgInfo);
    static void EmitJsStop(sptr<JsUtilCooperate::CallbackInfo> cb,
        const std::string &networkId, const CoordinationMsgInfo &msgInfo);
    static void EmitJsGetState(sptr<JsUtilCooperate::CallbackInfo> cb, bool state);
    void AddListener(napi_env env, const std::string &type, napi_value handle);
    void RemoveListener(napi_env env, const std::string &type, napi_value handle);
    napi_value CreateCallbackInfo(napi_env, napi_value handle, sptr<JsUtilCooperate::CallbackInfo> callback);
    void ResetEnv();
    void OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg) override;

private:
    static void CallEnablePromiseWork(sptr<JsUtilCooperate::CallbackInfo> cb);
    static void CallEnableAsyncWork(sptr<JsUtilCooperate::CallbackInfo> cb);
    static void CallStartPromiseWork(sptr<JsUtilCooperate::CallbackInfo> cb);
    static void CallStartAsyncWork(sptr<JsUtilCooperate::CallbackInfo> cb);
    static void CallStopPromiseWork(sptr<JsUtilCooperate::CallbackInfo> cb);
    static void CallStopAsyncWork(sptr<JsUtilCooperate::CallbackInfo> cb);
    static void CallGetStatePromiseWork(sptr<JsUtilCooperate::CallbackInfo> cb);
    static void CallGetStateAsyncWork(sptr<JsUtilCooperate::CallbackInfo> cb);
    static void EmitCoordinationMessageEvent(sptr<JsUtilCooperate::CallbackInfo> cb);

    inline static std::map<CoordinationMessage, CooperateMessage> messageTransform = {
        { CoordinationMessage::PREPARE, CooperateMessage::STATE_ON },
        { CoordinationMessage::UNPREPARE, CooperateMessage::STATE_OFF },
        { CoordinationMessage::ACTIVATE, CooperateMessage::INFO_START },
        { CoordinationMessage::ACTIVATE_SUCCESS, CooperateMessage::INFO_SUCCESS },
        { CoordinationMessage::ACTIVATE_FAIL, CooperateMessage::INFO_FAIL }
    };
    inline static std::map<std::string_view, std::vector<sptr<JsUtilCooperate::CallbackInfo>>>
        coordinationListeners_ {};
    std::atomic_bool isListeningProcess_ { false };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // JS_EVENT_COOPERATE_TARGET_H
