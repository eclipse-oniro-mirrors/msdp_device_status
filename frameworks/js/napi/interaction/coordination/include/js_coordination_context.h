/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef JS_COORDINATION_CONTEXT_H
#define JS_COORDINATION_CONTEXT_H

#include <memory>

#include "napi/native_node_api.h"
#include "js_coordination_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class JsCoordinationContext final {
public:
    JsCoordinationContext();
    DISALLOW_COPY_AND_MOVE(JsCoordinationContext);
    ~JsCoordinationContext();

    static napi_value Export(napi_env env, napi_value exports);
    static napi_value Prepare(napi_env env, napi_callback_info info);
    static napi_value Unprepare(napi_env env, napi_callback_info info);
    static napi_value Activate(napi_env env, napi_callback_info info);
    static napi_value Deactivate(napi_env env, napi_callback_info info);
    static napi_value GetCrossingSwitchState(napi_env env, napi_callback_info info);
    static napi_value On(napi_env env, napi_callback_info info);
    static napi_value Off(napi_env env, napi_callback_info info);
    std::shared_ptr<JsCoordinationManager> GetJsCoordinationMgr();

private:
    static napi_value CreateInstance(napi_env env);
    static napi_value JsConstructor(napi_env env, napi_callback_info info);
    static JsCoordinationContext *GetInstance(napi_env env);
    static void DeclareDeviceCoordinationInterface(napi_env env, napi_value exports);
    static void DeclareDeviceCoordinationData(napi_env env, napi_value exports);
    static napi_value EnumClassConstructor(napi_env env, napi_callback_info info);

    std::shared_ptr<JsCoordinationManager> mgr_ { nullptr };
    std::mutex mutex_;
    napi_ref contextRef_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // JS_COORDINATION_CONTEXT_H
