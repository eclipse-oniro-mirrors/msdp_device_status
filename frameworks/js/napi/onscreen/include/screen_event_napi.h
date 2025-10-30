/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SCREEN_EVENT_NAPI_H
#define SCREEN_EVENT_NAPI_H

#include <uv.h>
#include <set>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "on_screen_callback_stub.h"
#include "on_screen_data.h"
#include "on_screen_manager.h"
#include "on_screen_napi_data.h"


namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
class OnScreenCallback : public OnScreenCallbackStub {
public:
    explicit OnScreenCallback(napi_env env) : env_(env) {}
    ~OnScreenCallback();
    void OnScreenChange(const std::string& changeInfo) override;

public:
    int32_t windowId { 0 };
    std::string event;
    sptr<IRemoteOnScreenCallback> callback;
    std::set<napi_ref> onRef;
    napi_env env_ { nullptr };
};

struct PendingOff {
    int32_t wid;
    std::string evt;
    sptr<OnScreenCallback> cb;
};
class ScreenEventNapi {
public:
    explicit ScreenEventNapi(napi_env env, napi_value thisVar);
    ~ScreenEventNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value RegisterScreenEventCallbackNapi(napi_env env, napi_callback_info info);
    static napi_value UnregisterScreenEventCallbackNapi(napi_env env, napi_callback_info info);
    static napi_value IsParallelFeatureEnabled(napi_env env, napi_callback_info info);

private:
    static bool ConstructScreenEventNapi(napi_env env, napi_value jsThis);
    static void DefParallelFeatureStatus(napi_env env, napi_value exports);
    static bool TransJsToStr(napi_env env, napi_value in, std::string &out);
    static bool TransJsToInt32(napi_env env, napi_value in, int32_t &out);
    static void SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName);
    static void SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);
    static bool IsSameJsHandler(napi_env env, const std::set<napi_ref> &refs, napi_value jsHandler);
    static sptr<OnScreenCallback> UpsertScreenCallback(
        napi_env env, int32_t windowId, const std::string &event, napi_value jsHandler, napi_ref handlerRef);
    static bool EraseAndDeleteJsHandler(napi_env env, std::set<napi_ref>& refs, napi_value jsHandler);
    static void CollectAllPendingLocked(std::vector<PendingOff>& pending);
    static bool CollectWindowAllPendingLocked(int32_t windowId, std::vector<PendingOff>& pending);
    static bool CollectEventNodePendingLocked(int32_t windowId,
        const std::string& eventStr, std::vector<PendingOff>& pending);
    static bool EraseOneHandlerLocked(int32_t windowId, const std::string& eventStr,
        napi_env env, napi_value jsHandler, std::vector<PendingOff>& pending);

    napi_env env_;
};
} // OnScreen
} // DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SCREEN_EVENT_NAPI_H