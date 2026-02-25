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
#include <atomic>

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

    void CloseOnJsThread();
    void Disable();
    bool Disabled();

    // 做纯 C++ 容器操作；调用方需保证不在持锁状态下调用任何 N-API。
    void SnapshotRefsLocked(std::vector<napi_ref> &out) const;
    bool ContainsRefLocked(napi_ref ref) const;
    void AddRefLocked(napi_ref ref);
    bool RemoveRefLocked(napi_ref ref);
    bool EmptyLocked() const;

public:
    int32_t windowId { 0 };
    std::string event;
    sptr<IRemoteOnScreenCallback> callback;
    napi_env env_ { nullptr };

private:
    std::atomic<bool> disabled_ { false };
    mutable std::mutex refMtx_;
    std::set<napi_ref> onRef_;
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
    static napi_value GetLiveStatus(napi_env env, napi_callback_info info);

private:
    static bool ConstructScreenEventNapi(napi_env env, napi_value jsThis);
    static void DefParallelFeatureStatus(napi_env env, napi_value exports);
    static bool TransJsToStr(napi_env env, napi_value in, std::string &out);
    static bool TransJsToInt32(napi_env env, napi_value in, int32_t &out);
    static void SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName);
    static void SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);
    static bool IsSameJsHandler(napi_env env, const std::vector<napi_ref> &refs, napi_value jsHandler);
    static bool UpsertScreenCallback(napi_env env, int32_t windowId, const std::string &event,
        napi_value jsHandler, napi_ref handlerRef, sptr<OnScreenCallback> &outCb, bool &needRegisterSa);
    static bool EraseAndDeleteJsHandler(napi_env env, std::set<napi_ref>& refs, napi_value jsHandler);
    // 每个 env 都有一份 exports/模块实例：回调表与清理逻辑也按 env 维度隔离。
    static void CollectAllPendingLocked(napi_env env, std::vector<PendingOff>& pending);
    static bool CollectWindowAllPendingLocked(napi_env env, int32_t windowId, std::vector<PendingOff>& pending);
    static bool CollectEventNodePendingLocked(napi_env env, int32_t windowId,
        const std::string& eventStr, std::vector<PendingOff>& pending);
    static bool EraseOneHandlerLocked(napi_env env, int32_t windowId, const std::string& eventStr,
        napi_value jsHandler, std::vector<PendingOff>& pending, std::vector<napi_ref>& doomedRefs);
    static bool FindAndEraseJsHandler(napi_env env, const sptr<OnScreenCallback> &cb,
        napi_value jsHandler, napi_ref& doomed);
};
} // OnScreen
} // DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SCREEN_EVENT_NAPI_H