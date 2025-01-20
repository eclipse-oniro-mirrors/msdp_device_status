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

#ifndef JS_DRAG_MANAGER_H
#define JS_DRAG_MANAGER_H

#include <map>
#include <mutex>
#include <string>
#include <uv.h>
#include <vector>

#include "napi/native_node_api.h"
#include "nocopyable.h"
#include "refbase.h"

#include "i_drag_listener.h"
#include "i_subscript_listener.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class JsDragManager : public IDragListener, public std::enable_shared_from_this<JsDragManager> {
public:
    JsDragManager() = default;
    DISALLOW_COPY_AND_MOVE(JsDragManager);
    ~JsDragManager() = default;

    void ResetEnv();
    void OnDragMessage(DragState state) override;
    void RegisterListener(napi_env env, napi_value handle);
    void UnregisterListener(napi_env env, napi_value handle = nullptr);
    napi_value GetDataSummary(napi_env env);
    void SetDragSwitchState(napi_env env, bool enable);
    void SetAppDragSwitchState(napi_env env, bool enable, const std::string &pkgName);

private:
    struct CallbackInfo : public RefBase {
        napi_env env { nullptr };
        napi_ref ref { nullptr };
        DragState state;
    };
    template <typename T>
    static void DeletePtr(T &ptr)
    {
        if (ptr != nullptr) {
            delete ptr;
            ptr = nullptr;
        }
    }

    static void CallDragMsg(sptr<CallbackInfo> cb);
    void DeleteCallbackInfo(std::unique_ptr<CallbackInfo> callback);
    void ReleaseReference();
    bool IsSameHandle(napi_env env, napi_value handle, napi_ref ref);

    std::atomic_bool hasRegistered_ { false };
    inline static std::mutex mutex_;
    inline static std::vector<sptr<CallbackInfo>> listeners_ {};
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // JS_DRAG_MANAGER_H
