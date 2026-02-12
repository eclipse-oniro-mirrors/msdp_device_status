/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef MOTION_NAPI_H
#define MOTION_NAPI_H

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#ifdef MOTION_ENABLE
#include "motion_callback_stub.h"
#endif
#include "motion_event_napi.h"

namespace OHOS {
namespace Msdp {
class MotionNapi;
#ifdef MOTION_ENABLE
class MotionCallback : public MotionCallbackStub {
public:
    MotionCallback() = default;
    ~MotionCallback() override = default;
    void OnMotionChanged(const MotionEvent& event) override;
    // 一个系统侧回调需要分发给多个 JS 上下文（不同 napi_env）。
    void AddTarget(const std::shared_ptr<MotionNapi>& target);
    void RemoveTarget(const std::shared_ptr<MotionNapi>& target);
    bool HasTargets() const;

private:
    // 保护 targets_ 的互斥锁
    mutable std::mutex mutex_;
    std::vector<std::weak_ptr<MotionNapi>> targets_;
};
#endif

class MotionNapi : public MotionEventNapi, public std::enable_shared_from_this<MotionNapi> {
public:
    explicit MotionNapi(napi_env env, napi_value thisVar);
    ~MotionNapi() override;

    static napi_value Init(napi_env env, napi_value exports);
    static void DefineHoldingHandStatus(napi_env env, napi_value exports);
    static napi_value SubscribeMotion(napi_env env, napi_callback_info info);
    static napi_value UnSubscribeMotion(napi_env env, napi_callback_info info);
    static napi_value GetRecentOptHandStatus(napi_env env, napi_callback_info info);
public:
#ifdef MOTION_ENABLE
    // 将事件投递回“当前 napi_env 对应的 JS 线程”执行 避免跨线程直接调用 N-API
    void PostMotionEvent(int32_t type, int32_t status);
    bool ScheduleOperatingHandOnceDelayed(napi_ref handlerRef, int32_t status, uint32_t delayMs);
    void InvokeOperatingHandOnce(napi_ref handlerRef, int32_t status);
#endif

private:
#ifdef MOTION_ENABLE
    bool SubscribeToService(napi_env env, int32_t type, bool &serviceAlreadySubscribed);
    bool DoSubscription(napi_env env, int32_t type, sptr<MotionCallback> cb);
    bool UnsubscribeFromService(napi_env env, int32_t type);
    void UnsubscribeFromServiceNoThrow(int32_t type);
    void UnsubscribeFromAllTypes();
    void UnsubscribeFromAllTypesNoThrow();
#endif
    static void SaveExportsWeakRef(napi_env env, napi_value exports);
    static napi_value GetStableThis(napi_env env, napi_value jsThis);
    static void TakeAndDeleteExportsRef(napi_env env);
    static int32_t GetMotionType(const std::string &type);
    static std::shared_ptr<MotionNapi> GetOrCreateInstance(napi_env env, napi_value jsThis);
    static void RollbackInstancesLocked(napi_env env, const std::shared_ptr<MotionNapi> &sp);
    static std::shared_ptr<MotionNapi> TryGetExistingInstanceLocked(napi_env env);
    static std::shared_ptr<MotionNapi> GetInstance(napi_env env);
    static bool ValidateArgsType(napi_env env, napi_value *args, size_t argc,
        const std::vector<std::string> &expectedTypes);
    static bool TransJsToStr(napi_env env, napi_value value, std::string &str);
    static void SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName);
    static void SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);

};
} // namespace Msdp
} // namespace OHOS
#endif //MOTION_NAPI_H
