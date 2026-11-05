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

#ifndef DEVICE_STATUS_DROP_EVENT_NAPI_H
#define DEVICE_STATUS_DROP_EVENT_NAPI_H

#include <cstdint>
#include <memory>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#ifdef MOTION_ENABLE
#include <mutex>
#include <set>

#include "motion_callback_stub.h"
#endif // MOTION_ENABLE

namespace OHOS {
namespace Msdp {
enum class DropDetectionStatus : int32_t {
    STATUS_NORMAL = 0,
    STATUS_DROPPED = 1,
};

#ifdef MOTION_ENABLE
class DeviceStatusMotionEventNapi;
class DropDetectCallback final : public MotionCallbackStub {
public:
    void OnMotionChanged(const MotionEvent &event) override;
    void AddTarget(const std::shared_ptr<DeviceStatusMotionEventNapi> &target);
    void RemoveTarget(const std::shared_ptr<DeviceStatusMotionEventNapi> &target);
    bool HasTargets() const;

private:
    mutable std::mutex mutex_;
    std::vector<std::weak_ptr<DeviceStatusMotionEventNapi>> targets_;
};
#endif // MOTION_ENABLE

class DeviceStatusMotionEventNapi : public std::enable_shared_from_this<DeviceStatusMotionEventNapi> {
public:
    static napi_value OnDropDetect(napi_env env, napi_callback_info info);
    static napi_value OffDropDetect(napi_env env, napi_callback_info info);
    static void DefineDropDetectionStatus(napi_env env, napi_value exports);
#ifdef MOTION_ENABLE
    explicit DeviceStatusMotionEventNapi(napi_env env) : env_(env) {}
    ~DeviceStatusMotionEventNapi() = default;

#endif // MOTION_ENABLE

private:
    // NAPI helpers.
    static bool ValidateOffArgsType(napi_env env, napi_value callback);
    static void SetInt32Property(napi_env env, napi_value targetObj, int32_t value, const char *propName);
    static void SetPropertyName(napi_env env, napi_value targetObj, const char *propName, napi_value propValue);

#ifdef MOTION_ENABLE
    friend class DropDetectCallback;

    struct CallbackRegistration {
        explicit CallbackRegistration(napi_ref handlerRef) : handlerRef(handlerRef) {}
        // Accessed only on the environment thread; cancellation deletes this reference.
        napi_ref handlerRef;
    };
    using CallbackSnapshot = std::vector<std::shared_ptr<CallbackRegistration>>;

    // Instance lifecycle.
    static std::shared_ptr<DeviceStatusMotionEventNapi> GetInstance(napi_env env);
    static std::shared_ptr<DeviceStatusMotionEventNapi> GetOrCreateInstance(napi_env env);
    static void CleanupInstance(void *data);

    // Service subscriptions.
    int32_t SubscribeToService();
    int32_t UnsubscribeFromService();

    // Event delivery.
    // Called by DropDetectCallback while holding the registration snapshot lock.
    void PostMotionEvent(const MotionEvent &event);
    void OnEventDropDetection(int32_t status, const CallbackSnapshot &callbacks);
    bool ConvertDropDetectionData(napi_value handler, int32_t status);

    // JS callback management.
    int32_t AddCallbackEx(napi_value handler);
    int32_t RemoveCallback(napi_value handler);
    int32_t RemoveAllCallback();
    bool HasCallbacks();
    void CleanupDropCallbacks(napi_env env);
    bool IsSameValue(const napi_env &env, const napi_value &lhs, const napi_value &rhs);

    std::mutex envMutex_;
    napi_env env_ = nullptr;
    // Protected by the registration snapshot lock; queued tasks retain identities,
    // while all NAPI reference access and deletion stays on the environment thread.
    std::set<std::shared_ptr<CallbackRegistration>> callbackRefs_;
#endif // MOTION_ENABLE
};
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_STATUS_DROP_EVENT_NAPI_H
