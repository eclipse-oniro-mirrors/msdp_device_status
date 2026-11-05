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

#ifndef DEVICE_STATUS_ANI_DROP_EVENT_H
#define DEVICE_STATUS_ANI_DROP_EVENT_H

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "ohos.multimodalAwareness.deviceStatus.proj.hpp"
#include "ohos.multimodalAwareness.deviceStatus.impl.hpp"
#ifdef MOTION_ENABLE
#include "event_handler.h"
#include "motion_callback_stub.h"
#include "motion_agent_type.h"
#endif // MOTION_ENABLE

namespace OHOS {
namespace Msdp {
namespace DeviceStatusV1 {
using DropDetectionStatus_t = ::ohos::multimodalAwareness::deviceStatus::DropDetectionStatus;
using DropDetectCallback = ::taihe::callback<void(DropDetectionStatus_t)>;

#ifdef MOTION_ENABLE
struct DropCallbackInfo {
    DropCallbackInfo(const DropDetectCallback &callback, std::shared_ptr<AppExecFwk::EventHandler> handler)
        : callback(callback), handler(std::move(handler)) {}

    DropDetectCallback callback;
    std::shared_ptr<AppExecFwk::EventHandler> handler;
    std::atomic<bool> active {true};
};

class AniMotionCallback : public MotionCallbackStub {
public:
    AniMotionCallback() = default;
    ~AniMotionCallback() override = default;
    void OnMotionChanged(const MotionEvent &event) override;
    void EmitOnEvent(std::shared_ptr<MotionEvent> data);
};
#endif // MOTION_ENABLE

class AniMotionEvent {
public:
    static std::shared_ptr<AniMotionEvent> GetInstance();
    AniMotionEvent() = default;
    ~AniMotionEvent() = default;
#ifdef MOTION_ENABLE
    int32_t SubscribeCallback(int32_t type, ::taihe::callback_view<void(DropDetectionStatus_t)> f);
    int32_t UnSubscribeCallback(int32_t type, const DropDetectCallback *callback);
    void OnEventDropDetection(int32_t eventType, const std::shared_ptr<MotionEvent> &event);
#endif // MOTION_ENABLE

private:
#ifdef MOTION_ENABLE
    bool CheckEvents(int32_t eventType);
    int32_t AddCallback(int32_t eventType, const std::shared_ptr<DropCallbackInfo> &callback);
    int32_t RemoveCallback(int32_t eventType, const DropDetectCallback *callback);

    // Serialize each complete on/off operation, including native IPC and state commit.
    // Event delivery only takes mutex_ and never waits for subscriptionMutex_.
    std::mutex subscriptionMutex_;
    std::mutex mutex_;
    // Protected by subscriptionMutex_; do not hold mutex_ across native IPC.
    std::map<int32_t, sptr<IMotionCallback>> callbacks_;
    // Protected by mutex_. Queued tasks retain individual registration identities.
    std::map<int32_t, std::vector<std::shared_ptr<DropCallbackInfo>>> events_;
#endif // MOTION_ENABLE
};
} // namespace DeviceStatusV1
} // namespace Msdp
} // namespace OHOS
#endif // DEVICE_STATUS_ANI_DROP_EVENT_H
