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

#ifndef BEHAVIOR_AWARENESS_MANAGER_H
#define BEHAVIOR_AWARENESS_MANAGER_H

#include <functional>
#include <memory>
#include <mutex>

#include "nocopyable.h"
#include "behavior_awareness_data.h"
#include "iremote_behavior_awareness_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
class BehaviorAwarenessManager {
public:
    static BehaviorAwarenessManager &GetInstance();
    ~BehaviorAwarenessManager() = default;
    DISALLOW_COPY_AND_MOVE(BehaviorAwarenessManager);

    int32_t SubscribePerception(const SubscribeOptions &options,
        const sptr<IRemoteBehaviorAwarenessCallback> &callback);
    int32_t UnsubscribePerception(const sptr<IRemoteBehaviorAwarenessCallback> &callback);
    int32_t SubmitFeedback(const FeedbackData &feedback);
    void ReSubscribe();

private:
    BehaviorAwarenessManager();
    void InitSaReviveCallback();

    std::mutex mtx_;
    SubscribeOptions lastOptions_;
    sptr<IRemoteBehaviorAwarenessCallback> lastCallback_;
    bool hasSubscription_ { false };
};
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BEHAVIOR_AWARENESS_MANAGER_H
