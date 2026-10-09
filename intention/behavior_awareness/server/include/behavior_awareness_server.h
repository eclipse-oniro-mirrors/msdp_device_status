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

#ifndef BEHAVIOR_AWARENESS_SERVER_H
#define BEHAVIOR_AWARENESS_SERVER_H

#include <cstdint>
#include <string>
#include <unordered_map>

#include "behavior_awareness_type.h"
#include "i_plugin.h"
#include "iremote_behavior_awareness_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
class BehaviorAwarenessServer {
public:
    BehaviorAwarenessServer() = default;
    ~BehaviorAwarenessServer() = default;
    DISALLOW_COPY_AND_MOVE(BehaviorAwarenessServer);

    int32_t SubscribePerception(const CallingContext &context, const SubscribeOptions &options,
        const sptr<IRemoteBehaviorAwarenessCallback> &callback);
    int32_t UnsubscribePerception(const CallingContext &context,
        const sptr<IRemoteBehaviorAwarenessCallback> &callback);
    int32_t SubmitFeedback(const CallingContext &context, const FeedbackData &feedback);
    void NotifyClient(const PerceptionEventData &event);

private:
    std::string BuildSubscriptionKey(const std::string &bundleName, const SubscribeOptions &options);
    void SaveSubscription(const std::string &key, const SubscribeOptions &options,
        const sptr<IRemoteBehaviorAwarenessCallback> &callback);
    void RemoveSubscription(const std::string &key);
    int32_t RemoveAllSubscriptions(const std::string &bundleName);
    int32_t RemoveMatchingSubscription(const std::string &bundleName,
        const sptr<IRemoteBehaviorAwarenessCallback> &callback);
    void InitDeathRecipient();
    void OnRemoteDied(const wptr<IRemoteObject> &remote);

    std::unordered_map<std::string, SubscriptionInfo> subscriptions_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BEHAVIOR_AWARENESS_SERVER_H
