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

/* Mock intention_client.h for BehaviorAwarenessManager test.
 * Shadows the real intention_client.h via include-path priority.
 * Provides only what behavior_awareness_manager.cpp needs. */

#ifndef INTENTION_CLIENT_H
#define INTENTION_CLIENT_H

#include <functional>
#include "behavior_awareness_data.h"
#include "iremote_behavior_awareness_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class IntentionClient {
public:
    static std::shared_ptr<IntentionClient> GetInstance() { return instance_; }
    static void SetInstance(std::shared_ptr<IntentionClient> inst) { instance_ = inst; }

    virtual ~IntentionClient() = default;
    virtual int32_t SubscribePerception(const BehaviorAwareness::SubscribeOptions &options,
        const sptr<BehaviorAwareness::IRemoteBehaviorAwarenessCallback> &callback) = 0;
    virtual int32_t UnsubscribePerception(
        const sptr<BehaviorAwareness::IRemoteBehaviorAwarenessCallback> &callback) = 0;
    virtual int32_t SubmitFeedback(const BehaviorAwareness::FeedbackData &feedback) = 0;
    virtual void SetSaReviveCallback(std::function<void()> callback) = 0;

private:
    inline static std::shared_ptr<IntentionClient> instance_;
};

#define INTENTION_CLIENT OHOS::Msdp::DeviceStatus::IntentionClient::GetInstance()

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

#endif // INTENTION_CLIENT_H
