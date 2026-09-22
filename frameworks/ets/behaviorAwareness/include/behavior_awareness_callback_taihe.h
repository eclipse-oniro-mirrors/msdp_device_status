/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef BEHAVIOR_AWARENESS_CALLBACK_TAIHE_H
#define BEHAVIOR_AWARENESS_CALLBACK_TAIHE_H

#include <memory>
#include <mutex>

#include "ohos.multimodalAwareness.behaviorAwareness.proj.hpp"
#include "ohos.multimodalAwareness.behaviorAwareness.impl.hpp"
#include "taihe/runtime.hpp"
#include "behavior_awareness_callback_stub.h"
#include "behavior_awareness_data.h"

namespace ANI::MultimodalAwareness {

class BehaviorAwarenessCallbackTaihe
    : public OHOS::Msdp::DeviceStatus::BehaviorAwareness::BehaviorAwarenessCallbackStub {
public:
    explicit BehaviorAwarenessCallbackTaihe(
        std::shared_ptr<taihe::callback<void(
            ohos::multimodalAwareness::behaviorAwareness::PerceptionEvent const &)>> callback);
    ~BehaviorAwarenessCallbackTaihe() = default;

    void OnBehaviorAwareness(
        const OHOS::Msdp::DeviceStatus::BehaviorAwareness::PerceptionEventData &event) override;

private:
    std::mutex mutex_;
    std::shared_ptr<taihe::callback<void(
        ohos::multimodalAwareness::behaviorAwareness::PerceptionEvent const &)>> callback_;
};

} // namespace ANI::MultimodalAwareness
#endif // BEHAVIOR_AWARENESS_CALLBACK_TAIHE_H
