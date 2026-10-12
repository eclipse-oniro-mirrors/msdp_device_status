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

#include "behavior_awareness_callback_taihe.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessCallbackTaihe"

namespace ANI::MultimodalAwareness {
using namespace OHOS::Msdp::DeviceStatus::BehaviorAwareness;

BehaviorAwarenessCallbackTaihe::BehaviorAwarenessCallbackTaihe(
    std::shared_ptr<taihe::callback<void(
        ohos::multimodalAwareness::behaviorAwareness::PerceptionEvent const &)>> callback)
    : callback_(callback) {}

void BehaviorAwarenessCallbackTaihe::OnBehaviorAwareness(const PerceptionEventData &event)
{
    std::lock_guard lock(mutex_);
    if (callback_ == nullptr) {
        FI_HILOGE("OnBehaviorAwareness: callback is null");
        return;
    }
    ohos::multimodalAwareness::behaviorAwareness::PerceptionEvent taiheEvent{
        .perceptionEventId = taihe::string(event.perceptionEventId.c_str()),
        .domain = ohos::multimodalAwareness::behaviorAwareness::PerceptionDomain(
            ohos::multimodalAwareness::behaviorAwareness::PerceptionDomain::key_t::HABIT_AWARENESS),
        .confidence = event.confidence,
        .generateTime = event.generateTime,
        .payload = taihe::map<taihe::string, uintptr_t>(),
    };
    (*callback_)(taiheEvent);
    FI_HILOGD("OnBehaviorAwareness: event pushed, id:%{public}s", event.perceptionEventId.c_str());
}

bool BehaviorAwarenessCallbackTaihe::Matches(const taihe::callback_view<void(
    ohos::multimodalAwareness::behaviorAwareness::PerceptionEvent const &)> &other) const
{
    if (callback_ == nullptr) {
        return false;
    }
    return *callback_ == other;
}
} // namespace ANI::MultimodalAwareness
