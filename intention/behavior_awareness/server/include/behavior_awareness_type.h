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

#ifndef BEHAVIOR_AWARENESS_TYPE_H
#define BEHAVIOR_AWARENESS_TYPE_H

#include <cstdint>
#include <string>
#include <vector>

#include "behavior_awareness_data.h"
#include "iremote_behavior_awareness_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
struct SubscriptionInfo {
    PerceptionDomain domain { PerceptionDomain::HABIT_AWARENESS };
    std::vector<int32_t> patternTypes;
    sptr<IRemoteBehaviorAwarenessCallback> callback;
};
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // BEHAVIOR_AWARENESS_TYPE_H
