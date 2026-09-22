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

#ifndef IREMOTE_BEHAVIOR_AWARENESS_CALLBACK_H
#define IREMOTE_BEHAVIOR_AWARENESS_CALLBACK_H

#include <iremote_broker.h>
#include <iremote_object.h>

#include "behavior_awareness_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
class IRemoteBehaviorAwarenessCallback : public IRemoteBroker {
public:
    enum {
        BEHAVIOR_AWARENESS_CHANGE = 0,
    };

    virtual void OnBehaviorAwareness(const PerceptionEventData &event) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.msdp.IRemoteBehaviorAwarenessCallback");
};
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // IREMOTE_BEHAVIOR_AWARENESS_CALLBACK_H
