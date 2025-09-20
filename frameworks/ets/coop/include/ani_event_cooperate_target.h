/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ANI_EVENT_COOPERATE_TARGET_H
#define ANI_EVENT_COOPERATE_TARGET_H

#include "nocopyable.h"
#include "i_coordination_listener.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class AniEventCooperateTarget : public ICoordinationListener,
                               public std::enable_shared_from_this<AniEventCooperateTarget> {
public:
    enum class CooperateMessage {
        INFO_START = 0,
        INFO_SUCCESS = 1,
        INFO_FAIL = 2,
        STATE_ON = 3,
        STATE_OFF = 4
    };
    AniEventCooperateTarget();
    DISALLOW_COPY_AND_MOVE(AniEventCooperateTarget);
    virtual ~AniEventCooperateTarget() = default;
    void OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg) override;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // JS_EVENT_COOPERATE_TARGET_H
