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

#ifndef CAR_AWARENESS_CLIENT_H
#define CAR_AWARENESS_CLIENT_H

#include <mutex>
#include <unordered_map>
#include <vector>

#include "nocopyable.h"

#include "car_awareness_type.h"
#include "icar_awareness_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class CarAwarenessClient {
public:
    CarAwarenessClient() = default;
    virtual ~CarAwarenessClient() = default;
    DISALLOW_COPY_AND_MOVE(CarAwarenessClient);

    int32_t SubscribeCapability(int32_t type, const CarAwarenessOption &option, const sptr<ICarAwarenessCallback> &cb);
    int32_t UnSubscribeCapability(int32_t type, const CarAwarenessOption &option,
                                  const sptr<ICarAwarenessCallback> &cb);
    int32_t UpdateSpatialActionStatus(int32_t eventId);
    int32_t UpdateSpatialActionZone(int32_t zoneId);
    int32_t GetSupportCapabilityList(std::vector<std::string> &capabilities);
    int32_t GetCarAwareness(int32_t type, const CarAwarenessOption &option,
                            std::vector<CarAwarenessEvent> &events);
};
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS
#endif  // CAR_AWARENESS_CLIENT_H