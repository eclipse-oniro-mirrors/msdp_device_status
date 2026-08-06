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

#include "car_awareness_client.h"

#include "intention_client.h"

#undef LOG_TAG
#define LOG_TAG "CarAwarenessClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
int32_t CarAwarenessClient::SubscribeCapability(int32_t type, const CarAwarenessOption &option,
                                                const sptr<ICarAwarenessCallback> &cb)
{
    return INTENTION_CLIENT->SubscribeCapability(type, option, cb);
}

int32_t CarAwarenessClient::UnSubscribeCapability(int32_t type, const CarAwarenessOption &option,
                                                  const sptr<ICarAwarenessCallback> &cb)
{
    return INTENTION_CLIENT->UnSubscribeCapability(type, option, cb);
}

int32_t CarAwarenessClient::UpdateSpatialActionStatus(int32_t eventId)
{
    return INTENTION_CLIENT->UpdateSpatialActionStatus(eventId);
}

int32_t CarAwarenessClient::UpdateSpatialActionZone(int32_t zoneId)
{
    return INTENTION_CLIENT->UpdateSpatialActionZone(zoneId);
}

int32_t CarAwarenessClient::GetSupportCapabilityList(std::vector<std::string> &capabilities)
{
    return INTENTION_CLIENT->GetSupportCapabilityList(capabilities);
}

int32_t CarAwarenessClient::GetCarAwareness(int32_t type, const CarAwarenessOption &option,
                                            std::vector<CarAwarenessEvent> &events)
{
    return INTENTION_CLIENT->GetCarAwareness(type, option, events);
}
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS