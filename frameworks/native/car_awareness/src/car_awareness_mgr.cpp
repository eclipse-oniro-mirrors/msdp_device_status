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

#include "car_awareness_mgr.h"
#include "intention_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
CarAwarenessMgr &CarAwarenessMgr::GetInstance()
{
    static CarAwarenessMgr instance;
    return instance;
}

int32_t CarAwarenessMgr::SubscribeCapability(int32_t type, const CarAwarenessOption &option,
                                             sptr<ICarAwarenessCallback> cb)
{
    return INTER_MGR_IMPL.SubscribeCapability(type, option, cb);
}

int32_t CarAwarenessMgr::UnSubscribeCapability(int32_t type, const CarAwarenessOption &option,
                                               const sptr<ICarAwarenessCallback> cb)
{
    return INTER_MGR_IMPL.UnSubscribeCapability(type, option, cb);
}

int32_t CarAwarenessMgr::GetSupportCapabilityList(std::vector<std::string> &capabilities)
{
    return INTER_MGR_IMPL.GetSupportCapabilityList(capabilities);
}

int32_t CarAwarenessMgr::UpdateSpatialActionZone(int32_t zoneId)
{
    return INTER_MGR_IMPL.UpdateSpatialActionZone(zoneId);
}

int32_t CarAwarenessMgr::UpdateSpatialActionStatus(int32_t eventId)
{
    return INTER_MGR_IMPL.UpdateSpatialActionStatus(eventId);
}

int32_t CarAwarenessMgr::GetCarAwareness(int32_t type, const CarAwarenessOption &option,
                                         std::vector<CarAwarenessEvent> &events)
{
    return INTER_MGR_IMPL.GetCarAwareness(type, option, events);
}

}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS