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

namespace OHOS {
namespace Msdp {
CarAwarenessMgr& CarAwarenessMgr::GetInstance()
{
    static CarAwarenessMgr instance;
    return instance;
}

int32_t CarAwarenessMgr::SubscribeCapability(const int32_t type, const CarAwarenessOption &option,
    const sptr<ICarAwarenessCallback> cb)
{
    return 0;
}

int32_t CarAwarenessMgr::UnSubscribeCapability(const int32_t type, const CarAwarenessOption &option,
    const sptr<ICarAwarenessCallback> cb)
{
    return 0;
}

int32_t CarAwarenessMgr::IsCapabilitySupport(const int32_t type, bool &isSupport)
{
    return 0;
}

int32_t CarAwarenessMgr::GetSupportCapabilityList(std::vector<std::string> &capabilityVec)
{
    return 0;
}

int32_t CarAwarenessMgr::UpdateSpatialActionZone(const int32_t zoneId)
{
    return 0;
}

int32_t CarAwarenessMgr::UpdateSpatialActionStatus(const int32_t eventId)
{
    return 0;
}
} // namespace Msdp
} // namespace OHOS