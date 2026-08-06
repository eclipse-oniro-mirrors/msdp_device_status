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

#ifndef CAR_AWARENESS_MANAGER_NATIVE_H
#define CAR_AWARENESS_MANAGER_NATIVE_H

#include <memory>
#include <string>
#include <vector>

#include "car_awareness_type.h"
#include "icar_awareness_callback.h"
#include "nocopyable.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class CarAwarenessMgr {
public:
    /**
     * @brief Obtains a <b>CarAwarenessMgr</b> instance.
     * @return Returns a <b>CarAwarenessMgr</b> instance.
     */
    static CarAwarenessMgr &GetInstance();

    /**
     * @brief Subscribe car awareness capability By type.
     * @param type type of capability
     * @param option optional args for sysapi
     * @param cb car awareness event callback
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     */
    int32_t SubscribeCapability(int32_t type, const CarAwarenessOption &option,
                                const sptr<ICarAwarenessCallback> cb);

    /**
     * @brief UnSubscribe car awareness capability By type.
     * @param type type of capability
     * @param option optional args for sysapi
     * @param cb car awareness event callback
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     */
    int32_t UnSubscribeCapability(int32_t type, const CarAwarenessOption &option,
                                  const sptr<ICarAwarenessCallback> cb);

    /**
     * @brief Query the set of supported capabilities.
     * @param capabilities result obtained by interface
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     */
    int32_t GetSupportCapabilityList(std::vector<std::string> &capabilities);

    /**
     * @brief Update zoneId of SpatialAction Capability.
     * @param zoneId id of audio zone
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     */
    int32_t UpdateSpatialActionZone(int32_t zoneId);

    /**
     * @brief Update enable status of SpatialAction Capability.
     * @param eventId event id corresponding to the enable status
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     */
    int32_t UpdateSpatialActionStatus(int32_t eventId);

    /**
     * @brief Get car awareness capability result by type.
     * @param type type of capability
     * @param option optional args for sysapi
     * @param events resulting events
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     */
    int32_t GetCarAwareness(int32_t type, const CarAwarenessOption &option,
                            std::vector<CarAwarenessEvent> &events);

private:
    CarAwarenessMgr() = default;
    ~CarAwarenessMgr() = default;
    DISALLOW_COPY_AND_MOVE(CarAwarenessMgr);
};
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS

#endif // CAR_AWARENESS_MANAGER_NATIVE_H