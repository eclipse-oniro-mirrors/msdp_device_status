/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef STATIONARY_MANAGER_H
#define STATIONARY_MANAGER_H

#include <functional>
#include <memory>

#include "nocopyable.h"

#include "devicestatus_common.h"
#include "iremote_dev_sta_callback.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class StationaryManager {
public:

    /**
     * @brief Obtains a <b>StationaryManager</b> instance.
     * @return Returns a <b>StationaryManager</b> instance.
     * @since 9
     */
    static StationaryManager *GetInstance();

    /**
     * @brief Subscribes to device status changes.
     * @param type Indicates the device status type.
     * @param event Indicates the event type, which can be <b>ENTER</b>, <b>EXIT</b>, and <b>ENTER_EXIT</b>.
     * @param latency Indicates the reporting interval.
     * @param callback Indicates the callback used to return the device status changes.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t SubscribeCallback(Type type, ActivityEvent event, ReportLatencyNs latency,
        sptr<IRemoteDevStaCallback> callback);

    /**
     * @brief Unsubscribes from device status changes.
     * @param type Indicates the device status type.
     * @param event Indicates the event type, which can be <b>ENTER</b>, <b>EXIT</b>, and <b>ENTER_EXIT</b>.
     * @param callback Indicates the callback used to return the device status changes.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t UnsubscribeCallback(Type type, ActivityEvent event, sptr<IRemoteDevStaCallback> callback);

    /**
     * @brief Obtains the device status data.
     * @param type Indicates the device status type.
     * @return Returns the device status data.
     * @since 9
     */
    Data GetDeviceStatusData(const Type type);
private:
    StationaryManager() = default;
    DISALLOW_COPY_AND_MOVE(StationaryManager);
    static StationaryManager *instance_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // STATIONARY_MANAGER_H