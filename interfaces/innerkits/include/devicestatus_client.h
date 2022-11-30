/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DEVICESTATUS_CLIENT_H
#define DEVICESTATUS_CLIENT_H

#include <singleton.h>

#include "idevicestatus.h"
#include "idevicestatus_callback.h"
#include "devicestatus_data_utils.h"
#include "devicestatus_common.h"
#include "i_coordination_listener.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DevicestatusClient final : public DelayedRefSingleton<DevicestatusClient> {
    DECLARE_DELAYED_REF_SINGLETON(DevicestatusClient)

public:
    DISALLOW_COPY_AND_MOVE(DevicestatusClient);

    void SubscribeCallback(const DevicestatusDataUtils::DevicestatusType& type, \
        const sptr<IdevicestatusCallback>& callback);
    void UnSubscribeCallback(const DevicestatusDataUtils::DevicestatusType& type, \
        const sptr<IdevicestatusCallback>& callback);
    DevicestatusDataUtils::DevicestatusData GetDevicestatusData(const DevicestatusDataUtils::DevicestatusType& type);

    int32_t RegisterCoordinationListener(std::shared_ptr<ICoordinationListener> listener);
    int32_t UnregisterCoordinationListener(std::shared_ptr<ICoordinationListener> listener = nullptr);
    int32_t EnableInputDeviceCoordination(bool enabled, std::function<void(std::string, CoordinationMessage)> callback);
    int32_t StartInputDeviceCoordination(const std::string &sinkDeviceId, int32_t srcInputDeviceId,
        std::function<void(std::string, CoordinationMessage)> callback);
    int32_t StopDeviceCoordination(std::function<void(std::string, CoordinationMessage)> callback);
    int32_t GetInputDeviceCoordinationState(const std::string &deviceId, std::function<void(bool)> callback);

    int32_t AllocSocketPair(const int32_t moduleType);
    int32_t GetClientSocketFdOfAllocedSocketPair() const;
private:
    class DevicestatusDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DevicestatusDeathRecipient() = default;
        ~DevicestatusDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote);
    private:
        DISALLOW_COPY_AND_MOVE(DevicestatusDeathRecipient);
    };

    ErrCode Connect();
    sptr<Idevicestatus> devicestatusProxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
    void ResetProxy(const wptr<IRemoteObject>& remote);
    std::mutex mutex_;
    int32_t tokenType_ { -1 };
    int32_t socketFd_ { -1 };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // IDEVICESTATUS_H
