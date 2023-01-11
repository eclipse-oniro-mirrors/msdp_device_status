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

#ifndef IDEVICESTATUS_H
#define IDEVICESTATUS_H

#include <iremote_broker.h>

#include "iremote_object.h"
#include "idevicestatus_callback.h"
#include "devicestatus_data_utils.h"
#include "drag_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class Idevicestatus : public IRemoteBroker {
public:
    enum {
        DEVICESTATUS_SUBSCRIBE = 0,
        DEVICESTATUS_UNSUBSCRIBE,
        DEVICESTATUS_GETCACHE,
        REGISTER_COORDINATION_MONITOR = 30,
        UNREGISTER_COORDINATION_MONITOR = 31,
        ENABLE_COORDINATION = 32,
        START_COORDINATION = 33,
        STOP_COORDINATION = 34,
        GET_COORDINATION_STATE = 35,
        ALLOC_SOCKET_FD = 40,
        START_DRAG,
        STOP_DRAG
    };

    virtual void Subscribe(Type type,
        ActivityEvent event,
        ReportLatencyNs latency,
        sptr<IRemoteDevStaCallback> callback) = 0;
    virtual void Unsubscribe(Type type,
        ActivityEvent event,
        sptr<IRemoteDevStaCallback> callback) = 0;
    virtual Data GetCache(const Type& type) = 0;

    virtual int32_t RegisterCoordinationListener() = 0;
    virtual int32_t UnregisterCoordinationListener() = 0;
    virtual int32_t EnableCoordination(int32_t userData, bool enabled) = 0;
    virtual int32_t StartCoordination(int32_t userData, const std::string &sinkDeviceId,
        int32_t srcDeviceId) = 0;
    virtual int32_t StopCoordination(int32_t userData) = 0;
    virtual int32_t GetCoordinationState(int32_t userData, const std::string &deviceId) = 0;
    virtual int32_t StartDrag(const DragData &dragData) = 0;
    virtual int32_t StopDrag(int32_t &dragResult) = 0;
    virtual int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType,
        int32_t &socketFd, int32_t &tokenType) = 0;
    virtual bool IsRunning() const
    {
        return true;
    }
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.msdp.Idevicestatus");
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // IDEVICESTATUS_H
