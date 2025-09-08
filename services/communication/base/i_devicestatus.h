/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef I_DEVICESTATUS_H
#define I_DEVICESTATUS_H

#include <iremote_broker.h>

#include "drag_data.h"
#include "msdp_ipc_interface_code.h"
#include "iremote_dev_sta_callback.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class Idevicestatus : public IRemoteBroker {
public:
    virtual void Subscribe(Type type,
        ActivityEvent event,
        ReportLatencyNs latency,
        sptr<IRemoteDevStaCallback> callback) = 0;
    virtual void Unsubscribe(Type type,
        ActivityEvent event,
        sptr<IRemoteDevStaCallback> callback) = 0;
    virtual Data GetCache(const Type &type) = 0;

    virtual int32_t AllocSocketFd(const std::string &programName, int32_t moduleType,
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
#endif // I_DEVICESTATUS_H
