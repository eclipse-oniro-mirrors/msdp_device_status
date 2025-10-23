/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANI_DEVICESTATUS_MANAGER_H
#define ANI_DEVICESTATUS_MANAGER_H

#include <string>
#include <mutex>
#include <map>

#include "ohos.stationary.proj.hpp"
#include "ohos.stationary.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "devicestatus_callback_stub.h"
#include "stationary_data.h"
#include "ani_devicestatus_event.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using ActivityEvent_t = ohos::stationary::ActivityEvent;
using ActivityResponse_t = ohos::stationary::ActivityResponse;
class AniDeviceStatusCallback : public DeviceStatusCallbackStub {
public:
    AniDeviceStatusCallback();
    virtual ~AniDeviceStatusCallback();
    void OnDeviceStatusChanged(const Data &devicestatusData) override;
private:
    std::mutex backMutex_;
};

class AniDeviceStatusManager : public AniDeviceStatusEvent {
public:
    explicit AniDeviceStatusManager();
    ~AniDeviceStatusManager();

    static std::shared_ptr<AniDeviceStatusManager> GetInstance();
    int32_t ConvertTypeToInt(const std::string &type);
    ActivityEvent ConvertEventToInt(ActivityEvent_t event);
    void GetDeviceStatus(const std::string action,
        taihe::callback_view<void(ActivityResponse_t const&)> f, uintptr_t opq);
    void SubscribeDeviceStatusCallback(int32_t type, int32_t
        event, int32_t latency, uintptr_t opq);
    void SubscribeDeviceStatus(const std::string action, ActivityEvent_t event,
        int64_t reportLatencyNs, ::taihe::callback_view<void(ActivityResponse_t const&)> f, uintptr_t opq);
    void UnsubscribeCallback(int32_t type, int32_t event);
    void UnsubscribeDeviceStatus(const std::string action, ActivityEvent_t event,
        taihe::optional_view<uintptr_t> opq);
private:
    std::mutex mutex_;
    static std::map<int32_t, sptr<IRemoteDevStaCallback>> callbacks_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // ANI_DEVICESTATUS_MANAGER_H