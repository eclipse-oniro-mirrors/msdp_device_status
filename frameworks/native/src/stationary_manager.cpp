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

#include "stationary_manager.h"

#include "util.h"

#include "devicestatus_client.h"
#include "devicestatus_common.h"
#include "devicestatus_define.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

StationaryManager *StationaryManager::instance_ = new (std::nothrow) StationaryManager();

StationaryManager *StationaryManager::GetInstance()
{
    return instance_;
}

int32_t StationaryManager::SubscribeCallback(Type type, ActivityEvent event, ReportLatencyNs latency,
    sptr<IRemoteDevStaCallback> callback)
{
    return  DeviceStatusClient::GetInstance().SubscribeCallback(type, event, latency, callback);
}

int32_t StationaryManager::UnsubscribeCallback(Type type, ActivityEvent event, sptr<IRemoteDevStaCallback> callback)
{
    return  DeviceStatusClient::GetInstance().UnsubscribeCallback(type, event, callback);
}

Data StationaryManager::GetDeviceStatusData(Type type)
{
    return DeviceStatusClient::GetInstance().GetDeviceStatusData(type);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS