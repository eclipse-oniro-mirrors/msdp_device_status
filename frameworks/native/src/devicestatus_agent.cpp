/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "devicestatus_agent.h"

#include "devicestatus_define.h"
#include "fi_log.h"
#include "iremote_dev_sta_callback.h"
#include "stationary_manager.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusAgent"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void DeviceStatusAgent::DeviceStatusAgentCallback::OnDeviceStatusChanged(
    const Data &devicestatusData)
{
    FI_HILOGI("type:%{public}d, value:%{public}d", static_cast<Type>(devicestatusData.type),
        static_cast<OnChangedValue>(devicestatusData.value));
    std::shared_ptr<DeviceStatusAgent> agent = agent_.lock();
    CHKPV(agent);
    CHKPV(agent->agentEvent_);
    agent->agentEvent_->OnEventResult(devicestatusData);
}

int32_t DeviceStatusAgent::SubscribeAgentEvent(Type type,
    ActivityEvent event,
    ReportLatencyNs latency,
    std::shared_ptr<DeviceStatusAgent::DeviceStatusAgentEvent> agentEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(agentEvent, ERR_INVALID_VALUE);
    if (!(type > Type::TYPE_INVALID && type <= Type::TYPE_LID_OPEN) ||
        !(event > ActivityEvent::EVENT_INVALID && event <= ActivityEvent::ENTER_EXIT)) {
        FI_HILOGE("Subscription agent event failed");
        return ERR_INVALID_VALUE;
    }
    RegisterServiceEvent(type, event, latency);
    agentEvent_ = agentEvent;
    return RET_OK;
}

int32_t DeviceStatusAgent::UnsubscribeAgentEvent(Type type, ActivityEvent event)
{
    if (type > Type::TYPE_INVALID && type <= Type::TYPE_LID_OPEN && event > ActivityEvent::EVENT_INVALID
        && event <= ActivityEvent::ENTER_EXIT) {
        UnRegisterServiceEvent(type, event);
        return RET_OK;
    }
    FI_HILOGE("Unsubscription agent event failed");
    return ERR_INVALID_VALUE;
}

void DeviceStatusAgent::RegisterServiceEvent(Type type, ActivityEvent event, ReportLatencyNs latency)
{
    CALL_DEBUG_ENTER;
    callback_ = new (std::nothrow) DeviceStatusAgentCallback(shared_from_this());
    CHKPV(callback_);
    StationaryManager::GetInstance()->SubscribeCallback(type, event, latency, callback_);
}

void DeviceStatusAgent::UnRegisterServiceEvent(Type type, ActivityEvent event)
{
    CALL_DEBUG_ENTER;
    StationaryManager::GetInstance()->UnsubscribeCallback(type, event, callback_);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
