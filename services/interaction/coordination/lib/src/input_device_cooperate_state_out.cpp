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

#include "input_device_cooperate_state_out.h"

#include "cooperate_event_manager.h"
#include "coordination_message.h"
#include "device_cooperate_softbus_adapter.h"
#include "distributed_input_adapter.h"
#include "coordination_sm.h"
#include "input_device_cooperate_util.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MSDP_DOMAIN_ID, "InputDeviceCooperateStateOut" };
} // namespace

InputDeviceCooperateStateOut::InputDeviceCooperateStateOut(const std::string& startDhid)
    : startDhid_(startDhid)
{}

int32_t InputDeviceCooperateStateOut::StopInputDeviceCoordination(const std::string &networkId)
{
    CALL_DEBUG_ENTER;
    std::string srcNetworkId = networkId;
    if (srcNetworkId.empty()) {
        std::pair<std::string, std::string> prepared = InputDevCooSM->GetPreparedDevices();
        srcNetworkId = prepared.first;
    }
    int32_t ret = DevCoordinationSoftbusAdapter->StopRemoteCoordination(networkId);
    if (ret != RET_OK) {
        FI_HILOGE("Stop input device coordination fail");
        return static_cast<int32_t>(CoordinationMessage::COORDINATION_FAIL);
    }
    std::string taskName = "process_stop_task";
    std::function<void()> handleProcessStopFunc =
        std::bind(&InputDeviceCooperateStateOut::ProcessStop, this, srcNetworkId);
    CHKPR(eventHandler_, RET_ERR);
    eventHandler_->ProxyPostTask(handleProcessStopFunc, taskName, 0);
    return RET_OK;
}

void InputDeviceCooperateStateOut::ProcessStop(const std::string& srcNetworkId)
{
    CALL_DEBUG_ENTER;
    std::string sink = COORDINATION::GetLocalDeviceId();
    auto* context = CoordinationEventMgr->GetIContext();
    CHKPV(context);
    std::vector<std::string> dhids = context->GetDeviceManager().GetCoordinationDhids(startDhid_);
    if (dhids.empty()) {
        InputDevCooSM->OnStopFinish(false, srcNetworkId);
    }
    int32_t ret = DistributedAdapter->StopRemoteInput(srcNetworkId, sink, dhids, [this, srcNetworkId](bool isSuccess) {
        this->OnStopRemoteInput(isSuccess, srcNetworkId);
        });
    if (ret != RET_OK) {
        InputDevCooSM->OnStopFinish(false, srcNetworkId);
    }
}

void InputDeviceCooperateStateOut::OnStopRemoteInput(bool isSuccess, const std::string &srcNetworkId)
{
    CALL_DEBUG_ENTER;
    std::string taskName = "stop_finish_task";
    std::function<void()> handleStopFinishFunc =
        std::bind(&CoordinationSM::OnStopFinish, InputDevCooSM, isSuccess, srcNetworkId);
    CHKPV(eventHandler_);
    eventHandler_->ProxyPostTask(handleStopFinishFunc, taskName, 0);
}

void InputDeviceCooperateStateOut::OnKeyboardOnline(const std::string &dhid)
{
    std::pair<std::string, std::string> networkIds = InputDevCooSM->GetPreparedDevices();
    std::vector<std::string> dhids;
    dhids.push_back(dhid);
    DistributedAdapter->StartRemoteInput(networkIds.first, networkIds.second, dhids, [](bool isSuccess) {});
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
