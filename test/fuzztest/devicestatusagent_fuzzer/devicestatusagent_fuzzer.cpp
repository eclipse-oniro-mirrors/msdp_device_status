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

#include "devicestatusagent_fuzzer.h"

#include "fi_log.h"
#include <fuzzer/FuzzedDataProvider.h>

#include "stationary_data.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusAgentFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

static std::shared_ptr<DevicestatusAgentFuzzer::DeviceStatusAgentClient> agentEvent_ =
            std::make_shared<DevicestatusAgentFuzzer::DeviceStatusAgentClient>();
static std::shared_ptr<DeviceStatusAgent> agent_ = std::make_shared<DeviceStatusAgent>();

bool DevicestatusAgentFuzzer::DeviceStatusAgentClient::OnEventResult(
    const Data& devicestatusData)
{
    std::cout << "type: " << devicestatusData.type << std::endl;
    std::cout << "value: " << devicestatusData.value << std::endl;
    return true;
}

bool DeviceStatusAgentFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < 1)) {
        return false;
    }
    FuzzedDataProvider provider(data, size);
    int32_t type = provider.PickValueInArray({-1,0, 1, 2, 3, 4, 5, 6, 7, 8});
    int32_t event = provider.PickValueInArray({0, 1, 2, 3});
    int32_t latency = provider.PickValueInArray({-1, 1, 2, 3});
    agent_->SubscribeAgentEvent(static_cast<Type>(type),
        static_cast<ActivityEvent>(event), static_cast<ReportLatencyNs>(latency), agentEvent_);
    agent_->UnsubscribeAgentEvent(static_cast<Type>(type), static_cast<ActivityEvent>(event));
    agent_->RegisterServiceEvent(static_cast<Type>(type),
        static_cast<ActivityEvent>(event), static_cast<ReportLatencyNs>(latency));
    agent_->UnRegisterServiceEvent(static_cast<Type>(type), static_cast<ActivityEvent>(event));
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    OHOS::Msdp::DeviceStatus::DeviceStatusAgentFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS