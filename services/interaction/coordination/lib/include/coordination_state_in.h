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

#ifndef COORDINATION_STATE_IN_H
#define COORDINATION_STATE_IN_H

#include "i_coordination_state.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class CoordinationStateIn final : public ICoordinationState {
public:
    explicit CoordinationStateIn(const std::string &startDhid);
    int32_t StartCoordination(const std::string &remoteNetworkId, int32_t startDeviceId) override;
    int32_t StopCoordination(const std::string &networkId) override;

private:
    void ComeBack(const std::string &sinkNetworkId, int32_t startDeviceId);
    int32_t RelayComeBack(const std::string &srcNetworkId, int32_t startDeviceId);
    void OnStartRemoteInput(bool isSuccess, const std::string &srcNetworkId, int32_t startDeviceId) override;
    void StopRemoteInput(const std::string &sinkNetworkId, const std::string &srcNetworkId,
        const std::vector<std::string> &dhid, int32_t startDeviceId);
    void OnStopRemoteInput(bool isSuccess, const std::string &srcNetworkId, int32_t startDeviceId);
    int32_t ProcessStart(const std::string &remoteNetworkId, int32_t startDeviceId);
    int32_t ProcessStop();
    std::string startDhid_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COORDINATION_STATE_IN_H