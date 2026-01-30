/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef COOPERATE_SERVER_H
#define COOPERATE_SERVER_H

#include "nocopyable.h"

#include "i_context.h"
#include "i_plugin.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class CooperateServer final {
public:
    CooperateServer(IContext *context);
    ~CooperateServer() = default;
    DISALLOW_COPY_AND_MOVE(CooperateServer);

    int32_t EnableCooperate(CallingContext &context, int32_t userData);
    int32_t DisableCooperate(CallingContext &context, int32_t userData);
    int32_t StartCooperate(CallingContext &context, const std::string& remoteNetworkId, int32_t userData,
        int32_t startDeviceId, bool checkPermission);
    int32_t StartCooperateWithOptions(CallingContext &context, const std::string& remoteNetworkId,
        int32_t userData, int32_t startDeviceId, CooperateOptions options);
    int32_t StopCooperate(CallingContext &context, int32_t userData, bool isUnchained, bool checkPermission);
    int32_t RegisterCooperateListener(CallingContext &context);
    int32_t UnregisterCooperateListener(CallingContext &context);
    int32_t RegisterHotAreaListener(CallingContext &context, int32_t userData, bool checkPermission);
    int32_t UnregisterHotAreaListener(CallingContext &context);
    int32_t RegisterMouseEventListener(CallingContext &context, const std::string& networkId);
    int32_t UnregisterMouseEventListener(CallingContext &context, const std::string& networkId);
    int32_t GetCooperateStateSync(CallingContext &context, const std::string& udid, bool& state);
    int32_t GetCooperateStateAsync(CallingContext &context, const std::string& networkId, int32_t userData,
        bool isCheckPermission);
    int32_t SetDamplingCoefficient(CallingContext &context, uint32_t direction, double coefficient);
private:
    IContext *context_ { nullptr };
    int32_t unloadTimerId_ { -1 };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_SERVER_H