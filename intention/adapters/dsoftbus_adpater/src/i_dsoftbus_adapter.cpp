/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "i_dsoftbus_adapter.h"

#include "softbus_bus_center.h"

#include "devicestatus_define.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL { LOG_CORE, MSDP_DOMAIN_ID, "IDSoftbusAdapter" };
}

std::string IDSoftbusAdapter::GetLocalNetworkId()
{
    NodeBasicInfo localNode;

    int32_t ret = ::GetLocalNodeDeviceInfo(FI_PKG_NAME, &localNode);
    if (ret != RET_OK) {
        FI_HILOGE("DSOFTBUS::GetLocalNodeDeviceInfo fail, error:%{public}d", ret);
        return {};
    }
    return localNode.networkId;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS