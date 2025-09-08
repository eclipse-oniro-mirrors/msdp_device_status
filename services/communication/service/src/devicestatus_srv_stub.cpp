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

#include "devicestatus_srv_stub.h"

#include <unistd.h>
#include <tokenid_kit.h>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "pixel_map.h"

#include "devicestatus_callback_proxy.h"
#include "devicestatus_common.h"
#include "devicestatus_define.h"
#include "drag_data_packer.h"
#include "preview_style_packer.h"
#include "devicestatus_proto.h"
#include "iremote_dev_sta_callback.h"
#include "stationary_data.h"
#include "include/util.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusSrvStub"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

DeviceStatusSrvStub::DeviceStatusSrvStub()
{
}

int32_t DeviceStatusSrvStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    FI_HILOGD("cmd:%{public}d, flags:%{public}d", code, option.GetFlags());
    std::u16string descriptor = DeviceStatusSrvStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        FI_HILOGE("DeviceStatusSrvStub::OnRemoteRequest failed, descriptor is not matched");
        return E_DEVICESTATUS_GET_SERVICE_FAILED;
    }
    FI_HILOGE("Unknown code:%{public}u", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS