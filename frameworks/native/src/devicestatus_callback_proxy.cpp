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

#include "devicestatus_callback_proxy.h"

#include <message_parcel.h>

#include "iremote_object.h"
#include "message_option.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusCallbackProxy"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void DeviceStatusCallbackProxy::OnDeviceStatusChanged(const Data& devicestatusData)
{
    sptr<IRemoteObject> remote = Remote();
    CHKPV(remote);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(DeviceStatusCallbackProxy::GetDescriptor())) {
        FI_HILOGE("Write descriptor failed");
        return;
    }
    WRITEINT32(data, static_cast<int32_t>(devicestatusData.type));
    WRITEINT32(data, static_cast<int32_t>(devicestatusData.value));

    int32_t ret = remote->SendRequest(static_cast<int32_t>(IRemoteDevStaCallback::DEVICESTATUS_CHANGE),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, error code:%{public}d", ret);
        return;
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
