/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "on_screen_callback_proxy.h"

#include <message_parcel.h>

#include "iremote_object.h"
#include "message_option.h"

#include "devicestatus_common.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "OnScreenCallbackProxy"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
void OnScreenCallbackProxy::OnScreenChange(const std::string& changeInfo)
{
    sptr<IRemoteObject> remote = Remote();
    CHKPV(remote);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(OnScreenCallbackProxy::GetDescriptor())) {
        FI_HILOGE("Write descriptor failed");
        return;
    }
    WRITESTRING(data, changeInfo);

    int32_t ret = remote->SendRequest(static_cast<int32_t>(IRemoteOnScreenCallback::ON_SCREEN_CHANGE),
        data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, error code:%{public}d", ret);
        return;
    }
}
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
