/*
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

#include "car_awareness_callback_proxy.h"

#include <message_parcel.h>

#include "devicestatus_common.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "CarAwarenessCallbackProxy"

namespace OHOS {
namespace Msdp {
constexpr int32_t MAX_DATA_LEN = 1024 * 1024;

void CarAwarenessCallbackProxy::OnAwarenessEvent(const CarAwarenessEvent &event)
{
    FI_HILOGD("Enter");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        FI_HILOGE("remote object is null");
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(CarAwarenessCallbackProxy::GetDescriptor())) {
        FI_HILOGE("Write descriptor failed");
        return;
    }
    
    int32_t eventDataLen = event.eventData.size();
    if (eventDataLen > MAX_DATA_LEN || eventDataLen < 0) {
        FI_HILOGE("eventData too long");
        return;
    }

    WRITEINT32(data, event.type);
    WRITEINT32(data, event.eventData.size());
    WRITESTRING(data, event.eventData);

    int32_t ret = remote->SendRequest(static_cast<int32_t>(ICarAwarenessCallback::EVENT_CHANGE), data, reply, option);
    if (ret != 0) {
        FI_HILOGE("SendRequest is failed, error code:%{public}d", ret);
        return;
    }
}
}  // namespace Msdp
}  // namespace OHOS
