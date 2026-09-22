/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "behavior_awareness_callback_stub.h"

#include <message_parcel.h>

#include "devicestatus_common.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessCallbackStub"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {
int32_t BehaviorAwarenessCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    FI_HILOGD("cmd:%{public}u, flags:%{public}d", code, option.GetFlags());
    std::u16string descriptor = BehaviorAwarenessCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        FI_HILOGE("BehaviorAwarenessCallbackStub::OnRemoteRequest failed, descriptor is not matched");
        return E_DEVICESTATUS_GET_SERVICE_FAILED;
    }
    switch (code) {
        case static_cast<int32_t>(BEHAVIOR_AWARENESS_CHANGE): {
            return OnBehaviorAwarenessStub(data);
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t BehaviorAwarenessCallbackStub::OnBehaviorAwarenessStub(MessageParcel &data)
{
    CALL_DEBUG_ENTER;
    PerceptionEventData event;
    READSTRING(data, event.perceptionEventId, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, *reinterpret_cast<int32_t *>(&event.domain), E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, event.confidence, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT64(data, event.generateTime, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READSTRING(data, event.payload, E_DEVICESTATUS_READ_PARCEL_ERROR);
    OnBehaviorAwareness(event);
    return RET_OK;
}
} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
