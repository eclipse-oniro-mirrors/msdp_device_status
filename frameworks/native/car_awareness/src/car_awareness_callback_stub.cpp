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

#include "car_awareness_callback_stub.h"

#include "devicestatus_common.h"
#include "fi_log.h"

#undef LOG_TAG
#define LOG_TAG "CarAwarenessCbStub"

namespace OHOS {
namespace Msdp {
namespace {
    constexpr int32_t TYPE_PUBLIC_MIN = 101;
    constexpr int32_t TYPE_PUBLIC_MAX = 103;

    constexpr int32_t TYPE_SYSTEM_MIN = 201;
    constexpr int32_t TYPE_SYSTEM_MAX = 205;

    constexpr int32_t MAX_DATA_LEN = 1024 * 1024;
}

int32_t CarAwarenessCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    FI_HILOGD("Cmd:%{public}d,flags:%{public}d", code, option.GetFlags());
    std::u16string descripter = CarAwarenessCallbackStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        FI_HILOGE("descriptor mismatch");
        return DeviceStatus::E_DEVICESTATUS_GET_SERVICE_FAILED;
    }

    switch (code) {
        case static_cast<int32_t>(ICarAwarenessCallback::EVENT_CHANGE): {
            return OnEventChangeStub(data);
        }
        default: {
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
    return DeviceStatus::DEVICESTATUS_OK;
}

int32_t CarAwarenessCallbackStub::OnEventChangeStub(MessageParcel &data)
{
    FI_HILOGD("Enter");
    CarAwarenessEvent event;
    READINT32(data, event.type, DeviceStatus::E_DEVICESTATUS_READ_PARCEL_ERROR);
    if (!IsValidEventType(event.type)) {
        return DeviceStatus::DEVICESTATUS_FAILED;
    }
    READSTRING(data, event.eventData, DeviceStatus::E_DEVICESTATUS_READ_PARCEL_ERROR);
    if (event.eventData.size() > MAX_DATA_LEN) {
        FI_HILOGE("event too long");
        return DeviceStatus::E_DEVICESTATUS_READ_PARCEL_ERROR;
    }
    FI_HILOGI("Type: %{public}d", event.type);
    OnAwarenessEvent(event);
    FI_HILOGD("Exit");
    return DeviceStatus::DEVICESTATUS_OK;
}

bool CarAwarenessCallbackStub::IsValidEventType(const int32_t type)
{
    if ((type >= TYPE_PUBLIC_MIN && type <= TYPE_PUBLIC_MAX) ||
        (type >= TYPE_SYSTEM_MIN && type <= TYPE_SYSTEM_MAX)) {
        return true;
    }
    FI_HILOGE("Not valid type");
    return false;
}
} // namespace Msdp
} // namespace OHOS