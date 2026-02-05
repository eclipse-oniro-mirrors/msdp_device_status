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

#include "on_screen_callback_stub.h"

#include <message_parcel.h>

#include "devicestatus_common.h"
#include "devicestatus_define.h"
#ifndef DEVICE_STATUS_PHONE_STANDARD_LITE
#include "sequenceable_util.h"
#endif

#undef LOG_TAG
#define LOG_TAG  "OnScreenCallbackStub"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
int32_t OnScreenCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    FI_HILOGD("cmd:%{public}u, flags:%{public}d", code, option.GetFlags());
    std::u16string descriptor = OnScreenCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        FI_HILOGE("OnScreenCallbackStub::OnRemoteRequest failed, descriptor is not matched");
        return E_DEVICESTATUS_GET_SERVICE_FAILED;
    }
    switch (code) {
        case static_cast<int32_t>(ON_SCREEN_CHANGE): {
            return OnScreenChangeStub(data);
        }
#ifndef DEVICE_STATUS_PHONE_STANDARD_LITE
        case static_cast<int32_t>(ON_SCREEN_AWAREENSS): {
            return OnScreenAwarenessStub(data);
        }
#endif
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return OnScreenChangeStub(data);
}

int32_t OnScreenCallbackStub::OnScreenChangeStub(MessageParcel &data)
{
    CALL_DEBUG_ENTER;
    std::string metadata;
    READSTRING(data, metadata, E_DEVICESTATUS_READ_PARCEL_ERROR);
    OnScreenChange(metadata);
    return RET_OK;
}

#ifndef DEVICE_STATUS_PHONE_STANDARD_LITE
int32_t OnScreenCallbackStub::OnScreenAwarenessStub(MessageParcel &data)
{
    CALL_DEBUG_ENTER;
    OnscreenAwarenessInfo info;
    READINT32(data, info.resultCode, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT64(data, info.timestamp, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READSTRING(data, info.bundleName, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READSTRING(data, info.appID, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, info.appIndex, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READSTRING(data, info.pageId, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READSTRING(data, info.sampleId, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, info.collectStrategy, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT64(data, info.displayId, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, info.windowId, E_DEVICESTATUS_READ_PARCEL_ERROR);
    int32_t size;
    READINT32(data, size, E_DEVICESTATUS_READ_PARCEL_ERROR);
    for (int32_t i = 0; i < size; i++) {
        OnscreenEntityInfo entity;
        READSTRING(data, entity.entityName, E_DEVICESTATUS_READ_PARCEL_ERROR);
        SequenceableUtil::Unmarshalling(data, entity.entityInfo);
        info.entityInfo.push_back(entity);
    }
    OnScreenAwareness(info);
    return RET_OK;
}
#endif
} // namespace OnScreen
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS