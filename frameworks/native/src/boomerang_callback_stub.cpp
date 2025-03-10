/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "boomerang_callback_stub.h"

#include <message_parcel.h>

#include "devicestatus_common.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangCallbackStub"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

int32_t BoomerangCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    FI_HILOGD("cmd:%{public}u, flags:%{public}d", code, option.GetFlags());
    std::u16string descripter = BoomerangCallbackStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        FI_HILOGE("BoomerangCallbackStub::OnRemoteRequest failed, descriptor mismatch");
        return E_DEVICESTATUS_GET_SERVICE_FAILED;
    }

    switch (code) {
        case static_cast<int32_t>(IRemoteBoomerangCallback::SCREEN_SHOT): {
            return OnScreenshotStub(data);
        }
        case static_cast<int32_t>(IRemoteBoomerangCallback::NOTIFY_METADATA): {
            return OnNotifyMetadataStub(data);
        }
        case static_cast<int32_t>(IRemoteBoomerangCallback::ENCODE_IMAGE): {
            return OnEncodeImageStub(data);
        }
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return RET_OK;
}

int32_t BoomerangCallbackStub::OnScreenshotStub(MessageParcel &data)
{
    CALL_DEBUG_ENTER;
    int32_t type = 0;
    int32_t status = 0;
    READINT32(data, type, E_DEVICESTATUS_READ_PARCEL_ERROR);
    READINT32(data, status, E_DEVICESTATUS_READ_PARCEL_ERROR);
    BoomerangData boomerangData = {
        static_cast<BoomerangType>(type),
        static_cast<BoomerangStatus>(status)
    };
    OnScreenshotResult(boomerangData);
    return RET_OK;
}

int32_t BoomerangCallbackStub::OnEncodeImageStub(MessageParcel &data)
{
    CALL_DEBUG_ENTER;
    Media::PixelMap *rawPixelMap = OHOS::Media::PixelMap::Unmarshalling(data);
    CHKPF(rawPixelMap);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = std::shared_ptr<Media::PixelMap>(rawPixelMap);
    OnEncodeImageResult(pixelMap);
    return RET_OK;
}

int32_t BoomerangCallbackStub::OnNotifyMetadataStub(MessageParcel &data)
{
    CALL_DEBUG_ENTER;
    std::string metadata;
    READSTRING(data, metadata, E_DEVICESTATUS_READ_PARCEL_ERROR);
    OnNotifyMetadata(metadata);
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
