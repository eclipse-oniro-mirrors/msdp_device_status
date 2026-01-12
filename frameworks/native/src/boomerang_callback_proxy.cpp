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

#include "boomerang_callback_proxy.h"

#include <message_parcel.h>

#include "iremote_object.h"
#include "message_option.h"

#include "boomerang_client.h"
#include "devicestatus_common.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangCallbackProxy"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

template <typename WriteCallbackDataFunc>
void BoomerangCallbackProxy::SendRequestCommon(int32_t requestCode, WriteCallbackDataFunc writeCallbackDataFunc)
{
    sptr<IRemoteObject> remote = Remote();
    CHKPV(remote);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(BoomerangCallbackProxy::GetDescriptor())) {
        FI_HILOGE("Write descriptor failed");
        return;
    }

    writeCallbackDataFunc(data);

    int32_t ret = remote->SendRequest(requestCode, data, reply, option);
    if (ret != RET_OK) {
        FI_HILOGE("SendRequest is failed, error code:%{public}d", ret);
        return;
    }
}

void BoomerangCallbackProxy::OnScreenshotResult(const BoomerangData& screenshotData)
{
    SendRequestCommon(static_cast<int32_t>(IRemoteBoomerangCallback::SCREENSHOT),
        [&screenshotData](MessageParcel& data) {
            WRITEINT32(data, static_cast<int32_t>(screenshotData.type));
            WRITEINT32(data, static_cast<int32_t>(screenshotData.status));
        });
}

void BoomerangCallbackProxy::OnEncodeImageResult(std::shared_ptr<Media::PixelMap> pixelMap)
{
    SendRequestCommon(static_cast<int32_t>(IRemoteBoomerangCallback::ENCODE_IMAGE),
        [pixelMap](MessageParcel& data) {
            pixelMap->Marshalling(data);
        });
}

void BoomerangCallbackProxy::OnNotifyMetadata(const std::string& metadata)
{
    SendRequestCommon(static_cast<int32_t>(IRemoteBoomerangCallback::NOTIFY_METADATA),
        [&metadata](MessageParcel& data) {
            WRITESTRING(data, metadata);
        });
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
