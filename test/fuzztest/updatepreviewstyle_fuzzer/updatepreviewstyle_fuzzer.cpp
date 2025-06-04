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

#include "updatepreviewstyle_fuzzer.h"

#include "singleton.h"

#define private public
#include "devicestatus_service.h"
#include "fi_log.h"
#include "message_parcel.h"
#include "preview_style_packer.h"

#undef LOG_TAG
#define LOG_TAG "UpdatePreviewStyleFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

namespace OHOS {
constexpr uint32_t FOREGROUND_COLOR_IN { 0x33FF0000 };

bool UpdatePreviewStyleFuzzTest(const uint8_t* data, size_t size)
{
    const std::u16string FORMMGR_DEVICE_TOKEN { u"ohos.msdp.Idevicestatus" };
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN)) {
        FI_HILOGE("Failed to write interface token");
        return false;
    }

    PreviewStyle previewStyle;
    previewStyle.types = { PreviewType::FOREGROUND_COLOR };
    previewStyle.foregroundColor = FOREGROUND_COLOR_IN;
    if (PreviewStylePacker::Marshalling(previewStyle, datas) != RET_OK) {
        FI_HILOGE("Marshalling previewStyle failed");
        return false;
    }
    if (!datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        FI_HILOGE("Failed to write buffer");
        return false;
    }
    MessageOption option;
    MessageParcel reply;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::IIntentionIpcCode::COMMAND_UPDATE_PREVIEW_STYLE), datas, reply, option);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::UpdatePreviewStyleFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
