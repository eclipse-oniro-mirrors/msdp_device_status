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

#include "boomerangencodeimage_fuzzer.h"

#include "singleton.h"

#define private public
#include "boomerang_callback_stub.h"
#include "devicestatus_service.h"
#include "fi_log.h"
#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "BoomerangEncodeImageFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class BoomerangClientTestCallback : public BoomerangCallbackStub {
    public:
    private:
    BoomerangData data_;
};
namespace OHOS {
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t PIXEL_MAP_WIDTH { 40 };
constexpr int32_t PIXEL_MAP_HEIGHT { 40 };
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };

std::shared_ptr<Media::PixelMap> CreatePixelMap(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    if (width <= 0 || width > MAX_PIXEL_MAP_WIDTH || height <= 0 || height > MAX_PIXEL_MAP_HEIGHT) {
        FI_HILOGE("Invalid size, width:%{public}d, height:%{public}d", width, height);
        return nullptr;
    }
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = Media::PixelFormat::BGRA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.scaleMode = Media::ScaleMode::FIT_TARGET_SIZE;

    int32_t colorLen = width * height;
    std::unique_ptr<uint32_t[]> colors = std::make_unique<uint32_t[]>(colorLen);
    int32_t colorByteCount = colorLen * sizeof(uint32_t);
    auto ret = memset_s(colors.get(), colorByteCount, DEFAULT_ICON_COLOR, colorByteCount);
    if (ret != EOK) {
        FI_HILOGE("memset_s failed");
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(colors.get(), colorLen, opts);
    if (pixelMap == nullptr) {
        FI_HILOGE("Create pixelMap failed");
        return nullptr;
    }
    return pixelMap;
}

bool BoomerangEncodeImageFuzzTest(const uint8_t* data, size_t size)
{
    const std::u16string FORMMGR_DEVICE_TOKEN { u"ohos.msdp.Idevicestatus" };
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN)) {
        FI_HILOGE("Write failed");
        return false;
    }
    auto pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    if (!pixelMap->Marshalling(datas)) {
        FI_HILOGE("Failed to marshalling pixelMap");
        return false;
    }
    sptr<IRemoteBoomerangCallback> callback = new (std::nothrow) BoomerangClientTestCallback();
    if (!datas.WriteBuffer(data, size) || !datas.RewindRead(0)
        || !datas.WriteParcelable(pixelMap.get()) || !datas.WriteRemoteObject(callback->AsObject())) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::IIntentionIpcCode::COMMAND_BOOMERANG_ENCODE_IMAGE), datas, reply, option);
    return true;
}

bool BoomerangEncodeImageFuzzTest1(const uint8_t* data, size_t size)
{
    const std::u16string FORMMGR_DEVICE_TOKEN { u"ohos.msdp.Idevicestatus" };
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_DEVICE_TOKEN)) {
        FI_HILOGE("Write failed");
        return false;
    }
    auto pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    if (!pixelMap->Marshalling(datas)) {
        FI_HILOGE("Failed to marshalling pixelMap");
        return false;
    }
    if (!datas.WriteBuffer(data, size) || !datas.RewindRead(0) || !datas.WriteParcelable(pixelMap.get())) {
        FI_HILOGE("Write failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    DelayedSingleton<DeviceStatusService>::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(Msdp::IIntentionIpcCode::COMMAND_BOOMERANG_ENCODE_IMAGE), datas, reply, option);
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::BoomerangEncodeImageFuzzTest(data, size);
    OHOS::BoomerangEncodeImageFuzzTest1(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
