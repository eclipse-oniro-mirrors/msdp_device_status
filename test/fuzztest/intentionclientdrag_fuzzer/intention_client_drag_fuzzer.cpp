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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <nocopyable.h>

#include "boomerang_callback_stub.h"
#include "devicestatus_callback_stub.h"
#include "intention_client.h"
#include "intention_client_drag_fuzzer.h"
#include "fi_log.h"
#include "message_parcel.h"

#undef LOG_TAG
#define LOG_TAG "IntentionClientDragFuzzTest"

namespace {
    constexpr size_t THRESHOLD = 5;
    constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
    constexpr int32_t INT32_BYTE { 4 };
    constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
    constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
    const std::string FILTER_INFO { "Undefined filter info" };
    const std::string UD_KEY { "Unified data key" };
    const std::string EXTRA_INFO { "Undefined extra info" };
}
using namespace OHOS::Msdp;
std::shared_ptr<OHOS::Media::PixelMap> CreatePixelMap(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    if (width <= 0 || width > MAX_PIXEL_MAP_WIDTH || height <= 0 || height > MAX_PIXEL_MAP_HEIGHT) {
        FI_HILOGE("Invalid size, height:%{public}d, width:%{public}d", height, width);
        return nullptr;
    }
    OHOS::Media::InitializationOptions opts;
    opts.size.height = height;
    opts.size.width = width;
    opts.pixelFormat = OHOS::Media::PixelFormat::BGRA_8888;
    opts.alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.scaleMode = OHOS::Media::ScaleMode::FIT_TARGET_SIZE;

    int32_t colorLen = width * height;
    uint32_t* colorPixels = new (std::nothrow) uint32_t[colorLen];
    if (colorPixels == nullptr) {
        FI_HILOGE("colorPixels is nullptr");
        return nullptr;
    }
    int32_t colorByteCount = colorLen * INT32_BYTE;
    auto ret = memset_s(colorPixels, colorByteCount, DEFAULT_ICON_COLOR, colorByteCount);
    if (ret != EOK) {
        delete[] colorPixels;
        FI_HILOGE("memset_s failed");
        return nullptr;
    }
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = OHOS::Media::PixelMap::Create(colorPixels, colorLen, opts);
    if (pixelMap == nullptr) {
        delete[] colorPixels;
        FI_HILOGE("Create pixelMap failed");
        return nullptr;
    }
    delete[] colorPixels;
    return pixelMap;
}

class BoomerangClientTestCallback : public OHOS::Msdp::DeviceStatus::BoomerangCallbackStub {
public:

private:
    OHOS::Msdp::DeviceStatus::BoomerangData data_;
};

namespace OHOS {

void IntentionClientDragFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    Msdp::DeviceStatus::DragDropResult dragDropResult {
        .hasCustomAnimation = provider.ConsumeBool(),
        .mainWindow = provider.ConsumeIntegral<int32_t>()
    };
    Msdp::DeviceStatus::DragData dragData {
        .buffer = {
            provider.ConsumeIntegral<uint8_t>(),
            provider.ConsumeIntegral<uint8_t>()
        },
        .udKey = provider.ConsumeBytesAsString(10), // test value
        .extraInfo = provider.ConsumeBytesAsString(10), // test value
        .filterInfo = provider.ConsumeBytesAsString(10), // test value
        .sourceType = provider.ConsumeIntegral<int32_t>(),
        .dragNum = provider.ConsumeIntegral<int32_t>(),
        .pointerId = provider.ConsumeIntegral<int32_t>(),
        .displayX = provider.ConsumeIntegral<int32_t>(),
        .displayY = provider.ConsumeIntegral<int32_t>(),
        .displayId = provider.ConsumeIntegral<int32_t>(),
        .mainWindow = provider.ConsumeIntegral<int32_t>(),
        .hasCanceledAnimation = provider.ConsumeBool(),
        .hasCoordinateCorrected = provider.ConsumeBool(),
        .isDragDelay = provider.ConsumeBool(),
        .summaryVersion = provider.ConsumeIntegral<int32_t>(),
        .summaryTotalSize = provider.ConsumeIntegral<int64_t>(),
        .appCallee = provider.ConsumeBytesAsString(10), // test value
        .appCaller = provider.ConsumeBytesAsString(10) // test value
    };
    int32_t width = provider.ConsumeIntegral<int32_t>();
    int32_t height = provider.ConsumeIntegral<int32_t>();
    Msdp::DeviceStatus::ShadowInfo shadowInfo {
        .pixelMap = CreatePixelMap(width, height),
        .x = provider.ConsumeIntegral<int32_t>(),
        .y = provider.ConsumeIntegral<int32_t>()
    };
    bool visible = provider.ConsumeBool();
    bool isForce = provider.ConsumeBool();
    std::shared_ptr<Rosen::RSTransaction> rsTransaction = nullptr;
    std::string animationInfo = provider.ConsumeBytesAsString(10);
    INTENTION_CLIENT->StartDrag(dragData);
    INTENTION_CLIENT->GetDragData(dragData);
    INTENTION_CLIENT->StopDrag(dragDropResult);
    INTENTION_CLIENT->EnableInternalDropAnimation(animationInfo);
    if (shadowInfo.pixelMap != nullptr) {
        INTENTION_CLIENT->UpdateShadowPic(shadowInfo);
    }
    INTENTION_CLIENT->SetDragWindowVisible(visible, isForce, rsTransaction);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::IntentionClientDragFuzzTest(data, size);
    return 0;
}
