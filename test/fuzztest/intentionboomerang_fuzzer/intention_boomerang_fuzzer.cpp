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
#include "fi_log.h"
#include "intention_client.h"
#include "intention_boomerang_fuzzer.h"

#undef LOG_TAG
#define LOG_TAG "IntentionBoomerangFuzzTest"

namespace {
    constexpr size_t THRESHOLD = 5;
    constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
    constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
    constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
}
using namespace OHOS::Media;
using namespace OHOS::Msdp;
std::shared_ptr<OHOS::Media::PixelMap> CreatePixelMap(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    if (width <= 0 || width > MAX_PIXEL_MAP_WIDTH || height <= 0 || height > MAX_PIXEL_MAP_HEIGHT) {
        FI_HILOGE("Invalid size, height:%{public}d, width:%{public}d", height, width);
        return nullptr;
    }
    if (width > 0 && height > INT32_MAX / width) {
        FI_HILOGE("Integer overflow detected");
        return nullptr;
    }
    OHOS::Media::InitializationOptions opts;
    opts.size.height = height;
    opts.size.width = width;
    opts.pixelFormat = OHOS::Media::PixelFormat::BGRA_8888;
    opts.alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.scaleMode = OHOS::Media::ScaleMode::FIT_TARGET_SIZE;

    int32_t colorLen = width * height;
    std::vector<uint32_t> colorPixels(colorLen, DEFAULT_ICON_COLOR);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = OHOS::Media::PixelMap::Create(colorPixels.data(), colorLen, opts);
    if (pixelMap == nullptr) {
        FI_HILOGE("Create pixelMap failed");
        return nullptr;
    }
    return pixelMap;
}

class BoomerangClientTestCallback : public OHOS::Msdp::DeviceStatus::BoomerangCallbackStub {
public:

private:
    OHOS::Msdp::DeviceStatus::BoomerangData data_;
};

namespace OHOS {

void IntentionBoomerangFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t type = provider.ConsumeIntegral<int32_t>();
    const std::string bundleName = provider.ConsumeBytesAsString(THRESHOLD);
    sptr<Msdp::DeviceStatus::IRemoteBoomerangCallback> callback = nullptr;
    std::string metadata = provider.ConsumeBytesAsString(THRESHOLD);
    int32_t width = provider.ConsumeIntegralInRange<int32_t>(0, THRESHOLD);
    int32_t height = provider.ConsumeIntegralInRange<int32_t>(0, THRESHOLD);
    std::shared_ptr<PixelMap> pixelMap = CreatePixelMap(width, height);
    INTENTION_CLIENT->SubscribeCallback(static_cast<Msdp::DeviceStatus::BoomerangType>(type), bundleName, callback);
    INTENTION_CLIENT->UnsubscribeCallback(static_cast<Msdp::DeviceStatus::BoomerangType>(type), bundleName, callback);
    INTENTION_CLIENT->NotifyMetadataBindingEvent(bundleName, callback);
    INTENTION_CLIENT->SubmitMetadata(metadata);
    if (pixelMap != nullptr) {
        INTENTION_CLIENT->BoomerangEncodeImage(pixelMap, metadata, callback);
        INTENTION_CLIENT->BoomerangDecodeImage(pixelMap, callback);
    }
}

} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }
    /* Run your code on data */
    OHOS::IntentionBoomerangFuzzTest(data, size);
    return 0;
}
