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

#include "sequenceable_drag_summary_info_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "singleton.h"

#define private public
#include "devicestatus_service.h"
#include "fi_log.h"
#include "message_parcel.h"
#include "sequenceable_content_option.h"
#include "sequenceable_control_event.h"
#include "sequenceable_cooperate_options.h"
#include "sequenceable_drag_data.h"
#include "sequenceable_drag_result.h"
#include "sequenceable_drag_summary_info.h"
#include "sequenceable_drag_visible.h"
#include "sequenceable_page_content.h"
#include "sequenceable_posture_data.h"
#include "sequenceable_preview_animation.h"
#include "sequenceable_preview_style.h"
#include "sequenceable_rotate_window.h"


#undef LOG_TAG
#define LOG_TAG "SequenceableDragSummaryInfoFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t THRESHOLD = 5;
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
const std::string FILTER_INFO { "Undefined filter info" };
const std::string UD_KEY { "Unified data key" };
const std::string EXTRA_INFO { "Undefined extra info" };
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
    InitializationOptions opts;
    opts.size.height = height;
    opts.size.width = width;
    opts.pixelFormat = PixelFormat::BGRA_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.scaleMode = ScaleMode::FIT_TARGET_SIZE;
 
    int32_t colorLen = width * height;
    std::vector<uint32_t> colorPixels(colorLen, DEFAULT_ICON_COLOR);
    std::shared_ptr<PixelMap> pixelMap = PixelMap::Create(colorPixels.data(), colorLen, opts);
    if (pixelMap == nullptr) {
        FI_HILOGE("Create pixelMap failed");
        return nullptr;
    }
    return pixelMap;
}

bool SequenceableDragSummaryInfoFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    MessageParcel datas;
    int32_t width = provider.ConsumeIntegralInRange<int32_t>(1, THRESHOLD);
    int32_t height = provider.ConsumeIntegralInRange<int32_t>(1, THRESHOLD);
    auto pixelMap = CreatePixelMap(width, height);
    if (!pixelMap->Marshalling(datas)) {
        FI_HILOGE("Failed to marshalling pixelMap");
        return false;
    }
    Parcel parcel;
    Msdp::DeviceStatus::DragSummaryInfo dragSummaryInfo = {
        .summarys = {
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()} // test value
        },
        .detailedSummarys = {
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()} // test value
        },
        .summaryFormat = {
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>()}},
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>()}},
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>()}},
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegral<int32_t>()}},
        },
        .version = provider.ConsumeIntegral<int32_t>(),
        .totalSize = provider.ConsumeIntegral<int64_t>()
    };
    SequenceableDragSummaryInfo sequenceableDragSummaryInfo(dragSummaryInfo);
    SequenceableDragSummaryInfo *sequenceableDragSummaryInfo1 = sequenceableDragSummaryInfo.Unmarshalling(parcel);
    if (sequenceableDragSummaryInfo1 != nullptr) {
        sequenceableDragSummaryInfo1->Marshalling(parcel);
    }
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    SequenceableDragSummaryInfoFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
