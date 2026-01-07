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

#include "dragdatapacker_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "singleton.h"

#define private public
#include "drag_data_packer.h"

#include "devicestatus_errors.h"
#include "fi_log.h"
#include "message_parcel.h"


#undef LOG_TAG
#define LOG_TAG "DragDataPackerFuzzTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
    const int32_t RET_OK = 0;
    constexpr size_t THRESHOLD = 5;
    constexpr int32_t RANGEMAX = 10;
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
bool DragDataPackerFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    Parcel datas;
    int32_t shadowinfo_x = provider.ConsumeIntegralInRange<int32_t>(0, THRESHOLD);
    int32_t shadowinfo_y = provider.ConsumeIntegralInRange<int32_t>(0, THRESHOLD);
    int32_t width = provider.ConsumeIntegralInRange<int32_t>(1, THRESHOLD);
    int32_t height = provider.ConsumeIntegralInRange<int32_t>(1, THRESHOLD);
    std::shared_ptr<PixelMap> pixelMap = CreatePixelMap(width, height);
    if (pixelMap == nullptr) {
        FI_HILOGE("Create pixelMap failed");
        return false;
    }
    DragData dragData {
        .buffer = {
            provider.ConsumeIntegral<uint8_t>(),
            provider.ConsumeIntegral<uint8_t>()
        },
        .udKey = provider.ConsumeBytesAsString(RANGEMAX), // test value
        .extraInfo = provider.ConsumeBytesAsString(RANGEMAX), // test value
        .filterInfo = provider.ConsumeBytesAsString(RANGEMAX), // test value
        .sourceType = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
        .dragNum = provider.ConsumeIntegralInRange<int32_t>(1, RANGEMAX),
        .pointerId = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
        .displayX = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
        .displayY = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
        .displayId = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
        .mainWindow = provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX),
        .hasCanceledAnimation = provider.ConsumeBool(),
        .hasCoordinateCorrected = provider.ConsumeBool(),
        .summarys = {{
            provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}},
        .isDragDelay = provider.ConsumeBool(),
        .detailedSummarys = {
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}, // test value
            {provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()} // test value
        },
        .summaryFormat = {
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX)}},
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX)}},
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX)}},
            {provider.ConsumeBytesAsString(10), // test value
                {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX)}},
        },
        .summaryVersion = provider.ConsumeIntegral<int32_t>(),
        .summaryTotalSize = provider.ConsumeIntegral<int64_t>(),
        .summaryTag = provider.ConsumeBytesAsString(RANGEMAX),
        .isSetMaterialFilter = provider.ConsumeBool(),
        .materialFilter = std::make_shared<Rosen::Filter>(),
        .appCallee = provider.ConsumeBytesAsString(RANGEMAX), // test value
        .appCaller = provider.ConsumeBytesAsString(RANGEMAX) // test value
    };
    dragData.shadowInfos.push_back({ pixelMap, shadowinfo_x, shadowinfo_y });
    bool isCross = provider.ConsumeBool();
    int32_t ret = DragDataPacker::MarshallingDetailedSummarys(dragData, datas);
    if (ret == RET_OK) {
        DragDataPacker::UnMarshallingDetailedSummarys(datas, dragData);
    }
    ret = DragDataPacker::MarshallingSummaryExpanding(dragData, datas);
    if (ret == RET_OK) {
        DragDataPacker::UnMarshallingSummaryExpanding(datas, dragData);
    }
    ret = DragDataPacker::MarshallingMaterialId(dragData, datas);
    if (ret == RET_OK) {
        DragDataPacker::UnMarshallingMaterialId(datas, dragData);
    }
    ret = DragDataPacker::MarshallingMaterialFilter(dragData, datas);
    if (ret == RET_OK) {
        DragDataPacker::UnMarshallingMaterialFilter(datas, dragData);
    }
    ret = DragDataPacker::Marshalling(dragData, datas, isCross);
    if (ret == RET_OK) {
        DragDataPacker::UnMarshalling(datas, dragData, isCross);
    }
    DragDataPacker::CheckDragData(dragData);
    ShadowInfo shadowInfo = { pixelMap, shadowinfo_x, shadowinfo_y};
    ret = ShadowPacker::PackUpShadowInfo(shadowInfo, datas, isCross);
    if (ret == RET_OK) {
        ShadowPacker::UnPackShadowInfo(datas, shadowInfo, isCross);
    }
    ShadowPacker::CheckShadowInfo(shadowInfo);
    SummaryMap val = {{
        provider.ConsumeBytesAsString(10), provider.ConsumeIntegral<int64_t>()}};
    ret = SummaryPacker::Marshalling(val, datas);
    if (ret == RET_OK) {
        SummaryPacker::UnMarshalling(datas, val);
    }
    ShadowOffset shadowOffset = {
        .offsetX = provider.ConsumeIntegralInRange<int32_t>(0, THRESHOLD),
        .offsetY = provider.ConsumeIntegralInRange<int32_t>(0, THRESHOLD),
        .width = provider.ConsumeIntegralInRange<int32_t>(0, THRESHOLD),
        .height = provider.ConsumeIntegralInRange<int32_t>(0, THRESHOLD),
    };
    ret = ShadowOffsetPacker::Marshalling(shadowOffset, datas);
    if (ret == RET_OK) {
        ShadowOffsetPacker::UnMarshalling(datas, shadowOffset);
    }
    std::map<std::string, std::vector<int32_t>> vals = {
        {provider.ConsumeBytesAsString(10), // test value
            {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX)}},
        {provider.ConsumeBytesAsString(10), // test value
            {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX)}},
        {provider.ConsumeBytesAsString(10), // test value
            {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX)}},
        {provider.ConsumeBytesAsString(10), // test value
            {provider.ConsumeIntegral<int32_t>(), provider.ConsumeIntegralInRange<int32_t>(0, RANGEMAX)}},
    };
    ret = SummaryFormat::Marshalling(vals, datas);
    if (ret == RET_OK) {
        SummaryFormat::UnMarshalling(datas, vals);
    }
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }
    DragDataPackerFuzzTest(data, size);
    return 0;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS