/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "dragdatautil_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <fuzzer/FuzzedDataProvider.h>

#include "drag_data.h"
#include "drag_data_util.h"
#include "drag_data_packer.h"
#include "parcel.h"
#include "pixel_map.h"

namespace {
    constexpr size_t THRESHOLD = 4;
    constexpr int32_t MAX_PIXEL_MAP_WIDTH = 100;
    constexpr int32_t MAX_PIXEL_MAP_HEIGHT = 100;
    constexpr int32_t MAX_STRING_LENGTH = 50;
    constexpr int32_t MAX_SHADOW_NUM = 3;
    constexpr int32_t MAX_SUMMARY_ENTRIES = 10;
    constexpr uint32_t DEFAULT_PIXEL_COLOR = 0xFF0000FF;
    constexpr int32_t MAX_DRAG_NUM = 10;
    constexpr int32_t DRAG_NUM_MIN = -10;
    constexpr int32_t DRAG_NUM_MAX = 10;
    constexpr int32_t MAX_DISPLAY_COORD = 1000;
    constexpr size_t MAX_KEY_LENGTH = 20;
    constexpr int32_t MAX_VECTOR_SIZE = 5;
    constexpr uint32_t MAX_TEST_CASE = 6;
}

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

std::shared_ptr<Media::PixelMap> CreateFuzzPixelMap(FuzzedDataProvider &provider)
{
    int32_t width = provider.ConsumeIntegralInRange<int32_t>(1, MAX_PIXEL_MAP_WIDTH);
    int32_t height = provider.ConsumeIntegralInRange<int32_t>(1, MAX_PIXEL_MAP_HEIGHT);

    if (width <= 0 || height <= 0) {
        return nullptr;
    }

    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = Media::PixelFormat::BGRA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;

    int32_t colorLen = width * height;
    if (colorLen <= 0 || colorLen > MAX_PIXEL_MAP_WIDTH * MAX_PIXEL_MAP_HEIGHT) {
        return nullptr;
    }

    std::vector<uint32_t> colorPixels(colorLen, DEFAULT_PIXEL_COLOR);
    return Media::PixelMap::Create(colorPixels.data(), colorLen, opts);
}

void FuzzDragDataUtilMarshalling(FuzzedDataProvider &provider)
{
    DragData dragData;

    int32_t shadowNum = provider.ConsumeIntegralInRange<int32_t>(1, MAX_SHADOW_NUM);
    for (int32_t i = 0; i < shadowNum; ++i) {
        ShadowInfo shadowInfo;
        shadowInfo.pixelMap = CreateFuzzPixelMap(provider);
        if (shadowInfo.pixelMap) {
            shadowInfo.x = provider.ConsumeIntegral<int32_t>();
            shadowInfo.y = provider.ConsumeIntegral<int32_t>();
            dragData.shadowInfos.push_back(shadowInfo);
        }
    }

    size_t bufferSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_BUFFER_SIZE);
    dragData.buffer = provider.ConsumeBytes<uint8_t>(bufferSize);
    
    dragData.udKey = provider.ConsumeBytesAsString(
        provider.ConsumeIntegralInRange<size_t>(0, MAX_STRING_LENGTH));
    dragData.extraInfo = provider.ConsumeBytesAsString(
        provider.ConsumeIntegralInRange<size_t>(0, MAX_STRING_LENGTH));
    dragData.filterInfo = provider.ConsumeBytesAsString(
        provider.ConsumeIntegralInRange<size_t>(0, MAX_STRING_LENGTH));
    
    dragData.sourceType = provider.ConsumeIntegral<int32_t>();
    dragData.dragNum = provider.ConsumeIntegralInRange<int32_t>(1, MAX_DRAG_NUM);
    dragData.pointerId = provider.ConsumeIntegral<int32_t>();
    dragData.displayX = provider.ConsumeIntegralInRange<int32_t>(0, MAX_DISPLAY_COORD);
    dragData.displayY = provider.ConsumeIntegralInRange<int32_t>(0, MAX_DISPLAY_COORD);
    dragData.displayId = provider.ConsumeIntegral<int32_t>();
    dragData.mainWindow = provider.ConsumeIntegral<int32_t>();
    dragData.hasCanceledAnimation = provider.ConsumeBool();
    dragData.hasCoordinateCorrected = provider.ConsumeBool();
    dragData.isDragDelay = provider.ConsumeBool();

    int32_t summaryEntries = provider.ConsumeIntegralInRange<int32_t>(0, MAX_SUMMARY_ENTRIES);
    for (int32_t i = 0; i < summaryEntries; ++i) {
        std::string key = provider.ConsumeBytesAsString(
            provider.ConsumeIntegralInRange<size_t>(1, MAX_KEY_LENGTH));
        int64_t value = provider.ConsumeIntegral<int64_t>();
        if (!key.empty()) {
            dragData.summarys[key] = value;
        }
    }

    Parcel parcel;
    bool isCross = provider.ConsumeBool();
    DragDataUtil::Marshalling(dragData, parcel, isCross);

    DragData dragDataOut;
    DragDataUtil::UnMarshalling(parcel, dragDataOut, isCross);
}

void FuzzDragDataUtilDetailedSummarys(FuzzedDataProvider &provider)
{
    DragData dragData;

    int32_t entries = provider.ConsumeIntegralInRange<int32_t>(0, MAX_SUMMARY_ENTRIES);
    for (int32_t i = 0; i < entries; ++i) {
        std::string key = provider.ConsumeBytesAsString(
            provider.ConsumeIntegralInRange<size_t>(1, MAX_KEY_LENGTH));
        int64_t value = provider.ConsumeIntegral<int64_t>();
        if (!key.empty()) {
            dragData.detailedSummarys[key] = value;
        }
    }

    Parcel parcel;
    DragDataUtil::MarshallingDetailedSummarys(dragData, parcel);

    DragData dragDataOut;
    DragDataUtil::UnMarshallingDetailedSummarys(parcel, dragDataOut);
}

void FuzzDragDataUtilSummaryExpanding(FuzzedDataProvider &provider)
{
    DragData dragData;

    int32_t formatEntries = provider.ConsumeIntegralInRange<int32_t>(0, MAX_SUMMARY_ENTRIES);
    for (int32_t i = 0; i < formatEntries; ++i) {
        std::string key = provider.ConsumeBytesAsString(
            provider.ConsumeIntegralInRange<size_t>(1, MAX_KEY_LENGTH));
        int32_t vecSize = provider.ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        std::vector<int32_t> values;
        for (int32_t j = 0; j < vecSize; ++j) {
            values.push_back(provider.ConsumeIntegral<int32_t>());
        }
        if (!key.empty()) {
            dragData.summaryFormat[key] = values;
        }
    }

    dragData.summaryVersion = provider.ConsumeIntegral<int32_t>();
    dragData.summaryTotalSize = provider.ConsumeIntegral<int64_t>();
    dragData.summaryTag = provider.ConsumeBytesAsString(
        provider.ConsumeIntegralInRange<size_t>(0, MAX_STRING_LENGTH));

    Parcel parcel;
    DragDataUtil::MarshallingSummaryExpanding(dragData, parcel);

    DragData dragDataOut;
    DragDataUtil::UnMarshallingSummaryExpanding(parcel, dragDataOut);
}

void FuzzDragDataUtilMaterialId(FuzzedDataProvider &provider)
{
    DragData dragData;
    dragData.materialId = provider.ConsumeIntegral<int32_t>();

    Parcel parcel;
    DragDataUtil::MarshallingMaterialId(dragData, parcel);

    DragData dragDataOut;
    DragDataUtil::UnMarshallingMaterialId(parcel, dragDataOut);
}

void FuzzDragDataUtilMaterialFilter(FuzzedDataProvider &provider)
{
    DragData dragData;
    dragData.isSetMaterialFilter = provider.ConsumeBool();

    Parcel parcel;
    DragDataUtil::MarshallingMaterialFilter(dragData, parcel);

    DragData dragDataOut;
    DragDataUtil::UnMarshallingMaterialFilter(parcel, dragDataOut);
}

void FuzzDragDataPackerCheckDragData(FuzzedDataProvider &provider)
{
    DragData dragData;

    int32_t shadowNum = provider.ConsumeIntegralInRange<int32_t>(0, MAX_SHADOW_NUM);
    for (int32_t i = 0; i < shadowNum; ++i) {
        ShadowInfo shadowInfo;
        shadowInfo.pixelMap = CreateFuzzPixelMap(provider);
        if (shadowInfo.pixelMap) {
            shadowInfo.x = provider.ConsumeIntegralInRange<int32_t>(
                -shadowInfo.pixelMap->GetWidth(), 0);
            shadowInfo.y = provider.ConsumeIntegralInRange<int32_t>(
                -shadowInfo.pixelMap->GetHeight(), 0);
            dragData.shadowInfos.push_back(shadowInfo);
        }
    }

    dragData.dragNum = provider.ConsumeIntegralInRange<int32_t>(DRAG_NUM_MIN, DRAG_NUM_MAX);
    size_t bufferSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_BUFFER_SIZE * 2);
    dragData.buffer = provider.ConsumeBytes<uint8_t>(bufferSize);
    dragData.displayX = provider.ConsumeIntegral<int32_t>();
    dragData.displayY = provider.ConsumeIntegral<int32_t>();

    DragDataPacker::CheckDragData(dragData);
}

void FuzzShadowOffsetPacker(FuzzedDataProvider &provider)
{
    ShadowOffset shadowOffset;
    shadowOffset.offsetX = provider.ConsumeIntegral<int32_t>();
    shadowOffset.offsetY = provider.ConsumeIntegral<int32_t>();
    shadowOffset.width = provider.ConsumeIntegral<int32_t>();
    shadowOffset.height = provider.ConsumeIntegral<int32_t>();

    Parcel parcel;
    ShadowOffsetPacker::Marshalling(shadowOffset, parcel);

    ShadowOffset shadowOffsetOut;
    ShadowOffsetPacker::UnMarshalling(parcel, shadowOffsetOut);
}

bool DragDataUtilFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t testCase = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_TEST_CASE);

    switch (testCase) {
        case 0:
            FuzzDragDataUtilMarshalling(provider);
            break;
        case 1:
            FuzzDragDataUtilDetailedSummarys(provider);
            break;
        case 2:
            FuzzDragDataUtilSummaryExpanding(provider);
            break;
        case 3:
            FuzzDragDataUtilMaterialId(provider);
            break;
        case 4:
            FuzzDragDataUtilMaterialFilter(provider);
            break;
        case 5:
            FuzzDragDataPackerCheckDragData(provider);
            break;
        case 6:
            FuzzShadowOffsetPacker(provider);
            break;
        default:
            break;
    }

    return true;
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < THRESHOLD) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::Msdp::DeviceStatus::DragDataUtilFuzzTest(provider);
    return 0;
}

