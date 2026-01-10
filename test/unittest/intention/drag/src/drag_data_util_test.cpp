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

#define BUFF_SIZE 100

#include "drag_data_util_test.h"
#include "pointer_event.h"
#include "securec.h"
#include "message_parcel.h"

#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "interaction_manager.h"
#include "stationary_data.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
constexpr int32_t PIXEL_MAP_HEIGHT { 3 };
constexpr int32_t PIXEL_MAP_WIDTH { 3 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t DISPLAY_X { 50 };
constexpr int32_t DISPLAY_ID { 0 };
constexpr int32_t DISPLAY_Y { 50 };
constexpr int32_t INT32_BYTE { 4 };
constexpr bool HAS_CANCELED_ANIMATION { true };
const std::string UD_KEY { "Unified data key" };
const std::string FILTER_INFO { "Undefined filter info" };
const std::string EXTRA_INFO { "Undefined extra info" };
int32_t g_shadowinfo_x { 0 };
int32_t g_shadowinfo_y { 0 };
constexpr int64_t g_recordSize = 20;
} // namespace

void DragDataUtilTest::SetUpTestCase() {}

void DragDataUtilTest::SetUp()
{}

void DragDataUtilTest::TearDown()
{}

void DragDataUtilTest::TearDownTestCase()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

std::shared_ptr<Media::PixelMap> DragDataUtilTest::CreatePixelMap(int32_t width, int32_t height)
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

std::optional<DragData> DragDataUtilTest::CreateDragData(int32_t sourceType,
    int32_t pointerId, int32_t dragNum, bool hasCoordinateCorrected, int32_t shadowNum)
{
    CALL_DEBUG_ENTER;
    DragData dragData;
    for (int32_t i = 0; i < shadowNum; i++) {
        std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
        if (pixelMap == nullptr) {
            FI_HILOGE("pixelMap nullptr");
            return std::nullopt;
        }
        dragData.shadowInfos.push_back({ pixelMap, g_shadowinfo_x, g_shadowinfo_y });
    }
    dragData.buffer = std::vector<uint8_t>(MAX_BUFFER_SIZE, 0);
    dragData.udKey = UD_KEY;
    dragData.sourceType = sourceType;
    dragData.extraInfo = FILTER_INFO;
    dragData.displayId = DISPLAY_ID;
    dragData.pointerId = pointerId;
    dragData.dragNum = dragNum;
    dragData.displayX = DISPLAY_X;
    dragData.displayY = DISPLAY_Y;
    dragData.hasCoordinateCorrected = hasCoordinateCorrected;
    dragData.hasCanceledAnimation = HAS_CANCELED_ANIMATION;
    return dragData;
}
/**
 * @tc.name: DragDataUtilTest1
 * @tc.desc: DragDataUtilTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    dragData.value().summarys = { { udType, recordSize } };
    dragData.value().materialId = 1;
    Parcel parcel;
    bool isCross = true;
    int32_t ret = DragDataUtil::Marshalling(dragData.value(), parcel, isCross);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshalling(parcel, dragDataFromParcel, isCross);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragDataUtilTest2
 * @tc.desc: DragDataUtilTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    dragData.value().detailedSummarys = { { udType, recordSize } };
    dragData.value().materialId = 1;
    Parcel parcel;
    int32_t ret = DragDataUtil::MarshallingDetailedSummarys(dragData.value(), parcel);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshallingDetailedSummarys(parcel, dragDataFromParcel);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragDataUtilTest3
 * @tc.desc: DragDataUtilTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    const std::string udType = "general.message";
    dragData.value().detailedSummarys = { { udType, g_recordSize } };
    dragData.value().summaryFormat = { { udType, { 0, 1 } } };
    dragData.value().summaryVersion = 1;
    dragData.value().summaryTotalSize = 1;
    dragData.value().summaryTag = g_recordSize;
    Parcel parcel;
    int32_t ret = DragDataUtil::MarshallingSummaryExpanding(dragData.value(), parcel);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshallingSummaryExpanding(parcel, dragDataFromParcel);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragDataUtilTest4
 * @tc.desc: DragDataUtilTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest4, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    dragData.value().detailedSummarys = { { udType, recordSize } };
    dragData.value().materialId = 1;
    Parcel parcel;
    int32_t ret = DragDataUtil::MarshallingMaterialId(dragData.value(), parcel);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshallingMaterialId(parcel, dragDataFromParcel);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragDataUtilTest5
 * @tc.desc: DragDataUtilTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest5, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    dragData.value().detailedSummarys = { { udType, recordSize } };
    dragData.value().materialId = 1;
    dragData.value().isSetMaterialFilter = true;
    dragData.value().materialFilter = { nullptr };
    Parcel parcel;
    int32_t ret = DragDataUtil::MarshallingMaterialFilter(dragData.value(), parcel);
    ASSERT_EQ(ret, RET_ERR);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshallingMaterialFilter(parcel, dragDataFromParcel);
    ASSERT_EQ(ret, RET_ERR);
}


/**
 * @tc.name: TestDragDataUtil_Packer
 * @tc.desc: Pack up dragData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest6, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    Parcel parcel;
    int32_t ret = DragDataUtil::Marshalling(dragData.value(), parcel, false);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshalling(parcel, dragDataFromParcel, false);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_EQ(dragData.value(), dragDataFromParcel);
}

/**
 * @tc.name: TestDragDataUtil_Packer_Cross
 * @tc.desc: Pack up dragData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest7, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    Parcel parcel;
    int32_t ret = DragDataUtil::Marshalling(dragData.value(), parcel, true);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshalling(parcel, dragDataFromParcel, true);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_EQ(dragData.value(), dragDataFromParcel);
}


/**
 * @tc.name: DragDataUtilTest8
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest8, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    dragData.value().detailedSummarys = { { udType, recordSize } };
    Parcel parcel;
    int32_t ret = DragDataUtil::MarshallingDetailedSummarys(dragData.value(), parcel);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshallingDetailedSummarys(parcel, dragDataFromParcel);
    ASSERT_EQ(ret, RET_OK);
}
 
/**
 * @tc.name: DragDataUtilTest9
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest9, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    dragData.value().summaryFormat = { { "image", { 0, 1 } } };
    dragData.value().summaryTotalSize = 100;
    Parcel parcel;
    int32_t ret = DragDataUtil::MarshallingSummaryExpanding(dragData.value(), parcel);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshallingSummaryExpanding(parcel, dragDataFromParcel);
    ASSERT_EQ(ret, RET_OK);
}


/**
 * @tc.name: DragDataUtilTest10
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest10, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    dragData.value().detailedSummarys = { { udType, recordSize } };
    dragData.value().materialId = 1;
    Parcel parcel;
    int32_t ret = DragDataUtil::MarshallingMaterialId(dragData.value(), parcel);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshallingMaterialId(parcel, dragDataFromParcel);
    ASSERT_EQ(ret, RET_OK);
}

 
/**
 * @tc.name: DragDataUtilTest11
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDataUtilTest, DragDataUtilTest11, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(MMI::PointerEvent::SOURCE_TYPE_MOUSE, 0, 1, false, 1);
    ASSERT_TRUE(dragData);
    Parcel parcel;
    int32_t ret = DragDataUtil::MarshallingMaterialFilter(dragData.value(), parcel);
    ASSERT_EQ(ret, RET_OK);
    DragData dragDataFromParcel;
    ret = DragDataUtil::UnMarshallingMaterialFilter(parcel, dragDataFromParcel);
    ASSERT_EQ(ret, RET_OK);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
