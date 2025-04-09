/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "drag_data_manager_test.h"

#include <ipc_skeleton.h>

#include "pointer_event.h"
#include "securec.h"

#include "devicestatus_define.h"
#define private public
#include "drag_drawing.h"

#undef LOG_TAG
#define LOG_TAG "DragDataManagerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t PIXEL_MAP_WIDTH { 300 };
constexpr int32_t PIXEL_MAP_HEIGHT { 300 };
constexpr int32_t POINTER_ID { 0 };
constexpr int32_t DISPLAY_ID { 0 };
constexpr int32_t SHADOWINFO_X { 10 };
constexpr int32_t SHADOWINFO_Y { 10 };
constexpr int32_t DISPLAY_X { 50 };
constexpr int32_t DISPLAY_Y { 50 };
constexpr int32_t DRAG_NUM_ONE { 1 };
constexpr bool HAS_CANCELED_ANIMATION { true };
constexpr bool DRAG_WINDOW_VISIBLE { true };
constexpr int32_t INT32_BYTE { 4 };
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
const std::string UD_KEY { "Unified data key" };
}
void DragDataManagerTest::SetUpTestCase() {}

void DragDataManagerTest::TearDownTestCase() {}

void DragDataManagerTest::SetUp() {}

void DragDataManagerTest::TearDown() {}

std::shared_ptr<Media::PixelMap> DragDataManagerTest::CreatePixelMap(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    if (width <= 0 || width > MAX_PIXEL_MAP_WIDTH || height <= 0 || height > MAX_PIXEL_MAP_HEIGHT) {
        FI_HILOGE("Invalid size, height:%{public}d, width:%{public}d}", height, width);
        return nullptr;
    }
    Media::InitializationOptions options;
    options.size.width = width;
    options.size.height = height;
    options.pixelFormat = Media::PixelFormat::BGRA_8888;
    options.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    options.scaleMode = Media::ScaleMode::FIT_TARGET_SIZE;

    int32_t colorLen = width * height;
    uint32_t *colorPixels = new (std::nothrow) uint32_t[colorLen];
    if (colorPixels == nullptr) {
        FI_HILOGE("colorPixels is nullptr");
        return nullptr;
    }
    int32_t colorByteCount = colorLen * INT32_BYTE;
    auto ret = memset_s(colorPixels, colorByteCount, DEFAULT_ICON_COLOR, colorByteCount);
    if (ret != EOK) {
        FI_HILOGE("Call memset_s was a failure");
        delete[] colorPixels;
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(colorPixels, colorLen, options);
    if (pixelMap == nullptr) {
        FI_HILOGE("Failed to create pixelMap");
        delete[] colorPixels;
        return nullptr;
    }
    delete[] colorPixels;
    return pixelMap;
}

std::optional<DragData> DragDataManagerTest::CreateDragData(int32_t sourceType,
    int32_t pointerId, int32_t dragNum)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    if (pixelMap == nullptr) {
        FI_HILOGE("Create pixelmap failed");
        return std::nullopt;
    }

    DragData dragData;
    dragData.shadowInfos.push_back({ pixelMap, 0, 0 });
    dragData.buffer = std::vector<uint8_t>(MAX_BUFFER_SIZE, 0);
    dragData.udKey = UD_KEY;
    dragData.sourceType = sourceType;
    dragData.pointerId = pointerId;
    dragData.dragNum = dragNum;
    dragData.displayX = DISPLAY_X;
    dragData.displayY = DISPLAY_Y;
    dragData.displayId = DISPLAY_ID;
    dragData.hasCanceledAnimation = HAS_CANCELED_ANIMATION;
    return dragData;
}

namespace {
/**
 * @tc.name: DragDataManagerTest001
 * @tc.desc: test normal SetDragStyle and GetDragStyle in devicestatus
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::DEFAULT);
    EXPECT_TRUE(DRAG_DATA_MGR.GetDragStyle() == DragCursorStyle::DEFAULT);

    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::FORBIDDEN);
    EXPECT_TRUE(DRAG_DATA_MGR.GetDragStyle() == DragCursorStyle::FORBIDDEN);

    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::COPY);
    EXPECT_TRUE(DRAG_DATA_MGR.GetDragStyle() == DragCursorStyle::COPY);

    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::MOVE);
    EXPECT_TRUE(DRAG_DATA_MGR.GetDragStyle() == DragCursorStyle::MOVE);
}

/**
 * @tc.name: DragDataManagerTest002
 * @tc.desc: test abnormal SetDragStyle and GetDragStyle in devicestatus
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::DEFAULT);
    EXPECT_FALSE(DRAG_DATA_MGR.GetDragStyle() != DragCursorStyle::DEFAULT);

    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::FORBIDDEN);
    EXPECT_FALSE(DRAG_DATA_MGR.GetDragStyle() != DragCursorStyle::FORBIDDEN);

    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::COPY);
    EXPECT_FALSE(DRAG_DATA_MGR.GetDragStyle() != DragCursorStyle::COPY);

    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::MOVE);
    EXPECT_FALSE(DRAG_DATA_MGR.GetDragStyle() != DragCursorStyle::MOVE);
}

/**
 * @tc.name: DragDataManagerTest003
 * @tc.desc: test normal get devicestatus data in ipc
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t targetTid = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    DRAG_DATA_MGR.SetTargetTid(targetTid);
    EXPECT_TRUE(targetTid == DRAG_DATA_MGR.GetTargetTid());

    int32_t targetPid = IPCSkeleton::GetCallingPid();
    DRAG_DATA_MGR.SetTargetPid(targetPid);
    EXPECT_TRUE(targetPid == DRAG_DATA_MGR.GetTargetPid());
    float dragOriginDpi = DRAG_DATA_MGR.GetDragOriginDpi();
    EXPECT_TRUE(dragOriginDpi == 0.0f);
}

/**
 * @tc.name: DragDataManagerTest004
 * @tc.desc: test abnormal get devicestatus data in ipc
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest004, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t targetTid = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    DRAG_DATA_MGR.SetTargetTid(targetTid);
    EXPECT_FALSE(targetTid != DRAG_DATA_MGR.GetTargetTid());

    int32_t targetPid = IPCSkeleton::GetCallingPid();
    DRAG_DATA_MGR.SetTargetPid(targetPid);
    EXPECT_FALSE(targetPid != DRAG_DATA_MGR.GetTargetPid());
}

/**
 * @tc.name: DragDataManagerTest005
 * @tc.desc: test get devicestatus drag data
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest005, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ShadowOffset defaultShadowOffset = {
        .offsetX = SHADOWINFO_X,
        .offsetY = SHADOWINFO_Y,
        .width = PIXEL_MAP_WIDTH,
        .height = PIXEL_MAP_HEIGHT
    };
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    EXPECT_FALSE(pixelMap == nullptr);
    DragData dragData;
    dragData.shadowInfos.push_back({ pixelMap, SHADOWINFO_X, SHADOWINFO_Y });
    dragData.displayX = DISPLAY_X;
    dragData.displayY = DISPLAY_Y;
    DRAG_DATA_MGR.Init(dragData);
    DragData dragDataFirst = DRAG_DATA_MGR.GetDragData();
    EXPECT_TRUE(dragDataFirst.displayX == DISPLAY_X);
    EXPECT_TRUE(dragDataFirst.displayY == DISPLAY_Y);
    ShadowOffset shadowOffset;
    DRAG_DATA_MGR.GetShadowOffset(shadowOffset);
    EXPECT_EQ(defaultShadowOffset, shadowOffset);
    DRAG_DATA_MGR.ResetDragData();
    DragData dragDataSecond = DRAG_DATA_MGR.GetDragData();
    EXPECT_TRUE(dragDataSecond.displayX == -1);
    EXPECT_TRUE(dragDataSecond.displayY == -1);
}

/**
 * @tc.name: DragDataManagerTest006
 * @tc.desc: test pixelMap is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest006, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    dragData.shadowInfos.push_back({ nullptr, SHADOWINFO_X, SHADOWINFO_Y });
    dragData.displayX = DISPLAY_X;
    dragData.displayY = DISPLAY_Y;
    DRAG_DATA_MGR.Init(dragData);
    ShadowOffset shadowOffset;
    auto ret = DRAG_DATA_MGR.GetShadowOffset(shadowOffset);
    EXPECT_TRUE(ret == -1);
}

/**
 * @tc.name: DragDataManagerTest007
 * @tc.desc: abnormal test DragDrawing initialization
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest007, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHPAD, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData == std::nullopt);
    DragDrawing dragDrawing;
    dragDrawing.UpdateDragWindowState(DRAG_WINDOW_VISIBLE);
    dragDrawing.InitDrawingInfo(dragData.value());
    int32_t ret = dragDrawing.Init(dragData.value(), nullptr);
    EXPECT_EQ(ret, INIT_CANCEL);
    dragDrawing.UpdateDrawingState();
    ret = dragDrawing.Init(dragData.value(), nullptr);
    EXPECT_EQ(ret, INIT_FAIL);
    dragDrawing.DestroyDragWindow();
    dragDrawing.UpdateDragWindowState(!DRAG_WINDOW_VISIBLE);
}

/**
 * @tc.name: DragDataManagerTest008
 * @tc.desc: abnormal test DragDrawing initialization
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest008, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHPAD, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData == std::nullopt);
    DragDrawing dragDrawing;
    dragDrawing.UpdateDragWindowState(DRAG_WINDOW_VISIBLE);
    int32_t ret = dragDrawing.Init(dragData.value(), nullptr);
    EXPECT_EQ(ret, INIT_FAIL);
    dragDrawing.DestroyDragWindow();
    dragDrawing.UpdateDragWindowState(!DRAG_WINDOW_VISIBLE);
}

/**
 * @tc.name: DragDataManagerTest009
 * @tc.desc: normal test DragDrawing initialization
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest009, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData == std::nullopt);
    DragDrawing dragDrawing;
    int32_t ret = dragDrawing.Init(dragData.value(), nullptr);
    dragDrawing.UpdateDragWindowState(DRAG_WINDOW_VISIBLE);
    EXPECT_EQ(ret, INIT_SUCCESS);
    dragDrawing.DestroyDragWindow();
    dragDrawing.EraseMouseIcon();
    dragDrawing.UpdateDragWindowState(!DRAG_WINDOW_VISIBLE);
}

/**
 * @tc.name: DragDataManagerTest010
 * @tc.desc: normal test DragDrawing initialization
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest010, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData == std::nullopt);
    DragDrawing dragDrawing;
    int32_t ret = dragDrawing.Init(dragData.value(), nullptr);
    dragDrawing.UpdateDragWindowState(DRAG_WINDOW_VISIBLE);
    EXPECT_EQ(ret, INIT_CANCEL);
    dragDrawing.DestroyDragWindow();
    dragDrawing.UpdateDragWindowState(!DRAG_WINDOW_VISIBLE);
}

 /**
 * @tc.name: DragDataManagerTest011
 * @tc.desc: normal test DragDrawing drawing
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest011, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    EXPECT_FALSE(pointerEvent == nullptr);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    FI_HILOGD("SourceType:%{public}d, pointerId:%{public}d, displayX:%{public}d, displayY:%{public}d",
        pointerEvent->GetSourceType(), pointerEvent->GetPointerId(),
        pointerItem.GetDisplayX(), pointerItem.GetDisplayY());
    EXPECT_LT(pointerEvent->GetTargetDisplayId(), 0);
    DragDrawing dragDrawing;
    dragDrawing.Draw(pointerEvent->GetTargetDisplayId(), pointerItem.GetDisplayX(), pointerItem.GetDisplayY());
    dragDrawing.DestroyDragWindow();
}

/**
 * @tc.name: InteractionDragDrawingTest_CalculateScale
 * @tc.desc: normal test DragDrawing CalculateScale
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    EXPECT_FLOAT_EQ(1.0f, dragDrawing.CalculateScale(200, 300, 200, 300));
    EXPECT_FLOAT_EQ(0.5f, dragDrawing.CalculateScale(400, 200, 200, 300));
    EXPECT_FLOAT_EQ(0.4f, dragDrawing.CalculateScale(200, 500, 300, 200));
    EXPECT_FLOAT_EQ(0.5f, dragDrawing.CalculateScale(400, 600, 200, 300));
}

 /**
 * @tc.name: DragDataManagerTest013
 * @tc.desc: normal test DragDrawing drawing
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest013, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t eventId = 1;
    DRAG_DATA_MGR.SetEventId(eventId);
    EXPECT_TRUE(DRAG_DATA_MGR.GetEventId() == eventId);
}
} // namespace
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS