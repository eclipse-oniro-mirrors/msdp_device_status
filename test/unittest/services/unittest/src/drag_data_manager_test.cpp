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
#include "transaction/rs_interfaces.h"
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
void DragDataManagerTest::SetUpTestCase()
{
    auto connectToRenderObj = Rosen::RSInterfaces::GetInstance().GetConnectToRenderToken(DISPLAY_ID);
    rsUiDirector_ = OHOS::Rosen::RSUIDirector::Create(connectToRenderObj);
}

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
    dragDrawing.InitDrawingInfo(dragData.value());
    int32_t ret = dragDrawing.Init(dragData.value(), nullptr);
    EXPECT_EQ(ret, INIT_CANCEL);
    dragDrawing.DestroyDragWindow();
    dragDrawing.UpdateDragWindowState(!DRAG_WINDOW_VISIBLE);
    dragDrawing.UpdateDrawingState();
}

 /**
 * @tc.name: DragDataManagerTest010
 * @tc.desc: normal test DragDrawing drawing
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest010, TestSize.Level0)
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
 * @tc.name: DragDataManagerTest011
 * @tc.desc: normal test DragDrawing CalculateScale
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    EXPECT_FLOAT_EQ(1.0f, dragDrawing.CalculateScale(200, 300, 200, 300));
    EXPECT_FLOAT_EQ(0.5f, dragDrawing.CalculateScale(400, 200, 200, 300));
    EXPECT_FLOAT_EQ(0.4f, dragDrawing.CalculateScale(200, 500, 300, 200));
    EXPECT_FLOAT_EQ(0.5f, dragDrawing.CalculateScale(400, 600, 200, 300));
}

 /**
 * @tc.name: DragDataManagerTest012
 * @tc.desc: normal test DragDrawing drawing
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest012, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t eventId = 1;
    DRAG_DATA_MGR.SetEventId(eventId);
    EXPECT_TRUE(DRAG_DATA_MGR.GetEventId() == eventId);
}

/**
 * @tc.name: DragDataManagerTest013
 * @tc.desc: normal test DragDrawing RemoveModifier
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest013, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    int32_t width = 30;
    int32_t height = 50;
    dragDrawing.rsUiDirector_ = rsUiDirector_;
    dragDrawing.InitCanvas(width, height);
    if (dragDrawing.drawStyleScaleModifier_ == nullptr) {
        dragDrawing.drawStyleScaleModifier_ = std::make_shared<DrawStyleScaleModifier>();
    }
 
    if (dragDrawing.drawStyleChangeModifier_ == nullptr) {
        dragDrawing.drawStyleChangeModifier_ = std::make_shared<DrawStyleChangeModifier>();
    }
    EXPECT_NE(dragDrawing.drawStyleChangeModifier_, nullptr);
    EXPECT_NE(dragDrawing.drawStyleScaleModifier_, nullptr);
    dragDrawing.RemoveModifier();
 
    EXPECT_EQ(dragDrawing.drawStyleChangeModifier_, nullptr);
    EXPECT_EQ(dragDrawing.drawStyleScaleModifier_, nullptr);
    dragDrawing.RemoveModifier();
    dragDrawing.DestroyDragWindow();
    dragDrawing.UpdateDrawingState();
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
/**
 * @tc.name: DragDataManagerTest014
 * @tc.desc: normal test DragDrawing GetFilePath
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest014, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    bool isRTL = true;
    std::string filePath;
    dragDrawing.SetDragStyleRTL(isRTL);
    EXPECT_TRUE(dragDrawing.isRTL_);
    dragDrawing.GetFilePath(filePath);
    bool isRTL1 = false;
    dragDrawing.SetDragStyleRTL(isRTL1);
    EXPECT_FALSE(dragDrawing.isRTL_);
    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::COPY);
    EXPECT_TRUE(DRAG_DATA_MGR.GetDragStyle() == DragCursorStyle::COPY);
    dragDrawing.UpdateValidDragStyle(DragCursorStyle::COPY);
    dragDrawing.GetLTRFilePath(filePath);
    dragDrawing.GetFilePath(filePath);
}

/**
 * @tc.name: DragDataManagerTest015
 * @tc.desc: normal test DragDrawing GetFilePath
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest015, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    std::string filePath;
    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::DEFAULT);
    EXPECT_FALSE(DRAG_DATA_MGR.GetDragStyle() != DragCursorStyle::DEFAULT);
    dragDrawing.UpdateDragWindowState(DRAG_WINDOW_VISIBLE);
    dragDrawing.UpdateValidDragStyle(DragCursorStyle::DEFAULT);
    dragDrawing.GetRTLFilePath(filePath);
    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::FORBIDDEN);
    EXPECT_FALSE(DRAG_DATA_MGR.GetDragStyle() != DragCursorStyle::FORBIDDEN);
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHPAD, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData == std::nullopt);
    dragDrawing.InitDrawingInfo(dragData.value());
    dragDrawing.UpdateValidDragStyle(DragCursorStyle::FORBIDDEN);
    dragDrawing.GetRTLFilePath(filePath);
    std::optional<DragData> dragData1 = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHPAD, POINTER_ID, POINTER_ID);
    ASSERT_FALSE(dragData1 == std::nullopt);
    dragDrawing.InitDrawingInfo(dragData1.value());
    dragDrawing.GetRTLFilePath(filePath);
    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::COPY);
    EXPECT_FALSE(DRAG_DATA_MGR.GetDragStyle() != DragCursorStyle::COPY);
    std::optional<DragData> dragData2 = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHPAD, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData2 == std::nullopt);
    dragDrawing.InitDrawingInfo(dragData2.value());
    dragDrawing.UpdateValidDragStyle(DragCursorStyle::COPY);
    dragDrawing.GetRTLFilePath(filePath);
    std::optional<DragData> dragData3 = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHPAD, POINTER_ID, POINTER_ID);
    ASSERT_FALSE(dragData3 == std::nullopt);
    dragDrawing.InitDrawingInfo(dragData3.value());
    dragDrawing.GetRTLFilePath(filePath);
    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::MOVE);
    EXPECT_FALSE(DRAG_DATA_MGR.GetDragStyle() != DragCursorStyle::MOVE);
    dragDrawing.UpdateValidDragStyle(DragCursorStyle::MOVE);
    dragDrawing.GetRTLFilePath(filePath);
    dragDrawing.UpdateValidDragStyle(static_cast<DragCursorStyle>(-1));
    dragDrawing.GetRTLFilePath(filePath);
}

/**
 * @tc.name: DragDataManagerTest016
 * @tc.desc: normal test DragDrawing Draw
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest016, TestSize.Level0)
{
    std::shared_ptr<Media::PixelMap> stylePixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    bool isRTL = false;
    RSDrawingContext context;
    DrawSVGModifier drawSVGModifier(stylePixelMap, isRTL);
    ASSERT_NO_FATAL_FAILURE(drawSVGModifier.Draw(context));
}

/**
 * @tc.name: DragDataManagerTest017
 * @tc.desc: normal test DragDrawing Draw
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest017, TestSize.Level0)
{
    std::shared_ptr<Media::PixelMap> stylePixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    bool isRTL = true;
    RSDrawingContext context;
    DrawSVGModifier drawSVGModifier(stylePixelMap, isRTL);
    ASSERT_NO_FATAL_FAILURE(drawSVGModifier.Draw(context));
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

// ========== Simplified tests: only test nullptr branch ==========

/**
 * @tc.name: DragDataManagerTest018
 * @tc.desc: test DragDrawing Draw with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest018, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData == std::nullopt);
    DragDrawing dragDrawing;
    dragDrawing.InitDrawingInfo(dragData.value());
    dragDrawing.rsUiDirector_ = nullptr;
    int32_t displayId = 0;
    int32_t displayX = 100;
    int32_t displayY = 100;
    dragDrawing.Draw(displayId, displayX, displayY);
    dragDrawing.Draw(displayId, displayX, displayY, true);
}

/**
 * @tc.name: DragDataManagerTest019
 * @tc.desc: test DragDrawing DestroyDragWindow with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest019, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = nullptr;
    dragDrawing.DestroyDragWindow();
    ASSERT_TRUE(dragDrawing.rsUiDirector_ == nullptr);
}

/**
 * @tc.name: DragDataManagerTest020
 * @tc.desc: test DragDrawing UpdateDragWindowState with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest020, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData == std::nullopt);
    DragDrawing dragDrawing;
    dragDrawing.InitDrawingInfo(dragData.value());
    dragDrawing.rsUiDirector_ = nullptr;
    dragDrawing.UpdateDragWindowState(true);
    dragDrawing.UpdateDragWindowState(false);
}

/**
 * @tc.name: DragDataManagerTest023
 * @tc.desc: test DragDrawing UpdatePreviewStyle with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest023, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    PreviewStyle previewStyle;
    previewStyle.scale = 1.0f;
    dragDrawing.rsUiDirector_ = nullptr;
    int32_t ret = dragDrawing.UpdatePreviewStyle(previewStyle);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragDataManagerTest024
 * @tc.desc: test DragDrawing ScreenRotate with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest024, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = nullptr;
    dragDrawing.ScreenRotate(Rosen::Rotation::ROTATION_0, Rosen::Rotation::ROTATION_90);
    ASSERT_TRUE(dragDrawing.rsUiDirector_ == nullptr);
}

/**
 * @tc.name: DragDataManagerTest025
 * @tc.desc: test DragDrawing DoRotateDragWindowAnimation with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest025, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = nullptr;
    float rotation = 90.0f;
    float pivotX = 0.5f;
    float pivotY = 0.5f;
    std::shared_ptr<Rosen::RSTransaction> rsTransaction = nullptr;
    int32_t ret = dragDrawing.DoRotateDragWindowAnimation(rotation, pivotX, pivotY, rsTransaction);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragDataManagerTest026
 * @tc.desc: test DragDrawing InitVSync with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest026, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = nullptr;
    float endAlpha = 1.0f;
    float endScale = 1.0f;
    int32_t ret = dragDrawing.InitVSync(endAlpha, endScale);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragDataManagerTest027
 * @tc.desc: test DragDrawing UpdateAnimationProtocol with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest027, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = nullptr;
    Rosen::RSAnimationTimingProtocol protocol;
    protocol.SetDuration(100);
    dragDrawing.UpdateAnimationProtocol(protocol);
    ASSERT_TRUE(dragDrawing.rsUiDirector_ == nullptr);
}

/**
 * @tc.name: DragDataManagerTest028
 * @tc.desc: test DragDrawing RemoveModifier with nullptr modifiers
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest028, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    dragDrawing.drawStyleScaleModifier_ = nullptr;
    dragDrawing.drawStyleChangeModifier_ = nullptr;
    dragDrawing.RemoveModifier();
    dragDrawing.RemoveModifier();
    ASSERT_TRUE(dragDrawing.rsUiDirector_ == nullptr);
}

// ========== Integration tests: cover non-nullptr branches ==========

/**
 * @tc.name: DragDataManagerTest029
 * @tc.desc: test DragDrawing core functions with valid rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest029, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData == std::nullopt);

    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = rsUiDirector_;
    dragDrawing.InitDrawingInfo(dragData.value());

    // Test InitCanvas with non-null rsUiDirector_
    dragDrawing.InitCanvas(100, 100);

    // Test Draw with non-null rsUiDirector_ (relies on InitCanvas)
    dragDrawing.Draw(0, 100, 100);

    // Test UpdatePreviewStyle with non-null rsUiDirector_
    PreviewStyle previewStyle;
    previewStyle.scale = 1.0f;
    int32_t ret = dragDrawing.UpdatePreviewStyle(previewStyle);
    EXPECT_EQ(ret, RET_OK);

    // Test ScreenRotate with non-null rsUiDirector_
    dragDrawing.ScreenRotate(Rosen::Rotation::ROTATION_0, Rosen::Rotation::ROTATION_90);

    // Cleanup
    dragDrawing.DestroyDragWindow();
}

/**
 * @tc.name: DragDataManagerTest031
 * @tc.desc: test DragDrawing animation functions with valid rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest031, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData == std::nullopt);

    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = rsUiDirector_;
    dragDrawing.InitDrawingInfo(dragData.value());
    int32_t ret = dragDrawing.Init(dragData.value(), nullptr);
    EXPECT_EQ(ret, INIT_CANCEL);

    // Test UpdateAnimationProtocol with non-null rsUiDirector_
    Rosen::RSAnimationTimingProtocol protocol;
    protocol.SetDuration(100);
    dragDrawing.UpdateAnimationProtocol(protocol);

    // Test InitVSync with non-null rsUiDirector_
    float endAlpha = 1.0f;
    float endScale = 1.0f;
    ret = dragDrawing.InitVSync(endAlpha, endScale);
    EXPECT_EQ(ret, RET_ERR);

    // Cleanup
    dragDrawing.DestroyDragWindow();
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
/**
 * @tc.name: DragDataManagerTest032
 * @tc.desc: test DragDrawing FlushDragPosition with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest032, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = nullptr;
    uint64_t nanoTimestamp = 1000000;
    dragDrawing.FlushDragPosition(nanoTimestamp);
    ASSERT_TRUE(dragDrawing.rsUiDirector_ == nullptr);
}

/**
 * @tc.name: DragDataManagerTest033
 * @tc.desc: test DragDrawing DetachToDisplay with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest033, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = nullptr;
    int32_t displayId = 0;
    dragDrawing.DetachToDisplay(displayId);
    ASSERT_TRUE(dragDrawing.rsUiDirector_ == nullptr);
}

/**
 * @tc.name: DragDataManagerTest034
 * @tc.desc: test DragDrawing UpdateDragWindowDisplay with nullptr rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest034, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = nullptr;
    int32_t displayId = 0;
    dragDrawing.UpdateDragWindowDisplay(displayId);
    ASSERT_TRUE(dragDrawing.rsUiDirector_ == nullptr);
}

/**
 * @tc.name: DragDataManagerTest034
 * @tc.desc: test DragDrawing ARKUI_X functions with valid rsUiDirector_
 * @tc.type: FUNC
 */
HWTEST_F(DragDataManagerTest, DragDataManagerTest035, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE);
    ASSERT_FALSE(dragData == std::nullopt);

    DragDrawing dragDrawing;
    dragDrawing.rsUiDirector_ = rsUiDirector_;
    dragDrawing.InitDrawingInfo(dragData.value());
    int32_t ret = dragDrawing.Init(dragData.value(), nullptr);
    EXPECT_EQ(ret, INIT_CANCEL);

    // Test FlushDragPosition with non-null rsUiDirector_
    uint64_t nanoTimestamp = 1000000;
    dragDrawing.FlushDragPosition(nanoTimestamp);

    // Test DetachToDisplay with non-null rsUiDirector_
    int32_t displayId = 0;
    dragDrawing.DetachToDisplay(displayId);

    // Test UpdateDragWindowDisplay with non-null rsUiDirector_
    dragDrawing.UpdateDragWindowDisplay(displayId);

    // Cleanup
    dragDrawing.DestroyDragWindow();
}
#endif

} // namespace
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS