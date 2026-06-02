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
#include "drag_drawing_test.h"

#define BUFF_SIZE 100
#include <future>
#ifndef OHOS_BUILD_ENABLE_ARKUI_X
#include "parameters.h"
#endif // OHOS_BUILD_ENABLE_ARKUI_X
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
constexpr int32_t SHADOW_NUM_ONE { 1 };
constexpr int32_t INT32_BYTE { 4 };
constexpr int32_t POINTER_ID { 0 };
int32_t g_shadowinfoX { 0 };
int32_t g_shadowinfoY { 0 };
constexpr bool HAS_CANCELED_ANIMATION { true };
const std::string UD_KEY { "Unified data key" };
const std::string FILTER_INFO { "Undefined filter info" };
const std::string EXTRA_INFO { "Undefined extra info" };
DragManager g_dragMgr;
IContext *g_context { nullptr };
} // namespace

void DragDrawingTest::SetUpTestCase() {}

void DragDrawingTest::SetUp()
{
    context_ = std::make_shared<TestContext>();
    g_context = context_.get();
    g_dragMgr.Init(g_context);
}

void DragDrawingTest::TearDown()
{
    g_context = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

std::shared_ptr<Media::PixelMap> DragDrawingTest::CreatePixelMap(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    if (width <= 0 || width > MAX_PIXEL_MAP_WIDTH || height <= 0 || height > MAX_PIXEL_MAP_HEIGHT) {
        FI_HILOGE("Invalid, height:%{public}d, width:%{public}d", height, width);
        return nullptr;
    }
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.pixelFormat = Media::PixelFormat::BGRA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.scaleMode = Media::ScaleMode::FIT_TARGET_SIZE;

    int32_t colorLen = width * height;
    uint32_t *pixelColors = new (std::nothrow) uint32_t[BUFF_SIZE];
    CHKPP(pixelColors);
    int32_t colorByteCount = colorLen * INT32_BYTE;
    errno_t ret = memset_s(pixelColors, BUFF_SIZE, DEFAULT_ICON_COLOR, colorByteCount);
    if (ret != EOK) {
        FI_HILOGE("memset_s failed");
        delete[] pixelColors;
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(pixelColors, colorLen, opts);
    if (pixelMap == nullptr) {
        FI_HILOGE("Create pixelMap failed");
        delete[] pixelColors;
        return nullptr;
    }
    delete[] pixelColors;
    return pixelMap;
}

std::optional<DragData> DragDrawingTest::CreateDragData(int32_t sourceType,
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
        dragData.shadowInfos.push_back({ pixelMap, g_shadowinfoX, g_shadowinfoY });
    }
    dragData.buffer = std::vector<uint8_t>(MAX_BUFFER_SIZE, 0);
    dragData.filterInfo = FILTER_INFO;
    dragData.udKey = UD_KEY;
    dragData.sourceType = sourceType;
    dragData.extraInfo = EXTRA_INFO;
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
 * @tc.name: DragDrawingTest1
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = 1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context, true);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.LoadNewMaterialLib();
    g_dragMgr.dragDrawing_.materialId_ = -1;
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest2
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool ret = g_dragMgr.dragDrawing_.SetNewMaterialId();
    EXPECT_FALSE(ret);
    g_dragMgr.dragDrawing_.LoadNewMaterialLib();
    ret = g_dragMgr.dragDrawing_.SetNewMaterialId();
    EXPECT_FALSE(ret);
    ret = g_dragMgr.dragDrawing_.SetNewMaterialId();
    EXPECT_FALSE(ret);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
}

/**
 * @tc.name: DragDrawingTest3
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = 1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.LoadNewMaterialLib();
    bool result = g_dragMgr.dragDrawing_.SetNewMaterialId();
    EXPECT_FALSE(result);
    g_dragMgr.dragDrawing_.materialId_ = -1;
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest4
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest4, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool ret = g_dragMgr.dragDrawing_.SetMaterialFilter();
    EXPECT_FALSE(ret);
    g_dragMgr.dragDrawing_.materialFilter_ = std::make_shared<Rosen::Filter>();
    ret = g_dragMgr.dragDrawing_.SetMaterialFilter();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: DragDrawingTest5
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest5, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = -1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.materialFilter_ = std::make_shared<Rosen::Filter>();
    bool result = g_dragMgr.dragDrawing_.SetMaterialFilter();
    EXPECT_TRUE(result);
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest6
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest6, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = -1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    FilterInfo filterInfo;
    std::shared_ptr<Rosen::RSCanvasNode> filterNode = Rosen::RSCanvasNode::Create();
    g_dragMgr.dragDrawing_.OnSetCustomDragBlur(filterInfo, filterNode);
    filterNode = nullptr;
    g_dragMgr.dragDrawing_.OnSetCustomDragBlur(filterInfo, filterNode);
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest7
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest7, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    FilterInfo filterInfo;
    std::shared_ptr<Rosen::RSCanvasNode> filterNode = Rosen::RSCanvasNode::Create();
    g_dragMgr.dragDrawing_.SetCustomDragBlur(filterInfo, filterNode);
    g_dragMgr.dragDrawing_.materialId_ = 1;
    g_dragMgr.dragDrawing_.SetCustomDragBlur(filterInfo, filterNode);
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = 1694498816;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.SetCustomDragBlur(filterInfo, filterNode);
    g_dragMgr.dragDrawing_.materialId_ = -1;
    g_dragMgr.dragDrawing_.materialFilter_  = std::make_shared<Rosen::Filter>();
    g_dragMgr.dragDrawing_.SetCustomDragBlur(filterInfo, filterNode);
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.materialId_ = -1;
    g_dragMgr.dragDrawing_.materialFilter_  = std::make_shared<Rosen::Filter>();
    ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.SetCustomDragBlur(filterInfo, filterNode);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest8
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest8, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = -1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    FilterInfo filterInfo;
    ExtraInfo extraInfo;
    std::shared_ptr<Rosen::RSCanvasNode> filterNode = Rosen::RSCanvasNode::Create();
    g_dragMgr.dragDrawing_.OnSetComponentDragBlur(filterInfo, extraInfo, filterNode);
    filterNode = nullptr;
    g_dragMgr.dragDrawing_.OnSetComponentDragBlur(filterInfo, extraInfo, filterNode);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest9
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest9, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    FilterInfo filterInfo;
    ExtraInfo extraInfo;
    g_dragMgr.dragDrawing_.SetComponentDragBlur(filterInfo, extraInfo, nullptr);
    std::shared_ptr<Rosen::RSCanvasNode> filterNode = Rosen::RSCanvasNode::Create();
    g_dragMgr.dragDrawing_.SetComponentDragBlur(filterInfo, extraInfo, filterNode);
    g_dragMgr.dragDrawing_.materialId_ = 1;
    g_dragMgr.dragDrawing_.SetComponentDragBlur(filterInfo, extraInfo, filterNode);
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = 1694498816;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.SetComponentDragBlur(filterInfo, extraInfo, filterNode);
    g_dragMgr.dragDrawing_.materialId_ = -1;
    g_dragMgr.dragDrawing_.materialFilter_  = std::make_shared<Rosen::Filter>();
    g_dragMgr.dragDrawing_.SetComponentDragBlur(filterInfo, extraInfo, filterNode);
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.materialId_ = -1;
    g_dragMgr.dragDrawing_.materialFilter_  = std::make_shared<Rosen::Filter>();
    ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.SetComponentDragBlur(filterInfo, extraInfo, filterNode);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
}

/**
 * @tc.name: DragDrawingTest10
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest10, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = -1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    FilterInfo filterInfo;
    ExtraInfo extraInfo;
    extraInfo.cornerRadius = -1;
    std::shared_ptr<Rosen::RSCanvasNode> filterNode = Rosen::RSCanvasNode::Create();
    g_dragMgr.dragDrawing_.OnSetComponentDragBlur(filterInfo, extraInfo, filterNode);
    extraInfo.cornerRadius = 0;
    filterInfo.dipScale = -1;
    g_dragMgr.dragDrawing_.OnSetComponentDragBlur(filterInfo, extraInfo, filterNode);
    filterInfo.dipScale = std::numeric_limits<float>::max();
    extraInfo.cornerRadius = std::numeric_limits<float>::max();
    g_dragMgr.dragDrawing_.OnSetComponentDragBlur(filterInfo, extraInfo, filterNode);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest11
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest11, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = -1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    FilterInfo filterInfo;
    filterInfo.blurRadius = -1;
    std::shared_ptr<Rosen::RSCanvasNode> filterNode = Rosen::RSCanvasNode::Create();
    g_dragMgr.dragDrawing_.OnSetCustomDragBlur(filterInfo, filterNode);
    filterInfo.blurRadius = 0;
    filterInfo.dipScale = -1;
    g_dragMgr.dragDrawing_.OnSetCustomDragBlur(filterInfo, filterNode);
    filterInfo.dipScale = std::numeric_limits<float>::max();
    filterInfo.blurRadius = std::numeric_limits<float>::max();
    g_dragMgr.dragDrawing_.OnSetCustomDragBlur(filterInfo, filterNode);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest12
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest12, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().filterInfo = "{\"blurStyle\":2}";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.ProcessFilter();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest13
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest13, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = 1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.ProcessFilter();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest14
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest14, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().extraInfo = "{\"drag_data_type\":\"scb_folder\"}";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.ProcessFilter();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest15
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest15, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    g_dragMgr.dragDrawing_.materialId_ = 1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.ProcessFilter();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest16
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest16, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().extraInfo = "{\"drag_data_type\":\"scb_folder\"}";
    g_dragMgr.dragDrawing_.materialId_ = 1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.ProcessFilter();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
 * @tc.name: DragDrawingTest17
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragDrawingTest, DragDrawingTest17, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().filterInfo = "{\"blurStyle\":2}";
    g_dragMgr.dragDrawing_.materialId_ = 1;
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.ProcessFilter();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest18
* @tc.desc: Test CalculateRotation with normal values
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest18, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.currentDisplayX_ = 100.0f;
    g_dragMgr.dragDrawing_.currentDisplayY_ = 100.0f;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.CalculateRotation(150.0f, 150.0f, degreeX, degreeY);
    EXPECT_GE(degreeX, -40.0f);
    EXPECT_LE(degreeX, 40.0f);
    EXPECT_GE(degreeY, -40.0f);
    EXPECT_LE(degreeY, 40.0f);
}

/**
* @tc.name: DragDrawingTest19
* @tc.desc: Test CalculateRotation with extreme values
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest19, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.currentDisplayX_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDisplayY_ = 0.0f;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.CalculateRotation(1000.0f, 1000.0f, degreeX, degreeY);
    EXPECT_GE(degreeX, -40.0f);
    EXPECT_LE(degreeX, 40.0f);
    EXPECT_GE(degreeY, -40.0f);
    EXPECT_LE(degreeY, 40.0f);
}

/**
* @tc.name: DragDrawingTest20
* @tc.desc: Test CalculateRotation with negative movement
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest20, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.currentDisplayX_ = 200.0f;
    g_dragMgr.dragDrawing_.currentDisplayY_ = 200.0f;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.CalculateRotation(100.0f, 100.0f, degreeX, degreeY);
    EXPECT_GE(degreeX, -40.0f);
    EXPECT_LE(degreeX, 40.0f);
    EXPECT_GE(degreeY, -40.0f);
    EXPECT_LE(degreeY, 40.0f);
}

/**
* @tc.name: DragDrawingTest21
* @tc.desc: Test CalculateRotation with zero movement
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest21, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.currentDisplayX_ = 100.0f;
    g_dragMgr.dragDrawing_.currentDisplayY_ = 100.0f;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.CalculateRotation(100.0f, 100.0f, degreeX, degreeY);
    EXPECT_FLOAT_EQ(degreeX, 0.0f);
    EXPECT_FLOAT_EQ(degreeY, 0.0f);
}

/**
* @tc.name: DragDrawingTest22
* @tc.desc: Test CalculateRotation boundary conditions
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest22, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.currentDisplayX_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDisplayY_ = 0.0f;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.CalculateRotation(-1000.0f, -1000.0f, degreeX, degreeY);
    EXPECT_GE(degreeX, -40.0f);
    EXPECT_LE(degreeX, 40.0f);
    EXPECT_GE(degreeY, -40.0f);
    EXPECT_LE(degreeY, 40.0f);
}

/**
* @tc.name: DragDrawingTest23
* @tc.desc: Test DoFollowHandAnimation with FOLLOW_HAND_MORPH type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest23, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dragWindowVisible_ = true;
    g_dragMgr.dragDrawing_.DoFollowHandAnimation(150.0f, 150.0f);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest24
* @tc.desc: Test DoFollowHandAnimation with null parentNode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest24, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dragWindowVisible_ = true;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DoFollowHandAnimation(150.0f, 150.0f);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest25
* @tc.desc: Test DrawContentLight with FOLLOW_HAND_MORPH type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest25, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.DrawContentLight();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest26
* @tc.desc: Test DrawContentLight with null pixelMapNode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest26, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DrawContentLight();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
}

/**
* @tc.name: DragDrawingTest27
* @tc.desc: Test InitDrawingDisplayInfo with invalid value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest27, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.cubicCurveEnable_ = true;
    g_dragMgr.dragDrawing_.dropAnimationCurve_ = {0.2f, 0.0f, 0.2f};
    Rosen::RSAnimationTimingCurve curve = g_dragMgr.dragDrawing_.GetAnimationTimingCurve();
    g_dragMgr.dragDrawing_.InitDrawingDisplayInfo(0, 0, 0);
    g_dragMgr.dragDrawing_.InitDrawingDisplayInfo(0, -1, 0);
    g_dragMgr.dragDrawing_.InitDrawingDisplayInfo(0, 0, -1);
    g_dragMgr.dragDrawing_.InitDrawingDisplayInfo(0, -1, -1);
    EXPECT_EQ(3, g_dragMgr.dragDrawing_.dropAnimationCurve_.size());
    g_dragMgr.dragDrawing_.dropAnimationCurve_.resize(0);
}

/**
* @tc.name: DragDrawingTest28
* @tc.desc: Test UpdateDisplayXY with invalid value
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest28, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.cubicCurveEnable_ = true;
    g_dragMgr.dragDrawing_.dropAnimationCurve_ = {0.2f, 0.0f, 0.2f};
    Rosen::RSAnimationTimingCurve curve = g_dragMgr.dragDrawing_.GetAnimationTimingCurve();
    g_dragMgr.dragDrawing_.UpdateDisplayXY(0, 0);
    g_dragMgr.dragDrawing_.UpdateDisplayXY(0, -1);
    g_dragMgr.dragDrawing_.UpdateDisplayXY(-1, 0);
    g_dragMgr.dragDrawing_.UpdateDisplayXY(-1, -1);
    EXPECT_EQ(3, g_dragMgr.dragDrawing_.dropAnimationCurve_.size());
    g_dragMgr.dragDrawing_.dropAnimationCurve_.resize(0);
}

/**
* @tc.name: DragDrawingTest29
* @tc.desc: Test StopDestopAnimation with null parentNode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest29, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dragWindowVisible_ = false;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.StopDestopAnimation();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
}

/**
* @tc.name: DragDrawingTest30
* @tc.desc: Test RunDestopAnimation with null parentNode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest30, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    std::string dragAnimationInfo = "{\"CubicCurveEnable\":true,\"SpringEnable\":false,"
        "\"dropAnimationCurve\":[0.2,0.0,0.2,1.0],\"dropPosition\":[100,200],\"dropSize\":[50,50]}";
    ret = g_dragMgr.dragDrawing_.RunDestopAnimation(1000, dragAnimationInfo);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest31
* @tc.desc: Test StopDestopAnimation with dragWindowVisible true
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest31, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dragWindowVisible_ = true;
    g_dragMgr.dragDrawing_.StopDestopAnimation();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest32
* @tc.desc: Test StopDestopAnimation with dragWindowVisible false
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest32, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dragWindowVisible_ = false;
    g_dragMgr.dragDrawing_.StopDestopAnimation();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest33
* @tc.desc: Test ParserDragAnimationInfo with valid JSON
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest33, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string dragAnimationInfo = "{\"CubicCurveEnable\":true,\"SpringEnable\":false,"
        "\"dropAnimationCurve\":[0.2,0.0,0.2,1.0],\"dropPosition\":[100,200],\"dropSize\":[50,50]}";
    bool result = g_dragMgr.dragDrawing_.ParserDragAnimationInfo(dragAnimationInfo);
    EXPECT_TRUE(result);
    EXPECT_TRUE(g_dragMgr.dragDrawing_.cubicCurveEnable_);
    EXPECT_FALSE(g_dragMgr.dragDrawing_.springEnable_);
}

/**
* @tc.name: DragDrawingTest34
* @tc.desc: Test ParserDragAnimationInfo with empty string
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest34, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string dragAnimationInfo = "";
    bool result = g_dragMgr.dragDrawing_.ParserDragAnimationInfo(dragAnimationInfo);
    EXPECT_FALSE(result);
}

/**
* @tc.name: DragDrawingTest35
* @tc.desc: Test ParserDragAnimationInfo with invalid JSON
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest35, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string dragAnimationInfo = "invalid json string";
    bool result = g_dragMgr.dragDrawing_.ParserDragAnimationInfo(dragAnimationInfo);
    EXPECT_FALSE(result);
}

/**
* @tc.name: DragDrawingTest36
* @tc.desc: Test ParserDragAnimationInfo with spring enable
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest36, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string dragAnimationInfo = "{\"CubicCurveEnable\":false,\"SpringEnable\":true,"
        "\"dropAnimationCurve\":[0.347,0.99,0.0],\"dropPosition\":[100,200],\"dropSize\":[50,50]}";
    bool result = g_dragMgr.dragDrawing_.ParserDragAnimationInfo(dragAnimationInfo);
    EXPECT_TRUE(result);
    EXPECT_FALSE(g_dragMgr.dragDrawing_.cubicCurveEnable_);
    EXPECT_TRUE(g_dragMgr.dragDrawing_.springEnable_);
}

/**
* @tc.name: DragDrawingTest37
* @tc.desc: Test ParserDragAnimationInfo with missing fields
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest37, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string dragAnimationInfo = "{\"CubicCurveEnable\":true}";
    bool result = g_dragMgr.dragDrawing_.ParserDragAnimationInfo(dragAnimationInfo);
    EXPECT_FALSE(result);
}

/**
* @tc.name: DragDrawingTest38
* @tc.desc: Test GetAnimationTimingCurve with spring curve
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest38, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.springEnable_ = true;
    g_dragMgr.dragDrawing_.dropAnimationCurve_ = {0.347f, 0.99f, 0.0f};
    Rosen::RSAnimationTimingCurve curve = g_dragMgr.dragDrawing_.GetAnimationTimingCurve();
    EXPECT_EQ(3, g_dragMgr.dragDrawing_.dropAnimationCurve_.size());
}

/**
* @tc.name: DragDrawingTest39
* @tc.desc: Test MoveToEndAnimation with valid data
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest39, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dropPosition_ = {100.0f, 200.0f};
    g_dragMgr.dragDrawing_.dropSize_ = {50.0f, 50.0f};
    ret = g_dragMgr.dragDrawing_.MoveToEndAnimation();
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest40
* @tc.desc: Test MoveToEndAnimation with null parentNode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest40, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_dragMgr.dragDrawing_.MoveToEndAnimation();
    EXPECT_EQ(ret, RET_ERR);
}

/**
* @tc.name: DragDrawingTest41
* @tc.desc: Test MoveToEndAnimation with invalid dropPosition size
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest41, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dropPosition_ = {100.0f};
    ret = g_dragMgr.dragDrawing_.MoveToEndAnimation();
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest42
* @tc.desc: Test MoveToEndAnimation with invalid dropSize size
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest42, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dropPosition_ = {100.0f, 200.0f};
    g_dragMgr.dragDrawing_.dropSize_ = {50.0f};
    ret = g_dragMgr.dragDrawing_.MoveToEndAnimation();
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest43
* @tc.desc: Test DoDestopAnimation with valid data
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest43, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dropPosition_ = {100.0f, 200.0f};
    g_dragMgr.dragDrawing_.dropSize_ = {50.0f, 50.0f};
    ret = g_dragMgr.dragDrawing_.DoDestopAnimation();
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest44
* @tc.desc: Test DoDestopAnimation with null pixelMap
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest44, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dropPosition_ = {100.0f, 200.0f};
    g_dragMgr.dragDrawing_.dropSize_ = {50.0f, 50.0f};
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    ret = g_dragMgr.dragDrawing_.DoDestopAnimation();
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest45
* @tc.desc: Test RunDestopAnimation with valid JSON
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest45, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string dragAnimationInfo = "{\"CubicCurveEnable\":true,\"SpringEnable\":false,"
        "\"dropAnimationCurve\":[0.2,0.0,0.2,1.0],\"dropPosition\":[100,200],\"dropSize\":[50,50]}";
    g_dragMgr.dragDrawing_.dropPosition_ = {100.0f, 200.0f};
    g_dragMgr.dragDrawing_.dropSize_ = {50.0f, 50.0f};
    int32_t ret = g_dragMgr.dragDrawing_.RunDestopAnimation(1000, dragAnimationInfo);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest46
* @tc.desc: Test RunDestopAnimation with invalid JSON
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest46, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string dragAnimationInfo = "invalid json";
    int32_t ret = g_dragMgr.dragDrawing_.RunDestopAnimation(1000, dragAnimationInfo);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest47
* @tc.desc: Test RunDestopAnimation with empty JSON
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest47, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string dragAnimationInfo = "";
    int32_t ret = g_dragMgr.dragDrawing_.RunDestopAnimation(1000, dragAnimationInfo);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest48
* @tc.desc: Test UpdateDragPosition with FOLLOW_HAND_MORPH type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest48, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.dragWindowVisible_ = true;
    g_dragMgr.dragDrawing_.UpdateDragPosition(DISPLAY_ID, 150.0f, 150.0f);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest49
* @tc.desc: Test OnStartDrag with FOLLOW_HAND_MORPH type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest49, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    DragAnimationData animationData;
    animationData.displayX = 100;
    animationData.displayY = 100;
    g_dragMgr.dragDrawing_.OnStartDrag(animationData);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest50
* @tc.desc: Test UpdateDragWindowState with FOLLOW_HAND_MORPH type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest50, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.UpdateDragWindowState(false);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest51
* @tc.desc: Test ResetParameter with new fields
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest51, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.dragWindowVisible_ = true;
    g_dragMgr.dragDrawing_.dragAnimationType_ = 1;
    g_dragMgr.dragDrawing_.cubicCurveEnable_ = true;
    g_dragMgr.dragDrawing_.springEnable_ = true;
    g_dragMgr.dragDrawing_.lightFilterLeftTop_ = std::make_shared<Rosen::RSNGContentLightFilter>();
    g_dragMgr.dragDrawing_.lightFilterRightBottom_ = std::make_shared<Rosen::RSNGContentLightFilter>();
    g_dragMgr.dragDrawing_.ResetParameter();
    EXPECT_FALSE(g_dragMgr.dragDrawing_.dragWindowVisible_);
    EXPECT_EQ(g_dragMgr.dragDrawing_.dragAnimationType_, 0);
    EXPECT_FALSE(g_dragMgr.dragDrawing_.cubicCurveEnable_);
    EXPECT_FALSE(g_dragMgr.dragDrawing_.springEnable_);
    EXPECT_EQ(g_dragMgr.dragDrawing_.lightFilterLeftTop_, nullptr);
    EXPECT_EQ(g_dragMgr.dragDrawing_.lightFilterRightBottom_, nullptr);
}

/**
* @tc.name: DragDrawingTest52
* @tc.desc: Test GetAnimationTimingCurve with cubic curve
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest52, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.cubicCurveEnable_ = true;
    g_dragMgr.dragDrawing_.dropAnimationCurve_ = {0.2f, 0.0f, 0.2f, 1.0f};
    Rosen::RSAnimationTimingCurve curve = g_dragMgr.dragDrawing_.GetAnimationTimingCurve();
    EXPECT_EQ(4, g_dragMgr.dragDrawing_.dropAnimationCurve_.size());
    g_dragMgr.dragDrawing_.dropAnimationCurve_.resize(0);
}

/**
* @tc.name: DragDrawingTest53
* @tc.desc: Test GetAnimationTimingCurve with default curve
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest53, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.springEnable_ = false;
    g_dragMgr.dragDrawing_.cubicCurveEnable_ = false;
    Rosen::RSAnimationTimingCurve curve = g_dragMgr.dragDrawing_.GetAnimationTimingCurve();
    EXPECT_EQ(0, g_dragMgr.dragDrawing_.dropAnimationCurve_.size());
}

/**
* @tc.name: DragDrawingTest54
* @tc.desc: Test GetAnimationTimingCurve with invalid spring size
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest54, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.springEnable_ = true;
    g_dragMgr.dragDrawing_.dropAnimationCurve_ = {0.347f, 0.99f};
    Rosen::RSAnimationTimingCurve curve = g_dragMgr.dragDrawing_.GetAnimationTimingCurve();
    EXPECT_EQ(2, g_dragMgr.dragDrawing_.dropAnimationCurve_.size());
    g_dragMgr.dragDrawing_.dropAnimationCurve_.resize(0);
}

/**
* @tc.name: DragDrawingTest55
* @tc.desc: Test CalculateRotation with normal values
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest55, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.currentDisplayX_ = 100.0f;
    g_dragMgr.dragDrawing_.currentDisplayY_ = 100.0f;
    g_dragMgr.dragDrawing_.currentDegreeX_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDegreeY_ = 0.0f;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.CalculateRotation(150.0f, 150.0f, degreeX, degreeY);
    EXPECT_GE(degreeX, -40.0f);
    EXPECT_LE(degreeX, 40.0f);
    EXPECT_GE(degreeY, -40.0f);
    EXPECT_LE(degreeY, 40.0f);
}
 
/**
* @tc.name: DragDrawingTest56
* @tc.desc: Test CalculateRotation with extreme values
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest56, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.currentDisplayX_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDisplayY_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDegreeX_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDegreeY_ = 0.0f;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.CalculateRotation(1000.0f, 1000.0f, degreeX, degreeY);
    EXPECT_GE(degreeX, -40.0f);
    EXPECT_LE(degreeX, 40.0f);
    EXPECT_GE(degreeY, -40.0f);
    EXPECT_LE(degreeY, 40.0f);
}
 
/**
* @tc.name: DragDrawingTest57
* @tc.desc: Test CalculateRotation with negative movement
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest57, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.currentDisplayX_ = 200.0f;
    g_dragMgr.dragDrawing_.currentDisplayY_ = 200.0f;
    g_dragMgr.dragDrawing_.currentDegreeX_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDegreeY_ = 0.0f;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.CalculateRotation(100.0f, 100.0f, degreeX, degreeY);
    EXPECT_GE(degreeX, -40.0f);
    EXPECT_LE(degreeX, 40.0f);
    EXPECT_GE(degreeY, -40.0f);
    EXPECT_LE(degreeY, 40.0f);
}

/**
* @tc.name: DragDrawingTest58
* @tc.desc: Test CalculateRotation with zero movement
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest58, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.currentDisplayX_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDisplayY_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDegreeX_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDegreeY_ = 0.0f;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.CalculateRotation(0.0f, 0.0f, degreeX, degreeY);
    EXPECT_FLOAT_EQ(degreeX, 0.0f);
    EXPECT_FLOAT_EQ(degreeY, 0.0f);
}

/**
* @tc.name: DragDrawingTest59
* @tc.desc: Test CalculateLightIntensity
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest59, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    LightIntensity lightIntensity;
    g_dragMgr.dragDrawing_.DragWindowRotateInfo_.rotation = 0.0f;
    g_dragMgr.dragDrawing_.CalculateLightIntensity(100.0f, 100.0f, lightIntensity);
    EXPECT_NE(lightIntensity.lightLeftTop, 0.0f);
    g_dragMgr.dragDrawing_.DragWindowRotateInfo_.rotation = 90.0f;
    g_dragMgr.dragDrawing_.CalculateLightIntensity(100.0f, 100.0f, lightIntensity);
    EXPECT_NE(lightIntensity.lightLeftTop, 0.0f);
    g_dragMgr.dragDrawing_.DragWindowRotateInfo_.rotation = 180.0f;
    g_dragMgr.dragDrawing_.CalculateLightIntensity(100.0f, 100.0f, lightIntensity);
    EXPECT_NE(lightIntensity.lightLeftTop, 0.0f);
    g_dragMgr.dragDrawing_.DragWindowRotateInfo_.rotation = 270.0f;
    g_dragMgr.dragDrawing_.CalculateLightIntensity(100.0f, 100.0f, lightIntensity);
    EXPECT_NE(lightIntensity.lightLeftTop, 0.0f);
    g_dragMgr.dragDrawing_.DragWindowRotateInfo_.rotation = 0.0f;
    g_dragMgr.dragDrawing_.CalculateLightIntensity(-100.0f, -100.0f, lightIntensity);
    EXPECT_NE(lightIntensity.lightLeftTop, 0.0f);
    g_dragMgr.dragDrawing_.DragWindowRotateInfo_.rotation = 90.0f;
    g_dragMgr.dragDrawing_.CalculateLightIntensity(-100.0f, -100.0f, lightIntensity);
    EXPECT_NE(lightIntensity.lightLeftTop, 0.0f);
    g_dragMgr.dragDrawing_.DragWindowRotateInfo_.rotation = 180.0f;
    g_dragMgr.dragDrawing_.CalculateLightIntensity(-100.0f, -100.0f, lightIntensity);
    EXPECT_NE(lightIntensity.lightLeftTop, 0.0f);
    g_dragMgr.dragDrawing_.DragWindowRotateInfo_.rotation = 270.0f;
    g_dragMgr.dragDrawing_.CalculateLightIntensity(-100.0f, -100.0f, lightIntensity);
    EXPECT_NE(lightIntensity.lightLeftTop, 0.0f);
}

/**
* @tc.name: DragDrawingTest60
* @tc.desc: Test AdjustRotateDropPositionXY
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest60, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.AdjustRotateDropPositionXY(100.0f, 100.0f, degreeX, degreeY);
    EXPECT_FLOAT_EQ(degreeX, 0.0f);
    EXPECT_FLOAT_EQ(degreeY, 0.0f);
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.SetRotation(DISPLAY_ID, Rosen::Rotation::ROTATION_0);
    g_dragMgr.dragDrawing_.AdjustRotateDropPositionXY(1.0f, 1.0f, degreeX, degreeY);
    EXPECT_FLOAT_EQ(degreeX, 0.0f);
    EXPECT_FLOAT_EQ(degreeY, 0.0f);
    g_dragMgr.dragDrawing_.SetRotation(DISPLAY_ID, Rosen::Rotation::ROTATION_90);
    g_dragMgr.dragDrawing_.AdjustRotateDropPositionXY(1.0f, 1.0f, degreeX, degreeY);
    g_dragMgr.dragDrawing_.SetRotation(DISPLAY_ID, Rosen::Rotation::ROTATION_180);
    g_dragMgr.dragDrawing_.AdjustRotateDropPositionXY(1.0f, 1.0f, degreeX, degreeY);
    g_dragMgr.dragDrawing_.SetRotation(DISPLAY_ID, Rosen::Rotation::ROTATION_270);
    g_dragMgr.dragDrawing_.AdjustRotateDropPositionXY(100.0f, 100.0f, degreeX, degreeY);
    g_dragMgr.dragDrawing_.UpdateDragWindowState(false);
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest61
* @tc.desc: Test StopDestopAnimation with dragWindowVisible true
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest61, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.dragWindowVisible_ = true;
    g_dragMgr.dragDrawing_.StopDestopAnimation();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}

/**
* @tc.name: DragDrawingTest62
* @tc.desc: Test StopDestopAnimation with dragWindowVisible false
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest62, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, 1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().dragAnimationType = static_cast<int32_t>(DragAnimationType::FOLLOW_HAND_MORPH);
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.dragWindowVisible_ = false;
    g_dragMgr.dragDrawing_.StopDestopAnimation();
    g_dragMgr.dragDrawing_.newMaterialHandler_ = nullptr;
    g_dragMgr.dragDrawing_.DestroyDragWindow();
    g_dragMgr.dragDrawing_.UpdateDrawingState();
}
 
/**
* @tc.name: DragDrawingTest63
* @tc.desc: Test CalculateRotation with negative movement
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest63, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.currentDisplayX_ = 200.0f;
    g_dragMgr.dragDrawing_.currentDisplayY_ = 200.0f;
    g_dragMgr.dragDrawing_.currentDegreeX_ = 0.0f;
    g_dragMgr.dragDrawing_.currentDegreeY_ = 0.0f;
    float degreeX = 0.0f;
    float degreeY = 0.0f;
    g_dragMgr.dragDrawing_.dropArea_ = { 2, 2 };
    g_dragMgr.dragDrawing_.CalculateRotation(100.0f, 100.0f, degreeX, degreeY);
    EXPECT_GE(degreeX, -40.0f);
    g_dragMgr.dragDrawing_.dropArea_ = { 4, 2 };
    g_dragMgr.dragDrawing_.CalculateRotation(100.0f, 100.0f, degreeX, degreeY);
    EXPECT_LE(degreeX, 40.0f);
    g_dragMgr.dragDrawing_.dropArea_ = { 4, 4 };
    g_dragMgr.dragDrawing_.CalculateRotation(100.0f, 100.0f, degreeX, degreeY);
    EXPECT_LE(degreeX, 40.0f);
    g_dragMgr.dragDrawing_.dropArea_ = { 4, 6 };
    g_dragMgr.dragDrawing_.CalculateRotation(100.0f, 100.0f, degreeX, degreeY);
    EXPECT_GE(degreeY, -40.0f);
    g_dragMgr.dragDrawing_.dropArea_ = { 6, 4 };
    g_dragMgr.dragDrawing_.CalculateRotation(100.0f, 100.0f, degreeX, degreeY);
    EXPECT_LE(degreeY, 40.0f);
}

/**
* @tc.name: DragDrawingTest64
* @tc.desc: Test ParseDropArea
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragDrawingTest, DragDrawingTest64, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    JsonParser jsonParser("{\"dropArea\":\"2,2\"}");
    g_dragMgr.dragDrawing_.dragAnimationType_ = 0;
    bool ret = g_dragMgr.dragDrawing_.ParseDropArea(jsonParser);
    EXPECT_TRUE(ret);
    g_dragMgr.dragDrawing_.dragAnimationType_ = 1;
    ret = g_dragMgr.dragDrawing_.ParseDropArea(jsonParser);
    EXPECT_TRUE(!ret);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
