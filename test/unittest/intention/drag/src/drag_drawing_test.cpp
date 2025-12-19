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
ContextService *g_instance = nullptr;
DelegateTasks g_delegateTasks;
DeviceManager g_devMgr;
TimerManager g_timerMgr;
DragManager g_dragMgr;
SocketSessionManager g_socketSessionMgr;
std::unique_ptr<IInputAdapter> g_input { nullptr };
std::unique_ptr<IPluginManager> g_pluginMgr { nullptr };
std::unique_ptr<IDSoftbusAdapter> g_dsoftbus { nullptr };
IContext *g_context { nullptr };
} // namespace

ContextService::ContextService()
{
    ddm_ = std::make_unique<DDMAdapter>();
}

ContextService::~ContextService()
{
}

IDelegateTasks& ContextService::GetDelegateTasks()
{
    return g_delegateTasks;
}

IDeviceManager& ContextService::GetDeviceManager()
{
    return g_devMgr;
}

ITimerManager& ContextService::GetTimerManager()
{
    return g_timerMgr;
}

IDragManager& ContextService::GetDragManager()
{
    return g_dragMgr;
}

ContextService* ContextService::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        ContextService *cooContext = new (std::nothrow) ContextService();
        CHKPL(cooContext);
        g_instance = cooContext;
    });
    return g_instance;
}

ISocketSessionManager& ContextService::GetSocketSessionManager()
{
    return g_socketSessionMgr;
}

IDDMAdapter& ContextService::GetDDM()
{
    return *ddm_;
}

IPluginManager& ContextService::GetPluginManager()
{
    return *g_pluginMgr;
}

IInputAdapter& ContextService::GetInput()
{
    return *g_input;
}

IDSoftbusAdapter& ContextService::GetDSoftbus()
{
    return *g_dsoftbus;
}

void DragDrawingTest::SetUpTestCase() {}

void DragDrawingTest::SetUp()
{
    g_context = ContextService::GetInstance();
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
        FI_HILOGE("invalid, height:%{public}d, width:%{public}d", height, width);
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
    dragData.extraInfo = FILTER_INFO;
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
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
