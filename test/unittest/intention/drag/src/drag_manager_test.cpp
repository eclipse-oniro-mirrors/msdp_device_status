/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "drag_manager_test.h"

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
#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
constexpr int32_t TIME_WAIT_FOR_INTERNAL_DROP_ANIMATION { 500 };
#endif // OHOS_BUILD_INTERNAL_DROP_ANIMATION
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
constexpr int32_t PIXEL_MAP_HEIGHT { 3 };
constexpr int32_t PIXEL_MAP_WIDTH { 3 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t POINTER_ID { 0 };
constexpr int32_t DISPLAY_X { 50 };
constexpr int32_t DISPLAY_ID { 0 };
constexpr int32_t DISPLAY_Y { 50 };
constexpr int32_t DRAG_NUM_ONE { 1 };
constexpr int32_t INT32_BYTE { 4 };
constexpr int32_t PROMISE_WAIT_SPAN_MS { 2000 };
constexpr int32_t FOREGROUND_COLOR_IN { 0x33FF0000 };
constexpr int32_t FOREGROUND_COLOR_OUT { 0x00000000 };
int32_t g_shadowinfo_x { 0 };
int32_t g_shadowinfo_y { 0 };
constexpr int32_t ANIMATION_DURATION { 500 };
const std::string CURVE_NAME { "cubic-bezier" };
constexpr bool HAS_CUSTOM_ANIMATION { true };
constexpr int32_t TARGET_MAIN_WINDOW { 0 };
constexpr bool HAS_CANCELED_ANIMATION { true };
const std::string UD_KEY { "Unified data key" };
const std::string FILTER_INFO { "Undefined filter info" };
const std::string EXTRA_INFO { "Undefined extra info" };
constexpr int32_t SHADOW_NUM_ONE { 1 };
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

void DragManagerTest::SetUpTestCase() {}

void DragManagerTest::SetUp()
{
    g_context = ContextService::GetInstance();
    g_dragMgr.Init(g_context);
}

void DragManagerTest::TearDown()
{
    g_context = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

std::shared_ptr<Media::PixelMap> DragManagerTest::CreatePixelMap(int32_t width, int32_t height)
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

std::optional<DragData> DragManagerTest::CreateDragData(int32_t sourceType,
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

class TestStartDragListener : public IStartDragListener {
public:
    explicit TestStartDragListener(std::function<void(const DragNotifyMsg&)> function) : function_(function) { }
    void OnDragEndMessage(const DragNotifyMsg &msg) override
    {
        FI_HILOGD("DisplayX:%{public}d, displayY:%{public}d, targetPid:%{public}d, result:%{public}d",
            msg.displayX, msg.displayY, msg.targetPid, static_cast<int32_t>(msg.result));
        if (function_ != nullptr) {
            function_(msg);
        }
        FI_HILOGD("Test OnDragEndMessage");
    }

    void OnHideIconMessage() override
    {
        FI_HILOGD("Test OnHideIconMessage");
    }
private:
    std::function<void(const DragNotifyMsg&)> function_;
};

class DragListenerTest : public IDragListener {
public:
    DragListenerTest() {}
    explicit DragListenerTest(const std::string& name) : moduleName_(name) {}
    void OnDragMessage(DragState state) override
    {
        if (moduleName_.empty()) {
            moduleName_ = std::string("DragListenerTest");
        }
        FI_HILOGD("%{public}s, state:%{public}s", moduleName_.c_str(), PrintDragMessage(state).c_str());
    }
private:
    std::string PrintDragMessage(DragState state)
    {
        std::string type = "unknow";
        const std::map<DragState, std::string> stateType = {
            { DragState::ERROR, "error"},
            { DragState::START, "start"},
            { DragState::STOP, "stop"},
            { DragState::CANCEL, "cancel"}
        };
        auto item = stateType.find(state);
        if (item != stateType.end()) {
            type = item->second;
        }
        return type;
    }
private:
    std::string moduleName_;
};

class SubscriptListenerTest : public ISubscriptListener {
public:
    SubscriptListenerTest() {}
    explicit SubscriptListenerTest(const std::string& name) : moduleName_(name) {}
    void OnMessage(DragCursorStyle style) override
    {
        SetDragSyle(style);
        if (moduleName_.empty()) {
            moduleName_ = std::string("SubscriptListenerTest");
        }
        FI_HILOGD("subscriptListener, %{public}s, state:%{public}s",
            moduleName_.c_str(), PrintStyleMessage(style).c_str());
    }

    DragCursorStyle GetDragStyle()
    {
        return dragStyle_;
    }

private:
    void SetDragSyle(DragCursorStyle style)
    {
        dragStyle_ = style;
    }

    std::string PrintStyleMessage(DragCursorStyle style)
    {
        std::string type = "unknow";
        const std::map<DragCursorStyle, std::string> cursorStyles = {
            { DragCursorStyle::DEFAULT, "default"},
            { DragCursorStyle::FORBIDDEN, "forbidden"},
            { DragCursorStyle::COPY, "copy"},
            { DragCursorStyle::MOVE, "move"}
        };
        auto item = cursorStyles.find(style);
        if (item != cursorStyles.end()) {
            type = item->second;
        }
        return type;
    }

private:
    DragCursorStyle dragStyle_ { DragCursorStyle::DEFAULT };
    std::string moduleName_;
};

void DragManagerTest::AssignToAnimation(PreviewAnimation &animation)
{
    animation.duration = ANIMATION_DURATION;
    animation.curveName = CURVE_NAME;
    animation.curve = { 0.33, 0, 0.67, 1 };
}

/**
 * @tc.name: DragManagerTest1
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(), nullptr);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest2
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, 0);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: DragManagerTest3
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    g_shadowinfo_x = 2;
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest4
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest4, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_shadowinfo_x = 0;
    std::promise<bool> promiseFlag;
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, -1, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest5
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest5, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->AddDraglistener(nullptr);
    ASSERT_EQ(ret, RET_ERR);
    ret = InteractionManager::GetInstance()->RemoveDraglistener(nullptr);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest6
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest6, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<DragListenerTest>(std::string("Draglistener_Mouse"));
    int32_t ret = InteractionManager::GetInstance()->AddDraglistener(listener);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest7
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest7, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->AddSubscriptListener(nullptr);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest8
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest8, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<SubscriptListenerTest>("SubscriptListener");
    int32_t ret = InteractionManager::GetInstance()->AddSubscriptListener(listener);
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->AddSubscriptListener(listener);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest9
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest9, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto listener = std::make_shared<SubscriptListenerTest>("SubscriptListener");
    int32_t ret = InteractionManager::GetInstance()->RemoveSubscriptListener(listener);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest10
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest10, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->RemoveSubscriptListener(nullptr);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest11
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest11, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->RemoveSubscriptListener(nullptr);
    auto listener = std::make_shared<SubscriptListenerTest>("SubscriptListener");
    ret = InteractionManager::GetInstance()->AddSubscriptListener(listener);
    ret = InteractionManager::GetInstance()->RemoveSubscriptListener(nullptr);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest12
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest12, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->UpdateDragStyle(static_cast<DragCursorStyle>(-1));
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest13
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest13, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 1, 0 };
    int32_t ret = InteractionManager::GetInstance()->UpdateShadowPic(shadowInfo);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest14
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest14, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    std::vector<DragCursorStyle> dragCursorStyles = {DragCursorStyle::DEFAULT,
        DragCursorStyle::FORBIDDEN, DragCursorStyle::COPY, DragCursorStyle::MOVE};
    for (const auto& dragCursorStyle : dragCursorStyles) {
        ret = InteractionManager::GetInstance()->UpdateDragStyle(dragCursorStyle);
        ASSERT_EQ(ret, RET_OK);
    }
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest15
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest15, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest16
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest16, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    std::string udKey;
    ret = InteractionManager::GetInstance()->GetUdKey(udKey);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest17
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest17, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(false);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest18
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest18, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t offsetX = 0;
    int32_t offsetY = 0;
    int32_t width = 0;
    int32_t height = 0;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    ret = InteractionManager::GetInstance()->GetShadowOffset(offsetX, offsetY, width, height);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest19
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest19, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 0, 0 };
    ret = InteractionManager::GetInstance()->UpdateShadowPic(shadowInfo);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest20
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest20, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragData replyDragData;
    ret = InteractionManager::GetInstance()->GetDragData(replyDragData);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest21
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest21, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragState dragState;
    ret = InteractionManager::GetInstance()->GetDragState(dragState);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest22
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest22, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragAction dragAction { DragAction::INVALID };
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest23
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest23, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    std::string extraInfo;
    ret = InteractionManager::GetInstance()->GetExtraInfo(extraInfo);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest24
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest24, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    ret = InteractionManager::GetInstance()->UpdatePreviewStyle(previewStyleIn);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    PreviewStyle previewStyleOut;
    previewStyleOut.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleOut.foregroundColor = FOREGROUND_COLOR_OUT;
    ret = InteractionManager::GetInstance()->UpdatePreviewStyle(previewStyleOut);
    EXPECT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest25
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest25, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    PreviewAnimation animationIn;
    AssignToAnimation(animationIn);
    ret = InteractionManager::GetInstance()->UpdatePreviewStyleWithAnimation(previewStyleIn, animationIn);
    ASSERT_EQ(ret, RET_OK);
    PreviewStyle previewStyleOut;
    previewStyleOut.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleOut.foregroundColor = FOREGROUND_COLOR_OUT;
    PreviewAnimation animationOut;
    AssignToAnimation(animationOut);
    ret = InteractionManager::GetInstance()->UpdatePreviewStyleWithAnimation(previewStyleOut, animationOut);
    EXPECT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest26
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest26, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    std::map<std::string, int64_t> summarys = { { udType, recordSize } };
    dragData.value().summarys = summarys;
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    std::map<std::string, int64_t> summarysRlt;
    ret = InteractionManager::GetInstance()->GetDragSummary(summarysRlt);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_EQ(summarysRlt, summarys);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest27
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest27, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    ret = InteractionManager::GetInstance()->EnterTextEditorArea(true);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    ret = InteractionManager::GetInstance()->EnterTextEditorArea(false);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest28
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest28, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    ret = InteractionManager::GetInstance()->AddPrivilege();
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest29
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest29, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_ERR);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest30
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest30, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    int32_t ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest31
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest31, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->SetDragWindowVisible(true);
    ASSERT_EQ(ret, RET_ERR);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    ret = InteractionManager::GetInstance()->SetDragWindowVisible(false);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest32
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest32, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = -1;
    std::vector<DragCursorStyle> dragCursorStyles = {DragCursorStyle::FORBIDDEN,
        DragCursorStyle::COPY, DragCursorStyle::MOVE};
    for (const auto& dragCursorStyle : dragCursorStyles) {
        ret = InteractionManager::GetInstance()->UpdateDragStyle(dragCursorStyle);
        ASSERT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: DragManagerTest33
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest33, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 0, 0 };
    int32_t ret = InteractionManager::GetInstance()->UpdateShadowPic(shadowInfo);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest34
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest34, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t pid = InteractionManager::GetInstance()->GetDragTargetPid();
    EXPECT_GT(pid, 0);
}

/**
 * @tc.name: DragManagerTest35
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest35, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string udKey;
    int32_t ret = InteractionManager::GetInstance()->GetUdKey(udKey);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest36
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest36, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t offsetX = 0;
    int32_t offsetY = 0;
    int32_t width = 0;
    int32_t height = 0;
    int32_t ret = InteractionManager::GetInstance()->GetShadowOffset(offsetX, offsetY, width, height);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest37
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest37, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData replyDragData;
    int32_t ret = InteractionManager::GetInstance()->GetDragData(replyDragData);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest38
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest38, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyleOut;
    previewStyleOut.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleOut.foregroundColor = FOREGROUND_COLOR_OUT;
    int32_t ret = InteractionManager::GetInstance()->UpdatePreviewStyle(previewStyleOut);
    ASSERT_EQ(ret, RET_ERR);
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    ret = InteractionManager::GetInstance()->UpdatePreviewStyle(previewStyleIn);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest39
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest39, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    PreviewAnimation animationIn;
    AssignToAnimation(animationIn);
    int32_t ret = InteractionManager::GetInstance()->UpdatePreviewStyleWithAnimation(previewStyleIn, animationIn);
    ASSERT_EQ(ret, RET_ERR);
    PreviewStyle previewStyleOut;
    previewStyleOut.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleOut.foregroundColor = FOREGROUND_COLOR_OUT;
    PreviewAnimation animationOut;
    AssignToAnimation(animationOut);
    ret = InteractionManager::GetInstance()->UpdatePreviewStyleWithAnimation(previewStyleOut, animationOut);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest40
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest40, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->EnterTextEditorArea(true);
    ASSERT_EQ(ret, RET_ERR);
    ret = InteractionManager::GetInstance()->EnterTextEditorArea(false);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest41
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest41, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragAction dragAction { DragAction::INVALID };
    int32_t ret = InteractionManager::GetInstance()->GetDragAction(dragAction);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest42
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest42, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string extraInfo;
    int32_t ret = InteractionManager::GetInstance()->GetExtraInfo(extraInfo);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest43
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest43, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->AddPrivilege();
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest68
 * @tc.desc: Drag Drawingx`
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest68, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 1, 0 };
    ShadowInfo otherShadowInfo = {};
    EXPECT_TRUE(shadowInfo != otherShadowInfo);
    ShadowOffset shadowOffset {};
    ShadowOffset otherShadowOffset {};
    EXPECT_FALSE(shadowOffset != otherShadowOffset);
    DragData dragData {};
    DragData otherDragData {};
    EXPECT_FALSE(dragData != otherDragData);
    PreviewStyle previewStyle {};
    PreviewStyle otherPreviewStyle {};
    EXPECT_FALSE(previewStyle != otherPreviewStyle);
    Data data {};
    Data otherData {};
    EXPECT_TRUE(data != otherData);
    DragItemStyle dragItemStyle = { 1, 1, 0 };
    DragItemStyle otherDragItemStyle = {};
    EXPECT_TRUE(dragItemStyle != otherDragItemStyle);
}

/**
 * @tc.name: DragManagerTest69
 * @tc.desc: Drag Drawingx`
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest69, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = InteractionManager::GetInstance()->RotateDragWindowSync(nullptr);
    EXPECT_EQ(ret, 5);
}

/**
 * @tc.name: DragManagerTest70
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest70, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragBundleInfo dragBundleInfo;
    int32_t ret = InteractionManager::GetInstance()->GetDragBundleInfo(dragBundleInfo);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest71
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest71, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragBundleInfo dragBundleInfo;
    ret = InteractionManager::GetInstance()->GetDragBundleInfo(dragBundleInfo);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

/**
 * @tc.name: DragManagerTest72
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest72, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    std::map<std::string, int64_t> summarys = { { udType, recordSize } };
    dragData.value().detailedSummarys = summarys;
 
    const std::string udType1 = "general1.message";
    constexpr int64_t recordSize1 = 30;
    std::map<std::string, int64_t> summarys1 = { { udType1, recordSize1 } };
    dragData.value().summarys = summarys1;
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    std::map<std::string, int64_t> summarysRlt;
    ret = InteractionManager::GetInstance()->GetDragSummary(summarysRlt);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_EQ(summarysRlt.size(), 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}

#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
/**
 * @tc.name: DragManagerTest73
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest73, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragInternalInfo dragInternalInfo;
    g_dragMgr.GetDragDrawingInfo(dragInternalInfo);
    ASSERT_EQ(dragInternalInfo.rootNode, nullptr);
}

/**
 * @tc.name: DragManagerTest74
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest74, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.ResetAnimationParameter();
    g_dragMgr.ResetDragState();
    int32_t ret = g_dragMgr.PerformInternalDropAnimation();
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest75
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest75, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.ResetAnimationParameter();
    g_dragMgr.ResetDragState();
    std::string animationInfo = "{\"targetPos\": [100, 100]}";
    int32_t ret = InteractionManager::GetInstance()->EnableInternalDropAnimation(animationInfo);
    EXPECT_EQ(ret, RET_OK);
    ret = g_dragMgr.PerformInternalDropAnimation();
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragManagerTest76
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest76, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool hasCustomAnimation = true;
    DragData dragData;
    dragData.dragNum = 1;
    DRAG_DATA_MGR.Init(dragData);
    g_dragMgr.enableInternalDropAnimation_ = true;
    int32_t ret = g_dragMgr.HandleDragSuccess(hasCustomAnimation);
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.enableInternalDropAnimation_ = false;
}

/**
 * @tc.name: DragManagerTest77
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest77, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool hasCustomAnimation = true;
    DragData dragData;
    dragData.dragNum = 1;
    DRAG_DATA_MGR.Init(dragData);
    g_dragMgr.enableInternalDropAnimation_ = true;
    int32_t ret = g_dragMgr.HandleDragSuccess(hasCustomAnimation);
    EXPECT_EQ(ret, RET_OK);
    std::string animationInfo = "{\"targetPos\": [-1, -1]}";
    ret = InteractionManager::GetInstance()->EnableInternalDropAnimation(animationInfo);
    EXPECT_EQ(ret, RET_OK);
    ret = g_dragMgr.HandleDragSuccess(hasCustomAnimation);
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.enableInternalDropAnimation_ = false;
}

/**
 * @tc.name: DragManagerTest78
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest78, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool hasCustomAnimation = true;
    DragData dragData;
    dragData.dragNum = 0;
    DRAG_DATA_MGR.Init(dragData);
    g_dragMgr.enableInternalDropAnimation_ = true;
    int32_t ret = g_dragMgr.HandleDragSuccess(hasCustomAnimation);
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.enableInternalDropAnimation_ = false;
}

/**
 * @tc.name: DragManagerTest79
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest79, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool hasCustomAnimation = false;
    DragData dragData;
    dragData.dragNum = 0;
    DRAG_DATA_MGR.Init(dragData);
    g_dragMgr.enableInternalDropAnimation_ = true;
    int32_t ret = g_dragMgr.HandleDragSuccess(hasCustomAnimation);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.enableInternalDropAnimation_ = false;
}

/**
 * @tc.name: DragManagerTest80
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest80, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragResult result = DragResult::DRAG_SUCCESS;
    bool hasCustomAnimation = false;
    DragData dragData;
    dragData.dragNum = 1;
    DRAG_DATA_MGR.Init(dragData);
    g_dragMgr.enableInternalDropAnimation_ = true;
    int32_t ret = g_dragMgr.HandleDragResult(result, hasCustomAnimation);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.enableInternalDropAnimation_ = false;
}

/**
 * @tc.name: DragManagerTest81
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest81, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragResult result = DragResult::DRAG_SUCCESS;
    bool hasCustomAnimation = false;
    DragData dragData;
    dragData.dragNum = 0;
    DRAG_DATA_MGR.Init(dragData);
    g_dragMgr.enableInternalDropAnimation_ = true;
    int32_t ret = g_dragMgr.HandleDragResult(result, hasCustomAnimation);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.enableInternalDropAnimation_ = false;
}

/**
 * @tc.name: DragManagerTest82
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest82, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragResult result = DragResult::DRAG_FAIL;
    bool hasCustomAnimation = false;
    int32_t ret = g_dragMgr.HandleDragResult(result, hasCustomAnimation);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest83
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest83, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragResult result = DragResult::DRAG_EXCEPTION;
    bool hasCustomAnimation = false;
    int32_t ret = g_dragMgr.HandleDragResult(result, hasCustomAnimation);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest84
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest84, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragResult result = DragResult::DRAG_SUCCESS;
    bool hasCustomAnimation = false;
    DragData dragData;
    dragData.dragNum = 0;
    DRAG_DATA_MGR.Init(dragData);
    g_dragMgr.enableInternalDropAnimation_ = false;
    int32_t ret = g_dragMgr.HandleDragResult(result, hasCustomAnimation);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest85
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest85, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.InitCanvas(100, 100);
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.dragDrawing_.RemoveStyleNodeAnimations());
}

/**
 * @tc.name: DragManagerTest86
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest86, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.InitCanvas(100, 100);
    g_dragMgr.dragDrawing_.drawStyleScaleModifier_ = std::make_shared<DrawStyleScaleModifier>();
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.dragDrawing_.RemoveStyleNodeAnimations());
}

/**
 * @tc.name: DragManagerTest87
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest87, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragDrawing_.InitCanvas(100, 100);
    g_dragMgr.dragDrawing_.drawStyleScaleModifier_ = std::make_shared<DrawStyleScaleModifier>();
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.dragDrawing_.RemoveStyleNodeAnimations());
}

/**
 * @tc.name: DragManagerTest88
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest88, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    std::string animationInfo = "{\"targetPos\": [200, 1000]}";
    ret = InteractionManager::GetInstance()->EnableInternalDropAnimation(animationInfo);
    EXPECT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_INTERNAL_DROP_ANIMATION));
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}
#endif // OHOS_BUILD_INTERNAL_DROP_ANIMATION

/**
 * @tc.name: DragManagerTest89
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest89, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        promiseFlag.set_value(true);
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData.value().summaryFormat = { { "image", { 0, 1 } } };
    dragData.value().summaryTotalSize = 100;
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    DragSummaryInfo dragSummaryInfo;
    ret = InteractionManager::GetInstance()->GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_EQ(dragSummaryInfo.totalSize, 100);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    InteractionManager::GetInstance()->StopDrag(dropResult);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}
 
/**
 * @tc.name: DragManagerTest90
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest90, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragSummaryInfo dragSummaryInfo;
    int32_t ret = InteractionManager::GetInstance()->GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_ERR);
}
 
/**
 * @tc.name: DragManagerTest91
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest91, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragSummaryInfo dragSummaryInfo;
    int32_t ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_ERR);
}
 
/**
 * @tc.name: DragManagerTest92
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest92, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragState_ = DragState::START;
    DragData dragData;
    dragData.summaryFormat = { { "image", { 0, 1 } } };
    DRAG_DATA_MGR.Init(dragData);
    DragSummaryInfo dragSummaryInfo;
    int32_t ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}
 
/**
 * @tc.name: DragManagerTest93
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest93, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.dragState_ = DragState::MOTION_DRAGGING;
    DragData dragData;
    dragData.summaryFormat = { { "image", {} } };
    DRAG_DATA_MGR.Init(dragData);
    DragSummaryInfo dragSummaryInfo;
    int32_t ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}
 
/**
 * @tc.name: DragManagerTest94
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest94, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    std::map<std::string, int64_t> summarys = { { udType, recordSize } };
    dragData.detailedSummarys = summarys;
    dragData.summaryFormat = { { "image", { 0, 1 } } };
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.PrintDragData(dragData, ""));
}
 
/**
 * @tc.name: DragManagerTest95
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest95, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    const std::string udType = "general.message";
    constexpr int64_t recordSize = 20;
    std::map<std::string, int64_t> summarys = { { udType, recordSize } };
    dragData.detailedSummarys = summarys;
    dragData.summaryFormat = { { "image", {} } };
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.PrintDragData(dragData, ""));
}

#ifndef OHOS_BUILD_ENABLE_ARKUI_X
/**
 * @tc.name: DragManagerTest96
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest96, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string persistLanguage = system::GetParameter("persist.global.language", "");
    bool isRTL = g_dragMgr.isRTL_;
    system::SetParameter("persist.global.language", "");
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    system::SetParameter("persist.global.language", "ch");
    g_dragMgr.isRTL_ = true;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    g_dragMgr.isRTL_ = false;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    system::SetParameter("persist.global.language", "ar");
    g_dragMgr.isRTL_ = false;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    g_dragMgr.isRTL_ = true;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    system::SetParameter("persist.global.language", "fa");
    g_dragMgr.isRTL_ = false;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    g_dragMgr.isRTL_ = true;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    system::SetParameter("persist.global.language", "ur");
    g_dragMgr.isRTL_ = false;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    g_dragMgr.isRTL_ = true;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    system::SetParameter("persist.global.language", "he");
    g_dragMgr.isRTL_ = false;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    g_dragMgr.isRTL_ = true;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    system::SetParameter("persist.global.language", "ug");
    g_dragMgr.isRTL_ = false;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    g_dragMgr.isRTL_ = true;
    ASSERT_NO_FATAL_FAILURE(g_dragMgr.UpdateDragStylePositon());
    g_dragMgr.isRTL_ = isRTL;
    system::SetParameter("persist.global.language", persistLanguage.c_str());
}
#endif // OHOS_BUILD_ENABLE_ARKUI_X

#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
/**
 * @tc.name: DragManagerTest97
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest97, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.ResetAnimationParameter();
    g_dragMgr.ResetDragState();
    std::string animationInfo = "{\"targetPos\": [100, 100]}";
    int32_t ret = InteractionManager::GetInstance()->EnableInternalDropAnimation(animationInfo);
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.context_ = g_context;
    ret = g_dragMgr.PerformInternalDropAnimation();
    g_dragMgr.context_ = nullptr;
    g_dragMgr.internalDropTimerId_ = 0;
    ret = g_dragMgr.PerformInternalDropAnimation();
    g_dragMgr.context_ = nullptr;
    g_dragMgr.internalDropTimerId_ = -1;
    ret = g_dragMgr.PerformInternalDropAnimation();
    ASSERT_EQ(ret, RET_ERR);
}
 
/**
 * @tc.name: DragManagerTest98
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest98, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragMgr.context_ = g_context;
    g_dragMgr.internalDropTimerId_ = 0;
    g_dragMgr.ResetDragState();
    g_dragMgr.internalDropTimerId_ = -1;
    g_dragMgr.ResetDragState();
    g_dragMgr.context_ = nullptr;
    g_dragMgr.internalDropTimerId_ = 0;
    g_dragMgr.ResetDragState();
    g_dragMgr.context_ = nullptr;
    g_dragMgr.internalDropTimerId_ = -1;
    g_dragMgr.ResetDragState();
    std::string animationInfo = "{\"targetPos\": [100, 100]}";
    int32_t ret = InteractionManager::GetInstance()->EnableInternalDropAnimation(animationInfo);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragManagerTest99
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest99, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": nullptr } ";
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result);
        promiseFlag.set_value(true);
    };
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0.0f, 0.0f);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
}
 
/**
 * @tc.name: DragManagerTest100
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest100, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": false } ";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.allAnimationCnt_ = 100;
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0.0f, 0.0f);
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DestroyDragWindow();
}
 
/**
 * @tc.name: DragManagerTest101
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest101, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": true } ";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.allAnimationCnt_ = 100;
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0.0f, 0.0f);
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DestroyDragWindow();
}
 
/**
 * @tc.name: DragManagerTest102
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest102, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": true } ";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.preDragPositionX_ = 100;
    g_dragMgr.dragDrawing_.preDragPositionY_ = 100;
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0.0f, 0.0f);
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DestroyDragWindow();
}
 
/**
 * @tc.name: DragManagerTest103
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest103, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": true } ";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.allAnimationCnt_ = 1;
    g_dragMgr.dragDrawing_.preDragPositionX_ = 0;
    g_dragMgr.dragDrawing_.preDragPositionY_ = 0;
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0.0f, 0.0f);
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DestroyDragWindow();
}
 
/**
 * @tc.name: DragManagerTest104
 * @tc.desc: Update drag node bounds and frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest104, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    ASSERT_TRUE(dragData);
    dragData->filterInfo = " { \"enable_animation\": true } ";
    int32_t ret = g_dragMgr.dragDrawing_.Init(dragData.value(), g_context);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragDrawing_.allAnimationCnt_ = 100;
    g_dragMgr.dragDrawing_.preDragPositionX_ = 0;
    g_dragMgr.dragDrawing_.preDragPositionY_ = 0;
    g_dragMgr.dragDrawing_.UpdateDragNodeBoundsAndFrame(0.0f, 0.0f, 0.0f, 0.0f);
    g_dragMgr.dragDrawing_.UpdateDrawingState();
    g_dragMgr.dragDrawing_.DestroyDragWindow();
}
#endif // OHOS_BUILD_INTERNAL_DROP_ANIMATION

/**
 * @tc.name: DragManagerTest105
 * @tc.desc: Get udkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest105, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData->udKey = "test";
    dragData->summaryTag = "NEED_FETCH";
    int32_t ret = g_dragMgr.InitDataManager(dragData.value());
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = false;
    g_dragMgr.isCollaborationService_ = true;
    std::string udKey;
    ret = g_dragMgr.GetUdKey(udKey);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.lastEventId_ = 0;
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    std::map<std::string, int64_t> summarys;
    DragSummaryInfo dragSummaryInfo;
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.isCrossDragging_ = true;
    g_dragMgr.isCollaborationService_ = true;
    ret = g_dragMgr.GetUdKey(udKey);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: DragManagerTest106
 * @tc.desc: Get udkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest106, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData->udKey = "test";
    dragData->summaryTag = "NEED_FETCH";
    int32_t ret = g_dragMgr.InitDataManager(dragData.value());
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = true;
    g_dragMgr.isCollaborationService_ = false;
    std::string udKey;
    ret = g_dragMgr.GetUdKey(udKey);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    std::map<std::string, int64_t> summarys;
    DragSummaryInfo dragSummaryInfo;
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.isCrossDragging_ = false;
    g_dragMgr.isCollaborationService_ = false;
    ret = g_dragMgr.GetUdKey(udKey);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: DragManagerTest107
 * @tc.desc: Get udkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest107, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData->udKey = "test";
    int32_t ret = g_dragMgr.InitDataManager(dragData.value());
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = false;
    g_dragMgr.isCollaborationService_ = true;
    std::string udKey;
    ret = g_dragMgr.GetUdKey(udKey);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.lastEventId_ = 0;
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    std::map<std::string, int64_t> summarys;
    DragSummaryInfo dragSummaryInfo;
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.isCrossDragging_ = true;
    g_dragMgr.isCollaborationService_ = true;
    ret = g_dragMgr.GetUdKey(udKey);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: DragManagerTest108
 * @tc.desc: Get udkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest108, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    dragData->udKey = "test";
    int32_t ret = g_dragMgr.InitDataManager(dragData.value());
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = true;
    g_dragMgr.isCollaborationService_ = false;
    std::string udKey;
    ret = g_dragMgr.GetUdKey(udKey);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    std::map<std::string, int64_t> summarys;
    DragSummaryInfo dragSummaryInfo;
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.isCrossDragging_ = false;
    g_dragMgr.isCollaborationService_ = false;
    ret = g_dragMgr.GetUdKey(udKey);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::MOVE, 0, 0, 1);
    g_dragMgr.UpdateDragStyle(DragCursorStyle::COPY, 0, 0, 1);
    ret = g_dragMgr.GetDragSummary(summarys);
    ASSERT_EQ(ret, RET_OK);
    ret = g_dragMgr.GetDragSummaryInfo(dragSummaryInfo);
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: DragManagerTest109
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest109, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    EXPECT_TRUE(dragData);
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        FI_HILOGD("displayX:%{public}d, displayY:%{public}d, result:%{public}d, target:%{public}d",
            notifyMessage.displayX, notifyMessage.displayY, notifyMessage.result, notifyMessage.targetPid);
        promiseFlag.set_value(true);
    };
    int32_t ret = InteractionManager::GetInstance()->StartDrag(dragData.value(),
        std::make_shared<TestStartDragListener>(callback));
    ASSERT_EQ(ret, RET_OK);
    DragDropResult dropResult { DragResult::DRAG_SUCCESS,
        HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    ret = InteractionManager::GetInstance()->StopDrag(dropResult);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) !=
        std::future_status::timeout);
}
 
/**
 * @tc.name: DragManagerTest110
 * @tc.desc: Drag Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragManagerTest, DragManagerTest110, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDropResult dropResult { DragResult::DRAG_EXCEPTION, HAS_CUSTOM_ANIMATION, TARGET_MAIN_WINDOW };
    g_dragMgr.dragState_ = DragState::START;
    int32_t ret = g_dragMgr.StopDrag(dropResult, "Cross-device drag");
    ASSERT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
