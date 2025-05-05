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

#define BUFF_SIZE 100
#include "intention_service_test.h"

#include "ddm_adapter.h"
#include "drag_data_manager.h"
#include "drag_params.h"
#include "drag_server.h"
#include "dsoftbus_adapter.h"
#include "fi_log.h"
#include "input_adapter.h"
#include "intention_service.h"
#include "interaction_manager.h"
#include "ipc_skeleton.h"
#include "plugin_manager.h"

#undef LOG_TAG
#define LOG_TAG "IntentionServiceTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr int32_t POINTER_ID { 0 };
constexpr int32_t DRAG_NUM_ONE { 1 };
constexpr int32_t SHADOW_NUM_ONE { 1 };
constexpr int32_t PIXEL_MAP_WIDTH { 3 };
constexpr int32_t PIXEL_MAP_HEIGHT { 3 };
constexpr int32_t WINDOW_ID { -1 };
constexpr int32_t READ_OK { 1 };
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
const std::string FILTER_INFO { "Undefined filter info" };
const std::string UD_KEY { "Unified data key" };
const std::string EXTRA_INFO { "Undefined extra info" };
const std::string CURVE_NAME { "cubic-bezier" };
constexpr int32_t FOREGROUND_COLOR_IN { 0x33FF0000 };
constexpr int32_t DISPLAY_ID { 0 };
constexpr int32_t DISPLAY_X { 50 };
constexpr int32_t DISPLAY_Y { 50 };
constexpr int32_t INT32_BYTE { 4 };
int32_t g_shadowinfoX { 0 };
int32_t g_shadowinfoY { 0 };
constexpr int32_t ANIMATION_DURATION { 500 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr bool HAS_CANCELED_ANIMATION { true };
constexpr bool HAS_CUSTOM_ANIMATION { true };
Intention g_intention { Intention::DRAG };
static StationaryServer stationary_;
std::shared_ptr<ContextService> g_context { nullptr };
std::shared_ptr<IntentionService> g_intentionService { nullptr };
std::shared_ptr<IntentionService> g_intentionServiceNullptr { nullptr };
std::shared_ptr<IntentionDumper> g_intentionDumper { nullptr };
IContext *g_contextNullptr { nullptr };
} // namespace

int32_t MockDelegateTasks::PostSyncTask(DTaskCallback callback)
{
    return callback();
}

int32_t MockDelegateTasks::PostAsyncTask(DTaskCallback callback)
{
    return callback();
}

ContextService* ContextService::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        g_context = std::make_shared<ContextService>();
    });
    return g_context.get();
}

ContextService::ContextService()
{
    ddm_ = std::make_unique<DDMAdapter>();
    input_ = std::make_unique<InputAdapter>();
    pluginMgr_ = std::make_unique<PluginManager>(this);
    dsoftbus_ = std::make_unique<DSoftbusAdapter>();
}

IDelegateTasks& ContextService::GetDelegateTasks()
{
    return delegateTasks_;
}

IDeviceManager& ContextService::GetDeviceManager()
{
    return devMgr_;
}

ITimerManager& ContextService::GetTimerManager()
{
    return timerMgr_;
}

IDragManager& ContextService::GetDragManager()
{
    return dragMgr_;
}

ISocketSessionManager& ContextService::GetSocketSessionManager()
{
    return socketSessionMgr_;
}

IDDMAdapter& ContextService::GetDDM()
{
    return *ddm_;
}

IPluginManager& ContextService::GetPluginManager()
{
    return *pluginMgr_;
}

IInputAdapter& ContextService::GetInput()
{
    return *input_;
}

IDSoftbusAdapter& ContextService::GetDSoftbus()
{
    return *dsoftbus_;
}

void IntentionServiceTest::SetUpTestCase()
{
    g_intentionService = std::make_shared<IntentionService>(ContextService::GetInstance());
    g_intentionServiceNullptr = std::make_shared<IntentionService>(g_contextNullptr);
    g_intentionDumper = std::make_shared<IntentionDumper>(ContextService::GetInstance(), stationary_);
}

void IntentionServiceTest::TearDownTestCase()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_intentionServiceNullptr = nullptr;
    g_intentionDumper = nullptr;
}

void IntentionServiceTest::SetUp() {}

void IntentionServiceTest::TearDown() {}

std::shared_ptr<Media::PixelMap> IntentionServiceTest::CreatePixelMap(int32_t width, int32_t height)
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

std::optional<DragData> IntentionServiceTest::CreateDragData(int32_t sourceType,
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

void IntentionServiceTest::AssignToAnimation(PreviewAnimation &animation)
{
    animation.duration = ANIMATION_DURATION;
    animation.curveName = CURVE_NAME;
    animation.curve = { 0.33, 0, 0.67, 1 };
}

/**
 * @tc.name: IntentionServiceTest_1
 * @tc.desc: Test Enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_Enable001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    int32_t ret = g_intentionService->Enable(g_intention, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest2
 * @tc.desc: Test Disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_Disable001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->Disable(g_intention, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest3
 * @tc.desc: Test Start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_Start001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    MessageParcel replyParcel;
    MessageParcel dataParcel;

    int32_t ret = g_intentionService->Start(g_intention, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_Stop001
 * @tc.desc: Test Stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_Stop001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->Stop(g_intention, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_Stop002
 * @tc.desc: Test Stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_Stop002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    env->dragMgr_.dragState_ = DragState::START;
    StopDragParam param { dropResult };

    int32_t ret = param.Marshalling(dataParcel);
    EXPECT_EQ(ret, READ_OK);
    ret = g_intentionService->Stop(g_intention, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
    env->dragMgr_.dragState_ = DragState::STOP;
}

/**
 * @tc.name: IntentionServiceTest_Stop003
 * @tc.desc: Test Stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_Stop003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    env->dragMgr_.dragState_ = DragState::START;
    StopDragParam param { dropResult };

    int32_t ret = param.Marshalling(dataParcel);
    EXPECT_EQ(ret, READ_OK);
    ret = g_intentionServiceNullptr->Stop(g_intention, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
    env->dragMgr_.dragState_ = DragState::STOP;
}

/**
 * @tc.name: IntentionServiceTest5
 * @tc.desc: Test AddWatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_AddWatch001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    std::vector<DragRequestID> dragRequestIDs = {DragRequestID::UNKNOWN_DRAG_ACTION,
        DragRequestID::ADD_DRAG_LISTENER, DragRequestID::ADD_SUBSCRIPT_LISTENER};
    for (const auto& dragRequestID : dragRequestIDs) {
        ret = g_intentionService->AddWatch(g_intention, dragRequestID, dataParcel, replyParcel);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: IntentionServiceTest6
 * @tc.desc: Test RemoveWatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_RemoveWatch001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = RET_ERR;
    std::vector<DragRequestID> dragRequestIDs = {DragRequestID::UNKNOWN_DRAG_ACTION,
        DragRequestID::ADD_DRAG_LISTENER, DragRequestID::ADD_SUBSCRIPT_LISTENER};
    for (const auto& dragRequestID : dragRequestIDs) {
        ret = g_intentionService->RemoveWatch(g_intention, dragRequestID, dataParcel, replyParcel);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: IntentionServiceTest_Control001
 * @tc.desc: Test Control
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_Control001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    std::vector<DragRequestID> dragRequestIDs = {DragRequestID::UNKNOWN_DRAG_ACTION,
        DragRequestID::ADD_PRIVILEGE, DragRequestID::ENTER_TEXT_EDITOR_AREA};
    for (const auto& dragRequestID : dragRequestIDs) {
        ret = g_intentionService->Control(g_intention, dragRequestID, dataParcel, replyParcel);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: IntentionServiceTest_SetParam001
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = RET_ERR;
    std::vector<DragRequestID> dragRequestIDs = {DragRequestID::UNKNOWN_DRAG_ACTION,
        DragRequestID::SET_DRAG_WINDOW_VISIBLE, DragRequestID::UPDATE_DRAG_STYLE,
        DragRequestID::UPDATE_SHADOW_PIC, DragRequestID::UPDATE_PREVIEW_STYLE,
        DragRequestID::UPDATE_PREVIEW_STYLE_WITH_ANIMATION};
    for (const auto& dragRequestID : dragRequestIDs) {
        ret = g_intentionService->SetParam(g_intention, dragRequestID, dataParcel, replyParcel);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: IntentionServiceTest_SetParam002
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->SetParam(g_intention, DragRequestID::SET_DRAG_WINDOW_VISIBLE,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_SetParam003
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->SetParam(g_intention, DragRequestID::UPDATE_DRAG_STYLE,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_SetParam004
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam004, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->SetParam(g_intention, DragRequestID::UPDATE_SHADOW_PIC,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_SetParam005
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam005, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->SetParam(g_intention, DragRequestID::UPDATE_PREVIEW_STYLE,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_SetParam006
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam006, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->SetParam(g_intention, DragRequestID::UPDATE_PREVIEW_STYLE_WITH_ANIMATION,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_SetParam007
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam007, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->SetParam(g_intention, DragRequestID::ENTER_TEXT_EDITOR_AREA,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_SetParam008
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam008, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    env->dragMgr_.dragState_ = DragState::START;
    SetDragWindowVisibleParam param { true, true, nullptr };
    int32_t ret = param.Marshalling(dataParcel);
    EXPECT_EQ(ret, READ_OK);
    ret = g_intentionService->SetParam(Intention::DRAG, DragRequestID::SET_DRAG_WINDOW_VISIBLE,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
    env->dragMgr_.dragState_ = DragState::STOP;
    DRAG_DATA_MGR.dragData_ = {};
}

/**
 * @tc.name: IntentionServiceTest_SetParam009
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam009, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    env->dragMgr_.dragState_ = DragState::START;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 0, 0 };
    std::string extraInfo;
    UpdateShadowPicParam param { shadowInfo };
    bool ret = param.Marshalling(dataParcel);;
    EXPECT_EQ(ret, READ_OK);
    ret = g_intentionService->SetParam(g_intention, DragRequestID::UPDATE_SHADOW_PIC,
        dataParcel, replyParcel);
    EXPECT_TRUE(ret);
    env->dragMgr_.dragState_ = DragState::STOP;
}

/**
 * @tc.name: IntentionServiceTest_SetParam010
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam010, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    env->dragMgr_.dragState_ = DragState::START;
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    UpdatePreviewStyleParam param { previewStyleIn };
    bool ret = param.Marshalling(dataParcel);;
    EXPECT_EQ(ret, READ_OK);
    ret = g_intentionService->SetParam(g_intention, DragRequestID::UPDATE_PREVIEW_STYLE,
        dataParcel, replyParcel);
    EXPECT_TRUE(ret);
    env->dragMgr_.dragState_ = DragState::STOP;
}

/**
 * @tc.name: IntentionServiceTest_SetParam011
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam011, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    env->dragMgr_.dragState_ = DragState::START;
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    PreviewAnimation animationOut;
    AssignToAnimation(animationOut);
    UpdatePreviewAnimationParam param { previewStyleIn, animationOut };
    bool ret = param.Marshalling(dataParcel);;
    EXPECT_EQ(ret, READ_OK);
    ret = g_intentionService->SetParam(Intention::DRAG, DragRequestID::UPDATE_PREVIEW_STYLE_WITH_ANIMATION,
        dataParcel, replyParcel);
    EXPECT_FALSE(ret);
    env->dragMgr_.dragState_ = DragState::STOP;
}

/**
 * @tc.name: IntentionServiceTest_SetParam012
 * @tc.desc: Test SetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetParam012, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    EnterTextEditorAreaParam param { true };
    bool ret = param.Marshalling(dataParcel);;
    EXPECT_EQ(ret, READ_OK);
    ret = g_intentionService->SetParam(g_intention, DragRequestID::ENTER_TEXT_EDITOR_AREA, dataParcel, replyParcel);
    EXPECT_EQ(ret, READ_OK);
}

/**
 * @tc.name: IntentionServiceTest_GetParam001
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    std::vector<DragRequestID> dragRequestIDs = {DragRequestID::UNKNOWN_DRAG_ACTION,
        DragRequestID::GET_DRAG_TARGET_PID, DragRequestID::GET_UDKEY,
        DragRequestID::GET_SHADOW_OFFSET, DragRequestID::GET_DRAG_DATA,
        DragRequestID::GET_DRAG_STATE, DragRequestID::GET_DRAG_SUMMARY,
        DragRequestID::GET_DRAG_ACTION, DragRequestID::GET_EXTRA_INFO};
    for (const auto& dragRequestID : dragRequestIDs) {
        if (dragRequestID == DragRequestID::UNKNOWN_DRAG_ACTION ||
            dragRequestID == DragRequestID::GET_UDKEY ||
            dragRequestID == DragRequestID::GET_DRAG_DATA ||
            dragRequestID == DragRequestID::GET_DRAG_SUMMARY ||
            dragRequestID == DragRequestID::GET_DRAG_ACTION||
            dragRequestID == DragRequestID::GET_EXTRA_INFO) {
                ret = g_intentionService->GetParam(Intention::DRAG, dragRequestID, dataParcel, replyParcel);
                if (ret == RET_OK) {
                    GTEST_LOG_(INFO) << "dragRequestID: " << dragRequestID;
                }
                EXPECT_EQ(ret, RET_ERR);
        } else {
            ret = g_intentionService->GetParam(Intention::DRAG, dragRequestID, dataParcel, replyParcel);
            EXPECT_EQ(ret, RET_OK);
        }
    }
}

/**
 * @tc.name: IntentionServiceTest_GetParam002
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_DRAG_TARGET_PID,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionServiceTest_GetParam003
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam003, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    DRAG_DATA_MGR.Init(dragData.value());
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_UDKEY,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
    DRAG_DATA_MGR.dragData_ = {};
}

/**
 * @tc.name: IntentionServiceTest_GetParam004
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam004, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(g_intention, DragRequestID::GET_SHADOW_OFFSET,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_GetParam005
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam005, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(g_intention, DragRequestID::GET_DRAG_DATA,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_GetParam006
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam006, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_DRAG_STATE,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: IntentionServiceTest_GetParam007
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam007, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_DRAG_SUMMARY,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_GetParam008
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam008, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(g_intention, DragRequestID::GET_DRAG_ACTION,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_GetParam009
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam009, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(g_intention, DragRequestID::GET_EXTRA_INFO, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_GetParam010
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam010, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(g_intention, DragRequestID::GET_UDKEY, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest_GetParam011
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam011, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    DRAG_DATA_MGR.Init(dragData.value());
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_SHADOW_OFFSET,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
    DRAG_DATA_MGR.dragData_ = {};
}

/**
 * @tc.name: IntentionServiceTest_GetParam012
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam012, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    DRAG_DATA_MGR.Init(dragData.value());
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_EXTRA_INFO,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
    DRAG_DATA_MGR.dragData_ = {};
}

/**
 * @tc.name: IntentionServiceTest_GetParam013
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam013, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    env->dragMgr_.dragState_ = DragState::START;
    UpdateDragStyleParam param { DragCursorStyle::COPY, -1 };
    bool ret = param.Marshalling(dataParcel);
    EXPECT_EQ(ret, READ_OK);
    ret = g_intentionService->GetParam(g_intention, DragRequestID::UPDATE_DRAG_STYLE, dataParcel, replyParcel);
    EXPECT_TRUE(ret);
    env->dragMgr_.dragState_ = DragState::STOP;
}

/**
 * @tc.name: IntentionServiceTest_GetParam014
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam014, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    MessageParcel dataParcel;
    MessageParcel replyParcel;
    env->dragMgr_.dragState_ = DragState::START;
    GetDragTargetPidReply targetPidReply { IPCSkeleton::GetCallingPid() };
    bool ret = targetPidReply.Marshalling(dataParcel);
    EXPECT_EQ(ret, READ_OK);
    ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_DRAG_TARGET_PID, dataParcel, replyParcel);
    EXPECT_FALSE(ret);
    env->dragMgr_.dragState_ = DragState::STOP;
}

/**
 * @tc.name: IntentionServiceTest_GetParam015
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam015, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    env->dragMgr_.dragState_ = DragState::START;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    DRAG_DATA_MGR.Init(dragData.value());
    int32_t ret = g_intentionService->GetParam(g_intention, DragRequestID::GET_DRAG_DATA, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
    DRAG_DATA_MGR.dragData_ = {};
    ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_DRAG_DATA, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
    env->dragMgr_.dragState_ = DragState::STOP;
}

/**
 * @tc.name: IntentionServiceTest_GetParam016
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam016, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    env->dragMgr_.dragState_ = DragState::ERROR;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_DRAG_STATE,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
    env->dragMgr_.dragState_ = DragState::START;
    ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_DRAG_STATE, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
    env->dragMgr_.dragState_ = DragState::STOP;
}

/**
 * @tc.name: IntentionServiceTest_GetParam017
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam017, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    env->dragMgr_.dragState_ = DragState::ERROR;
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    int32_t ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_DRAG_ACTION,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
    env->dragMgr_.dragState_ = DragState::START;
    ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_DRAG_ACTION, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
    env->dragMgr_.dragState_ = DragState::STOP;
}

/**
 * @tc.name: IntentionServiceTest_GetParam018
 * @tc.desc: Test GetParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetParam018, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    MessageParcel replyParcel;
    MessageParcel dataParcel;
    DRAG_DATA_MGR.Init(dragData.value());
    int32_t ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_EXTRA_INFO,
        dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_OK);
    DRAG_DATA_MGR.dragData_ = {};
    ret = g_intentionService->GetParam(Intention::DRAG, DragRequestID::GET_EXTRA_INFO, dataParcel, replyParcel);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionDumper_Dump
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionDumper_Dump, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t fd = 1;
    std::vector<std::string> args {"help", "subscribe", "list", "current", "drag", "macroState", "unknow"};
    ASSERT_NO_FATAL_FAILURE(g_intentionDumper->Dump(fd, args));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS