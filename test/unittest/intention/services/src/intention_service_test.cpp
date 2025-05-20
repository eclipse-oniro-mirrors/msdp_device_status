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
constexpr int32_t PIXEL_MAP_WIDTH { 3 };
constexpr int32_t PIXEL_MAP_HEIGHT { 3 };
constexpr int32_t WINDOW_ID { -1 };
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
const std::string FILTER_INFO { "Undefined filter info" };
const std::string UD_KEY { "Unified data key" };
const std::string EXTRA_INFO { "Undefined extra info" };
const std::string CURVE_NAME { "cubic-bezier" };
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
std::shared_ptr g_context { nullptr };
std::shared_ptr g_intentionService { nullptr };
std::shared_ptr g_intentionServiceNullptr { nullptr };
IContext *g_contextNullptr { nullptr };
int32_t PERMISSION_EXCEPTION { 201 };
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
    std::call_once(flag, & {
        g_context = std::make_shared();
    });
    return g_context.get();
}

ContextService::ContextService()
{
    ddm_ = std::make_unique();
    input_ = std::make_unique();
    pluginMgr_ = std::make_unique(this);
    dsoftbus_ = std::make_unique();
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
    g_intentionService = std::make_shared(ContextService::GetInstance());
    g_intentionServiceNullptr = std::make_shared(g_contextNullptr);
}

void IntentionServiceTest::TearDownTestCase()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_intentionServiceNullptr = nullptr;
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

std::optional IntentionServiceTest::CreateDragData(int32_t sourceType,
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
 * @tc.desc: Test Socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_Socket001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto programName = GetProgramName();
    int32_t socketFd { -1 };
    int32_t tokenType { -1 };
    int32_t ret = g_intentionService->Socket(programName, CONNECT_MODULE_TYPE_FI_CLIENT, socketFd, tokenType);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest2
 * @tc.desc: Test EnableCooperate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_EnableCooperate001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t userData = 0;
    ErrCode ret = g_intentionService->EnableCooperate(userData);
    EXPECT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: IntentionServiceTest3
 * @tc.desc: Test DisableCooperate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_DisableCooperate001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t userData = 0;
    ErrCode ret = g_intentionService->DisableCooperate(userData);
    EXPECT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: IntentionServiceTest4
 * @tc.desc: Test StartCooperate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_StartCooperate001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string remoteNetworkId = "networkId";
    int32_t userData = 0;
    int32_t startDeviceId = 0;
    bool isCheckPermission = true;
    ErrCode ret = g_intentionService->StartCooperate(remoteNetworkId, userData, startDeviceId, isCheckPermission);
    EXPECT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: IntentionServiceTest5
 * @tc.desc: Test RegisterCooperateListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_RegisterCooperateListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionService->RegisterCooperateListener();
    EXPECT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: IntentionServiceTest6
 * @tc.desc: Test UnregisterCooperateListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_UnregisterCooperateListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionService->UnregisterCooperateListener();
    EXPECT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: IntentionServiceTest7
 * @tc.desc: Test RegisterHotAreaListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_RegisterHotAreaListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t userData = 0;
    bool isCheckPermission = true;
    ErrCode ret = g_intentionServiceNullptr->RegisterHotAreaListener(userData, isCheckPermission);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest8
 * @tc.desc: Test UnregisterHotAreaListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_UnregisterHotAreaListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionServiceNullptr->UnregisterHotAreaListener();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest9
 * @tc.desc: Test RegisterMouseEventListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_RegisterMouseEventListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string networkId = "networkId";
    ErrCode ret = g_intentionServiceNullptr->RegisterMouseEventListener(networkId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest10
 * @tc.desc: Test UnregisterMouseEventListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_UnregisterMouseEventListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string networkId = "networkId";
    ErrCode ret = g_intentionServiceNullptr->UnregisterMouseEventListener(networkId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest11
 * @tc.desc: Test GetCooperateStateSync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetCooperateStateSync001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string udid = "udid";
    bool state = true;
    ErrCode ret = g_intentionServiceNullptr->GetCooperateStateSync(udid, state);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest12
 * @tc.desc: Test GetCooperateStateAsync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetCooperateStateAsync001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string networkId = "networkId";
    int32_t userData = 0;
    bool isCheckPermission = true;
    ErrCode ret = g_intentionServiceNullptr->GetCooperateStateAsync(networkId, userData, isCheckPermission);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest13
 * @tc.desc: Test SetDamplingCoefficient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetDamplingCoefficient001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint32_t direction = 0;
    double coefficient = 0;
    ErrCode ret = g_intentionServiceNullptr->RegisterHotAreaListener(direction, coefficient);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest14
 * @tc.desc: Test StartDrag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_StartDrag001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    SequenceableDragData sequenceableDragData(dragData);
    ErrCode ret = g_intentionServiceNullptr->StartDrag(sequenceableDragData);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest15
 * @tc.desc: Test StopDrag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_StopDrag001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    SequenceableDragResult sequenceableDragResult(dropResult);
    ErrCode ret = g_intentionServiceNullptr->StopDrag(sequenceableDragResult);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest16
 * @tc.desc: Test AddDraglistener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_AddDraglistener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool isJsCaller = true;
    ErrCode ret = g_intentionServiceNullptr->AddDraglistener(isJsCaller);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest17
 * @tc.desc: Test RemoveDraglistener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_RemoveDraglistener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool isJsCaller = true;
    ErrCode ret = g_intentionServiceNullptr->RemoveDraglistener(isJsCaller);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest18
 * @tc.desc: Test AddSubscriptListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_AddSubscriptListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionServiceNullptr->AddSubscriptListener();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest19
 * @tc.desc: Test RemoveSubscriptListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_RemoveSubscriptListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionServiceNullptr->RemoveSubscriptListener();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest20
 * @tc.desc: Test SetDragWindowVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetDragWindowVisible001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragVisibleParam dragVisibleParam;
    SequenceableDragVisible sequenceableDragVisible(dragVisibleParam);
    ErrCode ret = g_intentionServiceNullptr->SetDragWindowVisible(sequenceableDragVisible);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest21
 * @tc.desc: Test UpdateDragStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_UpdateDragStyle001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t style = 0;
    int32_t eventId = 0;
    ErrCode ret = g_intentionServiceNullptr->UpdateDragStyle(style, eventId);
    EXPECT_EQ(ret, RET_ERR);
}

/**

 * @tc.name: IntentionServiceTest22
 * @tc.desc: Test UpdateShadowPic
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_UpdateShadowPic001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ErrCode ret = g_intentionServiceNullptr->UpdateShadowPic(pixelMap, 0, 0);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest23
 * @tc.desc: Test GetDragTargetPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetDragTargetPid001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t targetPid = 0;
    ErrCode ret = g_intentionServiceNullptr->GetDragTargetPid(targetPid);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest24
 * @tc.desc: GetUdKey
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetUdKey001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string udKey = "udkey";
    ErrCode ret = g_intentionServiceNullptr->GetUdKey(udKey);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest25
 * @tc.desc: Test GetShadowOffset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetShadowOffset001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t offsetX = 1;
    int32_t offsetY = 1;
    int32_t width = 1;
    int32_t height = 1;
    ErrCode ret = g_intentionServiceNullptr->GetShadowOffset(offsetX, offsetY, width, height);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest26
 * @tc.desc: Test GetDragData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetDragData001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    SequenceableDragData sequenceableDragData(dragData);
    ErrCode ret = g_intentionServiceNullptr->GetDragData(sequenceableDragData);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest27
 * @tc.desc: Test UpdatePreviewStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_UpdatePreviewStyle001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyle;
    SequenceablePreviewStyle sequenceablePreviewStyle(previewStyle);
    ErrCode ret = g_intentionServiceNullptr->UpdatePreviewStyle(sequenceablePreviewStyle);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest28
 * @tc.desc: Test UpdatePreviewStyleWithAnimation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_UpdatePreviewStyleWithAnimation001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyle;
    PreviewAnimation previewAnimation;
    SequenceablePreviewAnimation sequenceablePreviewAnimation(previewStyle, previewAnimation);
    ErrCode ret = g_intentionServiceNullptr->UpdatePreviewStyleWithAnimation(sequenceablePreviewAnimation);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest29
 * @tc.desc: Test RotateDragWindowSync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_RotateDragWindowSync001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptrRosen::RSTransaction rsTransaction { nullptr };
    SequenceableRotateWindow sequenceableRotateWindow(rsTransaction);
    ErrCode ret = g_intentionServiceNullptr->RotateDragWindowSync(sequenceableRotateWindow);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest30
 * @tc.desc: Test SetDragWindowScreenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetDragWindowScreenId001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionServiceNullptr->SetDragWindowScreenId(0, 0);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest31
 * @tc.desc: Test GetDragSummary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetDragSummary001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::map<std::string, int64_t> summarys;
    bool isJsCaller = true;
    ErrCode ret = g_intentionServiceNullptr->GetDragSummary(summarys, isJsCaller);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest32
 * @tc.desc: Test SetDragSwitchState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetDragSwitchState001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool enable = true;
    bool isJsCaller = true;
    ErrCode ret = g_intentionServiceNullptr->SetDragSwitchState(enable, isJsCaller);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest33
 * @tc.desc: Test SetAppDragSwitchState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetAppDragSwitchState001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool enable = true;
    std::string pkgName = "pkg";
    bool isJsCaller = true;
    ErrCode ret = g_intentionServiceNullptr->SetAppDragSwitchState(enable, pkgName, isJsCaller);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest34
 * @tc.desc: Test GetDragState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetDragState001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t dragState = 0;
    ErrCode ret = g_intentionServiceNullptr->GetDragState(dragState);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest35
 * @tc.desc: Test EnableUpperCenterMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_EnableUpperCenterMode001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool enable = true;
    ErrCode ret = g_intentionServiceNullptr->EnableUpperCenterMode(enable);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest36
 * @tc.desc: Test GetDragAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetDragAction001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t dragAction = 0;
    ErrCode ret = g_intentionServiceNullptr->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest37
 * @tc.desc: Test GetExtraInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetExtraInfo001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string extraInfo = "extraInfo";
    ErrCode ret = g_intentionServiceNullptr->GetExtraInfo(extraInfo);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest38
 * @tc.desc: Test AddPrivilege
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_AddPrivilege001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionServiceNullptr->AddPrivilege();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest39
 * @tc.desc: Test EraseMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_EraseMouseIcon001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionServiceNullptr->EraseMouseIcon();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest40
 * @tc.desc: Test SetMouseDragMonitorState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetMouseDragMonitorState001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool state = true;
    ErrCode ret = g_intentionServiceNullptr->SetMouseDragMonitorState(state);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest41
 * @tc.desc: Test SetDraggableState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetDraggableState001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool state = true;
    ErrCode ret = g_intentionServiceNullptr->SetDraggableState(state);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest42
 * @tc.desc: Test GetAppDragSwitchState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_GetAppDragSwitchState001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool state = true;
    ErrCode ret = g_intentionServiceNullptr->GetAppDragSwitchState(state);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: IntentionServiceTest43
 * @tc.desc: Test SetDraggableStateAsync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IntentionServiceTest_SetDraggableStateAsync001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool state = true;
    int64_t downTime = 6;
    ErrCode ret = g_intentionServiceNullptr->SetDraggableStateAsync(state, downTime);
    EXPECT_EQ(ret, RET_ERR);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS