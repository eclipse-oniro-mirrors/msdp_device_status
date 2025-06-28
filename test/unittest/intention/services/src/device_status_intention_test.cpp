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
#include "drag_server.h"
#include "dsoftbus_adapter.h"
#include "fi_log.h"
#include "input_adapter.h"
#include "intention_service.h"
#include "interaction_manager.h"
#include "ipc_skeleton.h"
#include "plugin_manager.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusIntentionTest"

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
std::shared_ptr<ContextService> g_context { nullptr };
std::shared_ptr<IntentionService> g_intentionService { nullptr };
std::shared_ptr<IntentionService> g_intentionServiceNullptr { nullptr };
sptr<IRemoteDevStaCallback> stationaryCallback_;
IContext *g_contextNullptr { nullptr };
int32_t PERMISSION_EXCEPTION { 201 };
constexpr int32_t RET_NO_SUPPORT = 801;
constexpr float DOUBLEPIMAX = 6.3F;
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

void DeviceStatusIntentionTest::SetUpTestCase()
{
    g_intentionService = std::make_shared<IntentionService>(ContextService::GetInstance());
    g_intentionServiceNullptr = std::make_shared<IntentionService>(g_contextNullptr);
}

void DeviceStatusIntentionTest::TearDownTestCase()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_intentionServiceNullptr = nullptr;
}

void DeviceStatusIntentionTest::SetUp()
{
    stationaryCallback_ = new (std::nothrow) TestDevStaCallback();
}

void DeviceStatusIntentionTest::TearDown() {}

std::shared_ptr<Media::PixelMap> DeviceStatusIntentionTest::CreatePixelMap(int32_t width, int32_t height)
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

std::optional<DragData> DeviceStatusIntentionTest::CreateDragData(int32_t sourceType,
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

void DeviceStatusIntentionTest::AssignToAnimation(PreviewAnimation &animation)
{
    animation.duration = ANIMATION_DURATION;
    animation.curveName = CURVE_NAME;
    animation.curve = { 0.33, 0, 0.67, 1 };
}

/**
 * @tc.name: DeviceStatusIntentionTest_1
 * @tc.desc: Test Socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_Socket001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto programName = GetProgramName();
    int32_t socketFd { -1 };
    int32_t tokenType { -1 };
    int32_t ret = g_intentionService->Socket(programName, CONNECT_MODULE_TYPE_FI_CLIENT, socketFd, tokenType);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DeviceStatusIntentionTest2
 * @tc.desc: Test EnableCooperate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_EnableCooperate001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t userData = 0;
    ErrCode ret = g_intentionService->EnableCooperate(userData);
    EXPECT_EQ(ret, PERMISSION_EXCEPTION);
}


/**
 * @tc.name: DeviceStatusIntentionTest3
 * @tc.desc: Test DisableCooperate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_DisableCooperate001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t userData = 0;
    ErrCode ret = g_intentionService->DisableCooperate(userData);
    EXPECT_EQ(ret, PERMISSION_EXCEPTION);
}
/**
 * @tc.name: DeviceStatusIntentionTest4
 * @tc.desc: Test StartCooperate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_StartCooperate001, TestSize.Level0)
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
 * @tc.name: DeviceStatusIntentionTest_StartCooperateWithOptions001
 * @tc.desc: Test StartCooperate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_StartCooperateWithOptions001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string remoteNetworkId = "networkId";
    int32_t userData = 0;
    int32_t startDeviceId = 0;
    bool isCheckPermission = true;
    CooperateOptions options {
            .displayX = 500,
            .displayY = 500,
            .displayId = 1
    };
    SequenceableCooperateOptions sequenceableCooperateOptions(options);
    ErrCode ret = g_intentionService->StartCooperateWithOptions(remoteNetworkId, userData, startDeviceId,
        isCheckPermission, sequenceableCooperateOptions);
    EXPECT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: DeviceStatusIntentionTest5
 * @tc.desc: Test RegisterCooperateListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_RegisterCooperateListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionService->RegisterCooperateListener();
    EXPECT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: DeviceStatusIntentionTest6
 * @tc.desc: Test UnregisterCooperateListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_UnregisterCooperateListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionService->UnregisterCooperateListener();
    EXPECT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: DeviceStatusIntentionTest7
 * @tc.desc: Test RegisterHotAreaListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_RegisterHotAreaListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t userData = 0;
    bool isCheckPermission = true;
    ErrCode ret = g_intentionServiceNullptr->RegisterHotAreaListener(userData, isCheckPermission);
    EXPECT_EQ(ret, RET_ERR);
}
/**
 * @tc.name: DeviceStatusIntentionTest8
 * @tc.desc: Test UnregisterHotAreaListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_UnregisterHotAreaListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ErrCode ret = g_intentionServiceNullptr->UnregisterHotAreaListener();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DeviceStatusIntentionTest9
 * @tc.desc: Test RegisterMouseEventListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_RegisterMouseEventListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string networkId = "networkId";
    ErrCode ret = g_intentionServiceNullptr->RegisterMouseEventListener(networkId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DeviceStatusIntentionTest10
 * @tc.desc: Test UnregisterMouseEventListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_UnregisterMouseEventListener001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string networkId = "networkId";
    ErrCode ret = g_intentionServiceNullptr->UnregisterMouseEventListener(networkId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DeviceStatusIntentionTest11
 * @tc.desc: Test GetCooperateStateSync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_GetCooperateStateSync001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string udid = "udid";
    bool state = true;
    ErrCode ret = g_intentionServiceNullptr->GetCooperateStateSync(udid, state);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DeviceStatusIntentionTest12
 * @tc.desc: Test GetCooperateStateAsync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_GetCooperateStateAsync001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string networkId = "networkId";
    int32_t userData = 0;
    bool isCheckPermission = true;
    ErrCode ret = g_intentionServiceNullptr->GetCooperateStateAsync(networkId, userData, isCheckPermission);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DeviceStatusIntentionTest13
 * @tc.desc: Test SetDamplingCoefficient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_SetDamplingCoefficient001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint32_t direction = 0;
    double coefficient = 0;
    ErrCode ret = g_intentionServiceNullptr->RegisterHotAreaListener(direction, coefficient);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DeviceStatusIntentionTest14
 * @tc.desc: Test StartDrag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceStatusIntentionTest, DeviceStatusIntentionTest_StartDrag001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    SequenceableDragData sequenceableDragData(dragData);
    ErrCode ret = g_intentionServiceNullptr->StartDrag(sequenceableDragData);
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS