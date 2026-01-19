/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "intention_service_cover_test.h"

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
const std::string TEST_METADATA { "{\"key\":\"value\",\"type\":\"test\"}" };
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
std::shared_ptr<ContextService> g_context { nullptr };
std::shared_ptr<IntentionService> g_intentionService { nullptr };
std::shared_ptr<IntentionService> g_intentionServiceNullptr { nullptr };
sptr<IRemoteDevStaCallback> stationaryCallback_;
IContext *g_contextNullptr { nullptr };
DragManager g_dragMgr;
constexpr int32_t RET_NO_SUPPORT = 801;
const std::string SIGNATURE { "signature" };
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
    return g_dragMgr;
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
}

void IntentionServiceTest::TearDownTestCase()
{
    if (g_intentionService != nullptr) {
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
        g_intentionService->drag_.universalDragWrapper_.universalDragHandle_ = nullptr;
#endif // OHOS_BUILD_UNIVERSAL_DRAG
        g_intentionService->onScreen_.handle_.pAlgorithm = nullptr;
        g_intentionService = nullptr;
    }
    g_intentionServiceNullptr = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void IntentionServiceTest::SetUp()
{
    stationaryCallback_ = new (std::nothrow) TestDevStaCallback();
}

void IntentionServiceTest::TearDown() {}

class IRemoteOnScreenCallbackTest : public OnScreen::IRemoteOnScreenCallback {
public:
    void OnScreenChange(const std::string &changeInfo) override{};
    void OnScreenAwareness(const OnScreen::OnscreenAwarenessInfo &info) override{};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

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

void IntentionServiceTest::IntentionServiceTestCallback::OnNotifyMetadata(const std::string& metadata)
{
    FI_HILOGI("OnNotifyMetadata");
}

sptr<IRemoteObject> IntentionServiceTest::IntentionServiceTestCallback::AsObject()
{
    return nullptr;
}

void IntentionServiceTest::IntentionServiceTestCallback::OnScreenshotResult(const BoomerangData& screenshotData)
{
    FI_HILOGI("OnScreenshotResult");
}

void IntentionServiceTest::IntentionServiceTestCallback::OnEncodeImageResult(std::shared_ptr<Media::PixelMap> pixelMap)
{
    FI_HILOGI("OnEncodeImageResult");
}

/**
 * @tc.name: IsDragStart001
 * @tc.desc: Test IsDragStart
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IsDragStart001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isStart;
    int32_t ret = g_intentionService->IsDragStart(isStart);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SubscribeCallback001
 * @tc.desc: Test SubscribeCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, SubscribeCallback001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t type = Type::TYPE_STILL;
    std::string bundleName = "com.example.test";
    sptr<IRemoteBoomerangCallback> subCallback = new (std::nothrow) IntentionServiceTestCallback();
    int32_t ret = g_intentionService->SubscribeCallback(type, bundleName, subCallback);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: SubscribeCallback002
 * @tc.desc: Test SubscribeCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, SubscribeCallback002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t type = Type::TYPE_STILL;
    std::string bundleName = "com.example.test";
    sptr<IRemoteBoomerangCallback> subCallback = new (std::nothrow) IntentionServiceTestCallback();
    int32_t ret = g_intentionService->SubscribeCallback(type, bundleName, subCallback);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    ret = g_intentionService->UnsubscribeCallback(type, bundleName, subCallback);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: NotifyMetadataBindingEvent001
 * @tc.desc: Test NotifyMetadataBindingEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, NotifyMetadataBindingEvent001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string bundleName = "com.example.test";
    sptr<IRemoteBoomerangCallback> notifyCallback = new (std::nothrow) IntentionServiceTestCallback();
    int32_t ret = g_intentionService->NotifyMetadataBindingEvent(bundleName, notifyCallback);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: SubmitMetadata001
 * @tc.desc: Test SubmitMetadata
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, SubmitMetadatak001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string metaData = TEST_METADATA;
    int32_t ret = g_intentionService->SubmitMetadata(metaData);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: BoomerangEncodeImage001
 * @tc.desc: Test BoomerangEncodeImage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, BoomerangEncodeImage001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string metaData = {"name"};
    std::shared_ptr<PixelMap> pixelMap = CreatePixelMap(1, 1);
    sptr<IRemoteBoomerangCallback> notifyCallback = new (std::nothrow) IntentionServiceTestCallback();
    int32_t ret = g_intentionService->BoomerangEncodeImage(pixelMap, metaData, notifyCallback);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: BoomerangDecodeImage001
 * @tc.desc: Test BoomerangDecodeImage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, BoomerangDecodeImage001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PixelMap> pixelMap = CreatePixelMap(1, 1);
    sptr<IRemoteBoomerangCallback> notifyCallback = new (std::nothrow) IntentionServiceTestCallback();
    int32_t ret = g_intentionService->BoomerangDecodeImage(pixelMap, notifyCallback);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: RegisterScreenEventCallback001
 * @tc.desc: Test RegisterScreenEventCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, RegisterScreenEventCallback001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = WINDOW_ID;
    const std::string event = "";
    sptr<IRemoteOnScreenCallback> onScreenCallback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    int32_t ret = g_intentionService->RegisterScreenEventCallback(windowId, event, onScreenCallback);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: UnregisterScreenEventCallback001
 * @tc.desc: Test UnregisterScreenEventCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, UnregisterScreenEventCallback001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = WINDOW_ID;
    const std::string event = "";
    sptr<IRemoteOnScreenCallback> onScreenCallback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    int32_t ret = g_intentionService->UnregisterScreenEventCallback(windowId, event, onScreenCallback);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: IsParallelFeatureEnabled001
 * @tc.desc: Test IsParallelFeatureEnabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, IsParallelFeatureEnabled001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = WINDOW_ID;
    int32_t outStatus = 0;
    int32_t ret = g_intentionService->IsParallelFeatureEnabled(windowId, outStatus);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: GetLiveStatus001
 * @tc.desc: Test GetLiveStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, GetLiveStatus001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_intentionService->GetLiveStatus();
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

/**
 * @tc.name: RegisterAwarenessCallback001
 * @tc.desc: Test RegisterAwarenessCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceTest, RegisterAwarenessCallback001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    sptr<IRemoteOnScreenCallback> onScreenCallback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    OnScreen::AwarenessCap option;
    OnScreen::SequenceableOnscreenAwarenessCap cap(option);
    OnScreen::SequenceableOnscreenAwarenessOption awarenessOption;
    int32_t ret = g_intentionService->RegisterAwarenessCallback(cap, onScreenCallback, awarenessOption);
    EXPECT_EQ(ret, RET_NO_SUPPORT);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS