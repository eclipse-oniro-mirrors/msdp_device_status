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
#include "intention_service_new_test.h"
 
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
#include "iremote_on_screen_callback.h"
#ifdef DEVICE_STATUS_CAR_AWARENESS_ENABLE
#include "car_awareness_callback_stub.h"
#include "sequenceable_car_awareness_option.h"
#include "sequenceable_car_awareness_event_array.h"
#endif // DEVICE_STATUS_CAR_AWARENESS_ENABLE

#undef LOG_TAG
#define LOG_TAG "IntentionServiceNewTest"
 
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr int32_t PIXEL_MAP_WIDTH{3};
constexpr int32_t PIXEL_MAP_HEIGHT{3};
constexpr uint32_t DEFAULT_ICON_COLOR{0xFF};
const std::string FILTER_INFO{"Undefined filter info"};
const std::string UD_KEY{"Unified data key"};
const std::string EXTRA_INFO{"Undefined extra info"};
const std::string CURVE_NAME{"cubic-bezier"};
constexpr int32_t DISPLAY_ID{0};
constexpr int32_t DISPLAY_X{50};
constexpr int32_t DISPLAY_Y{50};
constexpr int32_t INT32_BYTE{4};
int32_t g_shadowinfoX{0};
int32_t g_shadowinfoY{0};
constexpr int32_t ANIMATION_DURATION{500};
constexpr int32_t MAX_PIXEL_MAP_WIDTH{600};
constexpr int32_t MAX_PIXEL_MAP_HEIGHT{600};
constexpr bool HAS_CANCELED_ANIMATION{true};
std::shared_ptr<ContextService> g_context{nullptr};
DragManager g_dragMgr;
}  // namespace
 
int32_t MockDelegateTasks::PostSyncTask(DTaskCallback callback)
{
    return callback();
}
 
int32_t MockDelegateTasks::PostAsyncTask(DTaskCallback callback)
{
    return callback();
}
 
ContextService *ContextService::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() { g_context = std::make_shared<ContextService>(); });
    return g_context.get();
}
 
ContextService::ContextService()
{
    ddm_ = std::make_unique<DDMAdapter>();
    input_ = std::make_unique<InputAdapter>();
    pluginMgr_ = std::make_unique<PluginManager>(this);
    dsoftbus_ = std::make_unique<DSoftbusAdapter>();
}
 
IDelegateTasks &ContextService::GetDelegateTasks()
{
    return delegateTasks_;
}
 
IDeviceManager &ContextService::GetDeviceManager()
{
    return devMgr_;
}
 
ITimerManager &ContextService::GetTimerManager()
{
    return timerMgr_;
}
 
IDragManager &ContextService::GetDragManager()
{
    return g_dragMgr;
}
 
ISocketSessionManager &ContextService::GetSocketSessionManager()
{
    return socketSessionMgr_;
}
 
IDDMAdapter &ContextService::GetDDM()
{
    return *ddm_;
}
 
IPluginManager &ContextService::GetPluginManager()
{
    return *pluginMgr_;
}
 
IInputAdapter &ContextService::GetInput()
{
    return *input_;
}
 
IDSoftbusAdapter &ContextService::GetDSoftbus()
{
    return *dsoftbus_;
}
 
void IntentionServiceNewTest::SetUpTestCase()
{}
 
void IntentionServiceNewTest::TearDownTestCase()
{}
 
void IntentionServiceNewTest::SetUp()
{
    intentionService_ = std::make_shared<IntentionService>(ContextService::GetInstance());
}
 
void IntentionServiceNewTest::TearDown()
{
    if (intentionService_!= nullptr) {
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
        intentionService_->drag_.universalDragWrapper_.universalDragHandle_ = nullptr;
#endif // OHOS_BUILD_UNIVERSAL_DRAG
        intentionService_ = nullptr;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}
 
class IRemoteOnScreenCallbackTest : public OnScreen::IRemoteOnScreenCallback {
public:
    void OnScreenChange(const std::string &changeInfo) override{};
    void OnScreenAwareness(const OnScreen::OnscreenAwarenessInfo &info) override{};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};
 
std::shared_ptr<Media::PixelMap> IntentionServiceNewTest::CreatePixelMap(int32_t width, int32_t height)
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
 
std::optional<DragData> IntentionServiceNewTest::CreateDragData(
    int32_t sourceType, int32_t pointerId, int32_t dragNum, bool hasCoordinateCorrected, int32_t shadowNum)
{
    CALL_DEBUG_ENTER;
    DragData dragData;
    for (int32_t i = 0; i < shadowNum; i++) {
        std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
        if (pixelMap == nullptr) {
            FI_HILOGE("pixelMap nullptr");
            return std::nullopt;
        }
        dragData.shadowInfos.push_back({pixelMap, g_shadowinfoX, g_shadowinfoY});
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
 
void IntentionServiceNewTest::AssignToAnimation(PreviewAnimation &animation)
{
    animation.duration = ANIMATION_DURATION;
    animation.curveName = CURVE_NAME;
    animation.curve = {0.33, 0, 0.67, 1};
}
 
/**
 * @tc.name: RegisterAwarenessCallback
 * @tc.desc: Check RegisterAwarenessCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceNewTest, RegisterAwarenessCallback, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OnScreen::AwarenessCap option;
    OnScreen::SequenceableOnscreenAwarenessCap cap(option);
    OnScreen::SequenceableOnscreenAwarenessOption awarenessOption;
    sptr<IRemoteOnScreenCallbackTest> callback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    EXPECT_NE(intentionService_, nullptr);
    auto result = intentionService_->RegisterAwarenessCallback(cap, callback, awarenessOption);
    EXPECT_NE(result, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}
 
/**
 * @tc.name: UnregisterAwarenessCallback
 * @tc.desc: Check UnregisterAwarenessCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceNewTest, UnregisterAwarenessCallback, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OnScreen::AwarenessCap option;
    OnScreen::SequenceableOnscreenAwarenessCap cap(option);
    sptr<IRemoteOnScreenCallbackTest> callback = new (std::nothrow) IRemoteOnScreenCallbackTest();
    EXPECT_NE(intentionService_, nullptr);
    auto result = intentionService_->UnregisterAwarenessCallback(cap, callback);
    EXPECT_NE(result, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}
 
/**
 * @tc.name: Trigger
 * @tc.desc: Check Trigger
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceNewTest, Trigger, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OnScreen::AwarenessCap option;
    OnScreen::SequenceableOnscreenAwarenessCap cap(option);
    OnScreen::SequenceableOnscreenAwarenessInfo info;
    OnScreen::SequenceableOnscreenAwarenessOption awarenessOption;
    EXPECT_NE(intentionService_, nullptr);
    auto result = intentionService_->Trigger(cap, awarenessOption, info);
    EXPECT_NE(result, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}


#ifdef DEVICE_STATUS_CAR_AWARENESS_ENABLE
class TestCarAwarenessCallback : public CarAwarenessCallbackStub {
public:
    void OnAwarenessEvent(const CarAwarenessEvent &event) override
    {
        FI_HILOGI("OnAwarenessEvent called, type:%{public}d", event.type);
    }
};

/**
 * @tc.name: IntentionServiceNewTest_SubscribeCapability_001
 * @tc.desc: Test SubscribeCapability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceNewTest, IntentionServiceNewTest_SubscribeCapability_001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    SequenceableCarAwarenessOption option;
    sptr<TestCarAwarenessCallback> callback = new (std::nothrow) TestCarAwarenessCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_NE(intentionService_, nullptr);
    ErrCode ret = intentionService_->SubscribeCapability(1, option, callback);
    EXPECT_NE(ret, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: IntentionServiceNewTest_UnSubscribeCapability_001
 * @tc.desc: Test UnSubscribeCapability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceNewTest, IntentionServiceNewTest_UnSubscribeCapability_001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    SequenceableCarAwarenessOption option;
    sptr<TestCarAwarenessCallback> callback = new (std::nothrow) TestCarAwarenessCallback();
    ASSERT_NE(callback, nullptr);
    EXPECT_NE(intentionService_, nullptr);
    ErrCode ret = intentionService_->UnSubscribeCapability(1, option, callback);
    EXPECT_EQ(ret, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: IntentionServiceNewTest_UpdateSpatialActionStatus_001
 * @tc.desc: Test UpdateSpatialActionStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceNewTest, IntentionServiceNewTest_UpdateSpatialActionStatus_001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    EXPECT_NE(intentionService_, nullptr);
    ErrCode ret = intentionService_->UpdateSpatialActionStatus(1);
    EXPECT_NE(ret, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: IntentionServiceNewTest_UpdateSpatialActionZone_001
 * @tc.desc: Test UpdateSpatialActionZone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceNewTest, IntentionServiceNewTest_UpdateSpatialActionZone_001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    EXPECT_NE(intentionService_, nullptr);
    ErrCode ret = intentionService_->UpdateSpatialActionZone(1);
    EXPECT_NE(ret, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: IntentionServiceNewTest_GetSupportCapabilityList_001
 * @tc.desc: Test GetSupportCapabilityList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceNewTest, IntentionServiceNewTest_GetSupportCapabilityList_001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> capabilities;
    EXPECT_NE(intentionService_, nullptr);
    ErrCode ret = intentionService_->GetSupportCapabilityList(capabilities);
    EXPECT_EQ(ret, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: IntentionServiceNewTest_GetCarAwareness_001
 * @tc.desc: Test GetCarAwareness
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentionServiceNewTest, IntentionServiceNewTest_GetCarAwareness_001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    SequenceableCarAwarenessOption option;
    SequenceableCarAwarenessEventArray events;
    ErrCode ret = intentionService_->GetCarAwareness(1, option, events);
    EXPECT_TRUE(ret == 0 || ret == -1);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}
#endif // DEVICE_STATUS_CAR_AWARENESS_ENABLE
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS