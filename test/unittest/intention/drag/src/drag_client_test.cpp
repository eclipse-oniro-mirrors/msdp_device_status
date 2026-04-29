/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "drag_client_test.h"
#include "ddm_adapter.h"
#include "devicestatus_service.h"
#include "drag_data_manager.h"
#include "drag_client.h"
#include "interaction_manager.h"
#include "ipc_skeleton.h"
#include "singleton.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr int32_t PIXEL_MAP_WIDTH { 3 };
constexpr int32_t PIXEL_MAP_HEIGHT { 3 };
constexpr int32_t PROMISE_WAIT_SPAN_MS { 2000 };
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
const std::string FILTER_INFO { "Undefined filter info" };
const std::string UD_KEY { "Unified data key" };
const std::string EXTRA_INFO { "Undefined extra info" };
const std::string CURVE_NAME { "cubic-bezier" };
constexpr int32_t DISPLAY_ID { 0 };
constexpr int32_t DISPLAY_X { 50 };
constexpr int32_t DISPLAY_Y { 50 };
constexpr int32_t INT32_BYTE { 4 };
int32_t g_shadowinfo_x { 0 };
int32_t g_shadowinfo_y { 0 };
DragClient g_dragClient;
std::unique_ptr<IInputAdapter> g_input { nullptr };
std::unique_ptr<IPluginManager> g_pluginMgr { nullptr };
std::unique_ptr<IDSoftbusAdapter> g_dsoftbus { nullptr };
constexpr int32_t ANIMATION_DURATION { 500 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr bool HAS_CANCELED_ANIMATION { true };
Security::AccessToken::HapInfoParams g_testInfoParms = {
    .userID = 1,
    .bundleName = "drag_server_test",
    .instIndex = 0,
    .appIDDesc = "test"
};

Security::AccessToken::HapPolicyParams g_testPolicyPrams = {
    .apl = Security::AccessToken::APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {}
};
} // namespace

void DragClientTest::SetUpTestCase() {}

void DragClientTest::SetUp()
{
}

void DragClientTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

std::shared_ptr<Media::PixelMap> DragClientTest::CreatePixelMap(int32_t width, int32_t height)
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

std::optional<DragData> DragClientTest::CreateDragData(int32_t sourceType,
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

uint64_t NativeTokenGet()
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .aplStr = "system_basic",
    };

    infoInstance.processName = " DragServerTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}
class TestStopDragListener : public IStopDragListener {
public:
    TestStopDragListener() : callbackCalled(false), callbackCount(0) {}
    ~TestStopDragListener() override = default;
    void OnDragEndMessage() override
    {
        callbackCalled = true;
        callbackCount++;
    }
    void Reset()
    {
        callbackCalled = false;
        callbackCount = 0;
    }
    bool callbackCalled;
    int32_t callbackCount;
};

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

class StreamClientTest : public StreamClient {
public:
    StreamClientTest() = default;
    void Stop() override
    {}
    int32_t Socket() override
    {
        return RET_ERR;
    }
};

void DragClientTest::AssignToAnimation(PreviewAnimation &animation)
{
    animation.duration = ANIMATION_DURATION;
    animation.curveName = CURVE_NAME;
    animation.curve = { 0.33, 0, 0.67, 1 };
}

/**
 * @tc.name: DragClientTest1
 * @tc.desc: DragClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t displayId = 0;
    uint64_t screenId = 0;
    int32_t ret = g_dragClient.SetDragWindowScreenId(displayId, screenId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragClientTest4
 * @tc.desc: DragClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest4, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool state = false;
    int32_t ret = g_dragClient.SetMouseDragMonitorState(state);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragClientTest5
 * @tc.desc: DragClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest5, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool state = false;
    int32_t ret = g_dragClient.SetDraggableState(state);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragClientTest6
 * @tc.desc: DragClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest6, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool state = false;
    int32_t ret = g_dragClient.GetAppDragSwitchState(state);
#ifdef OHOS_BUILD_UNIVERSAL_DRAG
    EXPECT_EQ(ret, RET_ERR);
#else
    EXPECT_EQ(ret, RET_OK);
#endif // OHOS_BUILD_UNIVERSAL_DRAG
}

/**
 * @tc.name: DragClientTest7
 * @tc.desc: DragClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest7, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(g_dragClient.OnDisconnected());
}

/**
 * @tc.name: DragClientTest8
 * @tc.desc: DragClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest8, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ASSERT_EQ(g_dragClient.IsDragStart(), false);
}

/**
 * @tc.name: DragClientTest9
 * @tc.desc: DragClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest9, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragState dragState { DragState::ERROR };
    int32_t ret = g_dragClient.GetDragState(dragState);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragClientTest10
 * @tc.desc: DragClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest10, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        promiseFlag.set_value(true);
    };
    g_dragClient.startDragListener_ = std::make_shared<TestStartDragListener>(callback);
    g_dragClient.OnDisconnected();
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
}

/**
* @tc.name: DragClientTest11
* @tc.desc: Test DragClient destructor releases startDragListener_
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragClientTest, DragClientTest11, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto dragClient = std::make_unique<DragClient>();
    std::weak_ptr<IStartDragListener> weakListener;
    {
        auto listener = std::make_shared<TestStartDragListener>([](const DragNotifyMsg &msg) {});
        weakListener = listener;
        dragClient->startDragListener_ = listener;
    }
    dragClient.reset();
    ASSERT_TRUE(weakListener.expired());
}

/**
* @tc.name: DragClientTest12
* @tc.desc: Test OnNotifyResult clears startDragListener_
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragClientTest, DragClientTest12, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::promise<bool> promiseFlag;
    std::future<bool> futureFlag = promiseFlag.get_future();
    auto callback = [&promiseFlag](const DragNotifyMsg &notifyMessage) {
        promiseFlag.set_value(true);
    };
    auto listener = std::make_shared<TestStartDragListener>(callback);
    g_dragClient.startDragListener_ = listener;
    std::weak_ptr<IStartDragListener> weakListener = listener;
    ASSERT_FALSE(weakListener.expired());
    g_dragClient.OnDisconnected();
    listener = nullptr;
    ASSERT_TRUE(weakListener.expired());
    ASSERT_TRUE(futureFlag.wait_for(std::chrono::milliseconds(PROMISE_WAIT_SPAN_MS)) != std::future_status::timeout);
}

/**
* @tc.name: DragClientTest13
* @tc.desc: DragClient GetDragTargetPid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragClientTest, DragClientTest13, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t targetPid = g_dragClient.GetDragTargetPid();
    EXPECT_GE(targetPid, -1);
}

/**
* @tc.name: DragClientTest14
* @tc.desc: DragClient GetUdKey
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragClientTest, DragClientTest14, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string udKey;
    int32_t ret = g_dragClient.GetUdKey(udKey);
    EXPECT_EQ(ret, RET_ERR);
}

/**
* @tc.name: DragClientTest15
* @tc.desc: DragClient EraseMouseIcon
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragClientTest, DragClientTest15, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_dragClient.EraseMouseIcon();
    EXPECT_EQ(ret, RET_ERR);
}

/**
* @tc.name: DragClientTest16
* @tc.desc: DragClient GetDragAction
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragClientTest, DragClientTest16, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragAction dragAction;
    int32_t ret = g_dragClient.GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_ERR);
}

/**
* @tc.name: DragClientTest17
* @tc.desc: DragClient GetExtraInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragClientTest, DragClientTest17, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string extraInfo;
    int32_t ret = g_dragClient.GetExtraInfo(extraInfo);
    EXPECT_EQ(ret, RET_ERR);
}

/**
* @tc.name: DragClientTest18
* @tc.desc: DragClient GetDragSummaryInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragClientTest, DragClientTest18, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragSummaryInfo dragSummaryInfo;
    int32_t ret = g_dragClient.GetDragSummaryInfo(dragSummaryInfo);
    EXPECT_EQ(ret, RET_ERR);
}

/**
* @tc.name: DragClientTest19
* @tc.desc: DragClient AddPrivilege
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragClientTest, DragClientTest19, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string signature = "test_signature";
    DragEventData dragEventData;
    int32_t ret = g_dragClient.AddPrivilege(signature, dragEventData);
    EXPECT_EQ(ret, RET_ERR);
}

/**
* @tc.name: DragClientTest20
* @tc.desc: DragClient EnableUpperCenterMode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DragClientTest, DragClientTest20, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool enable = true;
    int32_t ret = g_dragClient.EnableUpperCenterMode(enable);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragClientTest21
 * @tc.desc: DragClient GetShadowOffset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest21, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ShadowOffset shadowOffset;
    int32_t ret = g_dragClient.GetShadowOffset(shadowOffset);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragClientTest22
 * @tc.desc: Test OnStopDragEnd with valid listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest22, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto stopDragListener = std::make_shared<TestStopDragListener>();
    g_dragClient.stopDragListener_ = stopDragListener;
    EXPECT_FALSE(stopDragListener->callbackCalled);
    StreamClientTest client;
    NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(stopDragListener->callbackCalled);
    EXPECT_EQ(stopDragListener->callbackCount, 1);
    EXPECT_EQ(g_dragClient.stopDragListener_, nullptr);
}

/**
 * @tc.name: DragClientTest23
 * @tc.desc: Test OnStopDragEnd without listener (nullptr)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest23, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragClient.stopDragListener_ = nullptr;
    StreamClientTest client;
    NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragClientTest24
 * @tc.desc: Test OnStopDragEnd multiple calls with same listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest24, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto stopDragListener = std::make_shared<TestStopDragListener>();
    g_dragClient.stopDragListener_ = stopDragListener;
    StreamClientTest client;
    NetPacket pkt1(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret1 = g_dragClient.OnStopDragEnd(client, pkt1);
    EXPECT_EQ(ret1, RET_OK);
    EXPECT_EQ(stopDragListener->callbackCount, 1);
    g_dragClient.stopDragListener_ = stopDragListener;
    NetPacket pkt2(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret2 = g_dragClient.OnStopDragEnd(client, pkt2);
    EXPECT_EQ(ret2, RET_OK);
    EXPECT_EQ(stopDragListener->callbackCount, 2);
}

/**
 * @tc.name: DragClientTest25
 * @tc.desc: Test OnStopDragEnd clears listener after first call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest25, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto stopDragListener = std::make_shared<TestStopDragListener>();
    g_dragClient.stopDragListener_ = stopDragListener;
    StreamClientTest client;
    NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret1 = g_dragClient.OnStopDragEnd(client, pkt);
    EXPECT_EQ(ret1, RET_OK);
    EXPECT_TRUE(stopDragListener->callbackCalled);
    EXPECT_EQ(g_dragClient.stopDragListener_, nullptr);
    NetPacket pkt2(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret2 = g_dragClient.OnStopDragEnd(client, pkt2);
    EXPECT_EQ(ret2, RET_ERR);
    EXPECT_EQ(stopDragListener->callbackCount, 1);
}

/**
 * @tc.name: DragClientTest26
 * @tc.desc: Test OnStopDragEnd with different MessageId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest26, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto stopDragListener = std::make_shared<TestStopDragListener>();
    g_dragClient.stopDragListener_ = stopDragListener;
    StreamClientTest client;
    NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(stopDragListener->callbackCalled);
}

/**
 * @tc.name: DragClientTest27
 * @tc.desc: Test OnStopDragEnd rapid successive calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest27, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    for (int32_t i = 0; i < 3; i++) {
        auto stopDragListener = std::make_shared<TestStopDragListener>();
        g_dragClient.stopDragListener_ = stopDragListener;
        StreamClientTest client;
        NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
        int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
        EXPECT_EQ(ret, RET_OK);
        EXPECT_TRUE(stopDragListener->callbackCalled);
        EXPECT_EQ(g_dragClient.stopDragListener_, nullptr);
    }
}

/**
 * @tc.name: DragClientTest28
 * @tc.desc: Test OnStopDragEnd listener callback verification
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest28, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto stopDragListener = std::make_shared<TestStopDragListener>();
    EXPECT_FALSE(stopDragListener->callbackCalled);
    EXPECT_EQ(stopDragListener->callbackCount, 0);
    g_dragClient.stopDragListener_ = stopDragListener;
    StreamClientTest client;
    NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(stopDragListener->callbackCalled);
    EXPECT_EQ(stopDragListener->callbackCount, 1);
}

/**
 * @tc.name: DragClientTest29
 * @tc.desc: Test OnStopDragEnd with null client reference
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest29, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto stopDragListener = std::make_shared<TestStopDragListener>();
    g_dragClient.stopDragListener_ = stopDragListener;
    StreamClientTest client;
    NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(stopDragListener->callbackCalled);
}

/**
 * @tc.name: DragClientTest30
 * @tc.desc: Test OnStopDragEnd listener reset after callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest30, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto stopDragListener1 = std::make_shared<TestStopDragListener>();
    g_dragClient.stopDragListener_ = stopDragListener1;
    StreamClientTest client;
    NetPacket pkt1(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret1 = g_dragClient.OnStopDragEnd(client, pkt1);
    EXPECT_EQ(ret1, RET_OK);
    EXPECT_EQ(g_dragClient.stopDragListener_, nullptr);
    auto stopDragListener2 = std::make_shared<TestStopDragListener>();
    g_dragClient.stopDragListener_ = stopDragListener2;
    NetPacket pkt2(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret2 = g_dragClient.OnStopDragEnd(client, pkt2);
    EXPECT_EQ(ret2, RET_OK);
    EXPECT_EQ(g_dragClient.stopDragListener_, nullptr);
    EXPECT_EQ(stopDragListener1->callbackCount, 1);
    EXPECT_EQ(stopDragListener2->callbackCount, 1);
}

/**
 * @tc.name: DragClientTest31
 * @tc.desc: Test OnStopDragEnd with weak pointer tracking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest31, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto stopDragListener = std::make_shared<TestStopDragListener>();
    std::weak_ptr<TestStopDragListener> weakListener = stopDragListener;
    EXPECT_FALSE(weakListener.expired());
    g_dragClient.stopDragListener_ = stopDragListener;
    StreamClientTest client;
    NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(stopDragListener->callbackCalled);
    EXPECT_EQ(g_dragClient.stopDragListener_, nullptr);
    EXPECT_FALSE(weakListener.expired());
}

/**
 * @tc.name: DragClientTest32
 * @tc.desc: Test OnStopDragEnd error handling without listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest32, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragClient.stopDragListener_ = nullptr;
    StreamClientTest client;
    NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
    for (int32_t i = 0; i < 3; i++) {
        int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: DragClientTest33
 * @tc.desc: Test OnStopDragEnd listener lifecycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest33, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    {
        auto stopDragListener = std::make_shared<TestStopDragListener>();
        g_dragClient.stopDragListener_ = stopDragListener;
        StreamClientTest client;
        NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
        int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
        EXPECT_EQ(ret, RET_OK);
        EXPECT_TRUE(stopDragListener->callbackCalled);
        EXPECT_EQ(g_dragClient.stopDragListener_, nullptr);
    }
    EXPECT_EQ(g_dragClient.stopDragListener_, nullptr);
}

/**
 * @tc.name: DragClientTest34
 * @tc.desc: Test OnStopDragEnd callback count verification
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest34, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto stopDragListener = std::make_shared<TestStopDragListener>();
    g_dragClient.stopDragListener_ = stopDragListener;
    StreamClientTest client;
    NetPacket pkt1(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret1 = g_dragClient.OnStopDragEnd(client, pkt1);
    EXPECT_EQ(ret1, RET_OK);
    EXPECT_EQ(stopDragListener->callbackCount, 1);
    g_dragClient.stopDragListener_ = stopDragListener;
    stopDragListener->Reset();
    NetPacket pkt2(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret2 = g_dragClient.OnStopDragEnd(client, pkt2);
    EXPECT_EQ(ret2, RET_OK);
    EXPECT_EQ(stopDragListener->callbackCount, 1);
}

/**
 * @tc.name: DragClientTest35
 * @tc.desc: Test OnStopDragEnd with concurrent access simulation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest35, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    auto stopDragListener = std::make_shared<TestStopDragListener>();
    g_dragClient.stopDragListener_ = stopDragListener;
    StreamClientTest client;
    NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
    int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(stopDragListener->callbackCalled);
    EXPECT_EQ(stopDragListener->callbackCount, 1);
    EXPECT_EQ(g_dragClient.stopDragListener_, nullptr);
}

/**
 * @tc.name: DragClientTest36
 * @tc.desc: Test OnStopDragEnd boundary condition with multiple listeners
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragClientTest, DragClientTest36, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    const int32_t listenerCount = 5;
    std::vector<std::shared_ptr<TestStopDragListener>> listeners;
    for (int32_t i = 0; i < listenerCount; i++) {
        auto listener = std::make_shared<TestStopDragListener>();
        listeners.push_back(listener);
        g_dragClient.stopDragListener_ = listener;
        StreamClientTest client;
        NetPacket pkt(MessageId::DRAG_STOP_DRAG_END);
        int32_t ret = g_dragClient.OnStopDragEnd(client, pkt);
        EXPECT_EQ(ret, RET_OK);
        EXPECT_TRUE(listeners[i]->callbackCalled);
        EXPECT_EQ(listeners[i]->callbackCount, 1);
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
