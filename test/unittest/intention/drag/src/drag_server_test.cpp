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
#include "drag_server_test.h"
#include "ddm_adapter.h"
#include "devicestatus_service.h"
#include "drag_data_manager.h"
#include "drag_data_packer.h"
#include "drag_data_util.h"
#include "drag_server.h"
#include "event_hub.h"
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
constexpr int32_t WINDOW_ID { -1 };
constexpr int32_t READ_OK { 1 };
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
const std::string FILTER_INFO { "Undefined filter info" };
const std::string UD_KEY { "Unified data key" };
const std::string EXTRA_INFO { "Undefined extra info" };
const std::string CURVE_NAME { "cubic-bezier" };
constexpr int32_t FOREGROUND_COLOR_IN { 0x33FF0000 };
constexpr int32_t FOREGROUND_COLOR_OUT { 0x00000000 };
constexpr int32_t DISPLAY_ID { 0 };
constexpr int32_t DISPLAY_X { 50 };
constexpr int32_t DISPLAY_Y { 50 };
constexpr int32_t INT32_BYTE { 4 };
constexpr int32_t MAX_BUF_SIZE { 1024 };
#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
constexpr int32_t MAX_ANIMATION_INFO_LENGTH { 1024 };
#endif // OHOS_BUILD_INTERNAL_DROP_ANIMATION
int32_t g_shadowinfo_x { 0 };
int32_t g_shadowinfo_y { 0 };
ContextService *g_instance = nullptr;
DelegateTasks g_delegateTasks;
DeviceManager g_devMgr;
TimerManager g_timerMgr;
DragManager g_dragMgr;
SocketSessionManager g_socketSessionMgr;
std::unique_ptr<IInputAdapter> g_input { nullptr };
std::unique_ptr<IPluginManager> g_pluginMgr { nullptr };
std::unique_ptr<IDSoftbusAdapter> g_dsoftbus { nullptr };
constexpr int32_t ANIMATION_DURATION { 500 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr bool HAS_CANCELED_ANIMATION { true };
constexpr bool HAS_CUSTOM_ANIMATION { true };
Intention g_intention { Intention::UNKNOWN_INTENTION };
std::shared_ptr<DragServer> g_dragServer { nullptr };
std::shared_ptr<DragServer> g_dragServerOne { nullptr };
IContext *g_context { nullptr };
IContext *g_contextOne { nullptr };
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

void DragServerTest::SetUpTestCase() {}

void DragServerTest::SetUp()
{
    g_context = ContextService::GetInstance();
    g_dragServer = std::make_shared<DragServer>(g_context);
    g_dragServerOne = std::make_shared<DragServer>(g_contextOne);
}

void DragServerTest::TearDown()
{
    g_dragServer = nullptr;
    g_context = nullptr;
    g_dragServerOne = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

std::shared_ptr<Media::PixelMap> DragServerTest::CreatePixelMap(int32_t width, int32_t height)
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

std::optional<DragData> DragServerTest::CreateDragData(int32_t sourceType,
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

void DragServerTest::AssignToAnimation(PreviewAnimation &animation)
{
    animation.duration = ANIMATION_DURATION;
    animation.curveName = CURVE_NAME;
    animation.curve = { 0.33, 0, 0.67, 1 };
}

/**
 * @tc.name: DragServerTest1
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool visible = false;
    bool isForce = false;
    const std::shared_ptr<Rosen::RSTransaction>& rsTransaction { nullptr };
    int32_t ret = g_dragServer->SetDragWindowVisible(visible, isForce, rsTransaction);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest2
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t eventId = -1;
    int32_t ret = g_dragServer->UpdateDragStyle(context, DragCursorStyle::DEFAULT, eventId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragServerTest3
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ShadowInfo shadowInfo {};
    int32_t ret = g_dragServer->UpdateShadowPic(shadowInfo);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest4
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest4, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyleOut;
    previewStyleOut.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleOut.foregroundColor = FOREGROUND_COLOR_OUT;
    int32_t ret = InteractionManager::GetInstance()->UpdatePreviewStyle(previewStyleOut);
    EXPECT_EQ(ret, RET_ERR);
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    ret = g_dragServer->UpdatePreviewStyle(previewStyleIn);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest5
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest5, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t targetPid = -1;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t ret = g_dragServer->GetDragTargetPid(context, targetPid);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragServerTest6
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest6, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string udKey { "Unified data key" };
    int32_t ret = g_dragServer->GetUdKey(udKey);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest7
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest7, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    ShadowOffset defaultShadowOffset = {};
    int32_t ret = g_dragServer->GetShadowOffset(defaultShadowOffset);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest8
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest8, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData datas;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t ret = g_dragServer->GetDragData(context, datas);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest9
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest9, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    DragState dragState;
    int32_t ret = g_dragServer->GetDragState(context, dragState);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragServerTest_GetDragState_002
 * @tc.desc: verify GetDragState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest_GetDragState_002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context;
    DragState dragState;
    int32_t ret = g_dragServer->GetDragState(context, dragState);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest10
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest10, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::map<std::string, int64_t> summarys;
    bool isJsCaller = false;
    int32_t ret = g_dragServer->GetDragSummary(context, summarys, isJsCaller);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragServerTest11
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest11, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragAction dragAction;
    int32_t ret = g_dragServer->GetDragAction(dragAction);
    EXPECT_EQ(ret, RET_ERR);
    DragAction dragAction1 { DragAction::INVALID };
    ret = InteractionManager::GetInstance()->GetDragAction(dragAction1);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest12
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest12, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::string extraInfo { "Undefined extra info" };
    int32_t ret = g_dragServer->GetExtraInfo(extraInfo);
    EXPECT_EQ(ret, RET_ERR);
    std::string extraInfo1;
    ret = InteractionManager::GetInstance()->GetExtraInfo(extraInfo1);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest13
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest13, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool visible = true;
    DRAG_DATA_MGR.SetDragWindowVisible(visible);
    bool ret = DRAG_DATA_MGR.GetDragWindowVisible();
    EXPECT_TRUE(ret);
    int32_t tid = DRAG_DATA_MGR.GetTargetTid();
    EXPECT_NE(tid, READ_OK);
    float dragOriginDpi = DRAG_DATA_MGR.GetDragOriginDpi();
    EXPECT_TRUE(dragOriginDpi == 0.0f);
}

/**
 * @tc.name: DragServerTest14
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest14, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DRAG_DATA_MGR.SetTextEditorAreaFlag(true);
    DRAG_DATA_MGR.SetPixelMapLocation({1, 1});
    bool ret = DRAG_DATA_MGR.GetCoordinateCorrected();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: DragServerTest15
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest15, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DRAG_DATA_MGR.initialPixelMapLocation_ = {1, 1};
    DRAG_DATA_MGR.SetInitialPixelMapLocation(DRAG_DATA_MGR.GetInitialPixelMapLocation());
    DRAG_DATA_MGR.SetDragOriginDpi(1);
    bool ret = DRAG_DATA_MGR.GetTextEditorAreaFlag();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: DragServerTest16
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest16, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    const std::shared_ptr<Rosen::RSTransaction> rsTransaction;
    int32_t ret = g_dragServer->RotateDragWindowSync(context, rsTransaction);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest17
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest17, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(IPCSkeleton::GetCallingTokenID());
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_TRUE(ret);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: DragServerTest18
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest18, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIdExStruct.tokenID));
    auto g_tokenId1 = tokenIdEx.tokenIdExStruct.tokenID;
    CallingContext context {
        .intention = g_intention,
        .tokenId = g_tokenId1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(g_tokenId1);
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: DragClientTest19
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragClientTest19, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    uint16_t displayId = 0;
    uint64_t screenId = 0;
    int32_t ret = g_dragServer->SetDragWindowScreenId(context, displayId, screenId);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest20
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest20, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool state = true;
    int32_t ret = g_dragServer->SetMouseDragMonitorState(state);
    EXPECT_EQ(ret, RET_ERR);
    bool state1 = false;
    ret = g_dragServer->SetMouseDragMonitorState(state1);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragServerTest21
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest21, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool state = true;
    int32_t ret2 = g_dragServer->SetDraggableState(state);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: DragServerTest22
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest22, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t ret = g_dragServer->StartDrag(context, dragData);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest23
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest23, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    g_dragMgr.dragState_ = DragState::START;
    int32_t ret = g_dragServer->StopDrag(context, dropResult);
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: DragServerTest24
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest24, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    g_dragMgr.dragState_ = DragState::START;
    int32_t ret = g_dragServerOne->StopDrag(context, dropResult);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: DragServerTest25
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest25, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool isJsCaller = false;
    int32_t ret = g_dragServer->AddDraglistener(context, isJsCaller);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest26
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest26, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool isJsCaller = false;
    int32_t ret = g_dragServer->RemoveDraglistener(context, isJsCaller);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest27
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest27, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t ret = g_dragServer->AddSubscriptListener(context);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest28
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest28, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t ret = g_dragServer->RemoveSubscriptListener(context);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest29
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest29, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool state = false;
    int64_t downTime = 1;
    int32_t ret = g_dragServer->SetDraggableStateAsync(state, downTime);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragServerTest30
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest30, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool enable = false;
    bool isJsCaller = false;
    int32_t ret = g_dragServer->SetDragSwitchState(context, enable, isJsCaller);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragServerTest31
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest31, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t ret = g_dragServer->AddPrivilege(context);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest32
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest32, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t ret = g_dragServer->EraseMouseIcon(context);
    EXPECT_EQ(ret, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest33
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest33, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    bool enable = false;
    std::string pkgName { "Undefined name" };
    bool isJsCaller = false;
    int32_t ret = g_dragServer->SetAppDragSwitchState(context, enable, pkgName, isJsCaller);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragServerTest34
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest34, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool enable = false;
    int32_t ret = g_dragServer->EnableUpperCenterMode(enable);
    EXPECT_EQ(ret, RET_ERR);
    bool enable1 = true;
    int32_t ret1 = g_dragServer->EnableUpperCenterMode(enable1);
    EXPECT_EQ(ret1, RET_ERR);
}

/**
 * @tc.name: DragServerTest35
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest35, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    PreviewAnimation animationOut;
    AssignToAnimation(animationOut);
    int32_t ret = g_dragServer->UpdatePreviewStyleWithAnimation(previewStyleIn, animationOut);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest57
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest57, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragBundleInfo dragBundleInfo;
    int32_t ret = g_dragServer->GetDragBundleInfo(dragBundleInfo);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest58
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest58, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragBundleInfo dragBundleInfo;

    g_dragMgr.dragState_ = DragState::ERROR;
    int32_t ret = g_dragServer->GetDragBundleInfo(dragBundleInfo);
    EXPECT_EQ(ret, RET_ERR);

    g_dragMgr.dragState_ = DragState::START;
    g_dragMgr.isCrossDragging_ = false;
    ret = g_dragServer->GetDragBundleInfo(dragBundleInfo);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_FALSE(dragBundleInfo.isCrossDevice);

    g_dragMgr.dragState_ = DragState::MOTION_DRAGGING;
    g_dragMgr.isCrossDragging_ = true;
    ret = g_dragServer->GetDragBundleInfo(dragBundleInfo);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(dragBundleInfo.isCrossDevice);
    
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: DragServerTest59
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest59, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    DRAG_DATA_MGR.SetPreviewStyle(previewStyleIn);
    PreviewStyle previewStyleIn1;
    previewStyleIn1 = DRAG_DATA_MGR.GetPreviewStyle();
    EXPECT_EQ(previewStyleIn, previewStyleIn1);
}


/**
 * @tc.name: DragServerTest60
 * @tc.desc: Drag Drawingx`
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest60, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 1, 0 };
    ShadowOffset shadowOffset;
    DRAG_DATA_MGR.SetShadowInfos({shadowInfo});
    int32_t ret = DRAG_DATA_MGR.GetShadowOffset(shadowOffset);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragServerTest61
 * @tc.desc: Drag Drawingx`
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest61, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool visible = true;
    DRAG_DATA_MGR.SetDragWindowVisible(visible);
    bool ret = DRAG_DATA_MGR.GetDragWindowVisible();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: DragServerTest62
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest62, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(IPCSkeleton::GetCallingTokenID());
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_TRUE(ret);
    bool isJsCaller = false;
    int32_t ret1 = g_dragServer->AddDraglistener(context, isJsCaller);
    EXPECT_EQ(ret1, RET_ERR);
    ret1 = g_dragServer->RemoveDraglistener(context, isJsCaller);
    EXPECT_EQ(ret1, RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: DragServerTest63
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest63, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(IPCSkeleton::GetCallingTokenID());
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_TRUE(ret);
    int32_t ret1 = g_dragServer->AddSubscriptListener(context);
    EXPECT_EQ(ret1, RET_ERR);
    ret1 = g_dragServer->RemoveSubscriptListener(context);
    EXPECT_EQ(ret1, RET_ERR);
    OHOS::Security::AccessToken::AccessTokenKit::DeleteToken(g_tokenId);
}

/**
 * @tc.name: DragServerTest64
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest64, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIdExStruct.tokenID));
    auto g_tokenId1 = tokenIdEx.tokenIdExStruct.tokenID;
    CallingContext context {
        .intention = g_intention,
        .tokenId = g_tokenId1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(g_tokenId1);
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_FALSE(ret);
    int32_t targetPid = -1;
    int32_t ret1 = g_dragServer->GetDragTargetPid(context, targetPid);
    EXPECT_EQ(ret1, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest65
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest65, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIdExStruct.tokenID));
    auto g_tokenId1 = tokenIdEx.tokenIdExStruct.tokenID;
    CallingContext context {
        .intention = g_intention,
        .tokenId = g_tokenId1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(g_tokenId1);
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_FALSE(ret);
    DragData datas1;
    int32_t ret1 = g_dragServer->GetDragData(context, datas1);
    EXPECT_EQ(ret1, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest66
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest66, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIdExStruct.tokenID));
    auto g_tokenId1 = tokenIdEx.tokenIdExStruct.tokenID;
    CallingContext context {
        .intention = g_intention,
        .tokenId = g_tokenId1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(g_tokenId1);
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_FALSE(ret);
    const std::shared_ptr<Rosen::RSTransaction> rsTransaction;
    int32_t ret1 = g_dragServer->RotateDragWindowSync(context, rsTransaction);
    EXPECT_EQ(ret1, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest67
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest67, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(IPCSkeleton::GetCallingTokenID());
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_TRUE(ret);
    DragData datas1;
    uint16_t displayId = 0;
    uint64_t screenId = 0;
    int32_t ret1 = g_dragServer->SetDragWindowScreenId(context, displayId, screenId);
    EXPECT_EQ(ret1, RET_OK);
}

/**
 * @tc.name: DragServerTest68
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest68, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::map<std::string, int64_t> summarys;
    bool isJsCaller = true;
    int32_t ret = g_dragServer->GetDragSummary(context, summarys, isJsCaller);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragServerTest69
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest69, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(IPCSkeleton::GetCallingTokenID());
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_TRUE(ret);
    std::map<std::string, int64_t> summarys;
    bool isJsCaller = true;
    int32_t ret1 = g_dragServer->GetDragSummary(context, summarys, isJsCaller);
    EXPECT_EQ(ret1, RET_OK);
}

/**
 * @tc.name: DragServerTest70
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest70, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIdExStruct.tokenID));
    auto g_tokenId1 = tokenIdEx.tokenIdExStruct.tokenID;
    CallingContext context {
        .intention = g_intention,
        .tokenId = g_tokenId1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(g_tokenId1);
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_FALSE(ret);
    std::map<std::string, int64_t> summarys;
    bool isJsCaller = true;
    int32_t ret1 = g_dragServer->GetDragSummary(context, summarys, isJsCaller);
    EXPECT_EQ(ret1, COMMON_NOT_SYSTEM_APP);
}

/**
 * @tc.name: DragServerTest71
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest71, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(IPCSkeleton::GetCallingTokenID());
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_TRUE(ret);
    int32_t ret1 = g_dragServer->EraseMouseIcon(context);
    EXPECT_EQ(ret1, RET_ERR);
}

/**
 * @tc.name: DragServerTest74
 * @tc.desc: Test
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest74, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DragData dragData;
    dragData.displayX = DISPLAY_X;
    dragData.displayY = DISPLAY_Y;
    DRAG_DATA_MGR.Init(dragData);
    DRAG_DATA_MGR.SetDragStyle(DragCursorStyle::DEFAULT);
    EXPECT_TRUE(DRAG_DATA_MGR.GetDragStyle() == DragCursorStyle::DEFAULT);
    int32_t eventId = 1;
    DRAG_DATA_MGR.SetEventId(eventId);
    EXPECT_TRUE(DRAG_DATA_MGR.GetEventId() == eventId);
}

/**
 * @tc.name: DragServerTest75
 * @tc.desc: Test
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest75, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool isStart = false;

    g_dragMgr.dragState_ = DragState::ERROR;
    int32_t ret = g_dragServer->IsDragStart(isStart);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(isStart, false);

    g_dragMgr.dragState_ = DragState::START;
    ret = g_dragServer->IsDragStart(isStart);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(isStart, true);

    g_dragMgr.dragState_ = DragState::MOTION_DRAGGING;
    ret = g_dragServer->IsDragStart(isStart);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(isStart, false);
}

#ifdef OHOS_BUILD_INTERNAL_DROP_ANIMATION
/**
 * @tc.name: DragServerTest76
 * @tc.desc: Test
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest76, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint64_t g_tokenId = NativeTokenGet();
    EXPECT_EQ(g_tokenId, IPCSkeleton::GetCallingTokenID());
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(IPCSkeleton::GetCallingTokenID());
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_TRUE(ret);
    std::string animationInfo = "{\"targetPos\": [8, 8]}";
    int32_t ret1 = g_dragServer->EnableInternalDropAnimation(context, animationInfo);
    EXPECT_EQ(ret1, RET_OK);
}

/**
 * @tc.name: DragServerTest77
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest77, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(g_testInfoParms, g_testPolicyPrams);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIdExStruct.tokenID));
    auto g_tokenId1 = tokenIdEx.tokenIdExStruct.tokenID;
    CallingContext context {
        .intention = g_intention,
        .tokenId = g_tokenId1,
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    g_dragServer->GetPackageName(g_tokenId1);
    bool ret = g_dragServer->IsSystemHAPCalling(context);
    EXPECT_FALSE(ret);
    std::string animationInfo = "{\"targetPos\": [8, 8]}";
    int32_t ret1 = g_dragServer->EnableInternalDropAnimation(context, animationInfo);
    EXPECT_EQ(ret1, COMMON_NOT_SYSTEM_APP);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
