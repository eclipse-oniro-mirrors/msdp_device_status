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
#include "drag_params.h"
#include "drag_server.h"
#include "interaction_manager.h"
#include "ipc_skeleton.h"
#include "singleton.h"
#include "tunnel_client.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

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
int32_t g_shadowinfo_x { 0 };
int32_t g_shadowinfo_y { 0 };
ContextService *g_instance = nullptr;
DelegateTasks g_delegateTasks;
DeviceManager g_devMgr;
TimerManager g_timerMgr;
DragManager g_dragMgr;
DragClient g_dragClient;
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
std::shared_ptr<TunnelClient> g_tunnel { nullptr };
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
int32_t PERMISSION_EXCEPTION { 202 };
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
    g_tunnel = std::make_shared<TunnelClient>();
}

void DragServerTest::TearDown()
{
    g_dragServer = nullptr;
    g_context = nullptr;
    g_tunnel = nullptr;
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    int32_t ret = g_dragServer->Enable(context, datas, reply);
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
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->Disable(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
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
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->Start(context, datas, reply);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->Stop(context, datas, reply);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    int32_t ret = -1;
    MessageParcel reply;
    MessageParcel datas;
    std::vector<DragRequestID> dragRequestIDs = {DragRequestID::UNKNOWN_DRAG_ACTION,
        DragRequestID::ADD_DRAG_LISTENER, DragRequestID::ADD_SUBSCRIPT_LISTENER};
    for (const auto& dragRequestID : dragRequestIDs) {
        GTEST_LOG_(INFO) << "dragRequestID: " << dragRequestID;
        ret = g_dragServer->AddWatch(context, dragRequestID, datas, reply);
        EXPECT_EQ(ret, RET_ERR);
    }
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = -1;
    std::vector<DragRequestID> dragRequestIDs = {DragRequestID::UNKNOWN_DRAG_ACTION,
        DragRequestID::REMOVE_DRAG_LISTENER, DragRequestID::REMOVE_SUBSCRIPT_LISTENER};
    for (const auto& dragRequestID : dragRequestIDs) {
        GTEST_LOG_(INFO) << "dragRequestID: " << dragRequestID;
        ret = g_dragServer->RemoveWatch(context, dragRequestID, datas, reply);
        EXPECT_EQ(ret, RET_ERR);
    }
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    std::vector<DragRequestID> dragRequestIDs = {DragRequestID::UNKNOWN_DRAG_ACTION,
        DragRequestID::SET_DRAG_WINDOW_VISIBLE, DragRequestID::UPDATE_DRAG_STYLE,
        DragRequestID::UPDATE_SHADOW_PIC, DragRequestID::UPDATE_PREVIEW_STYLE,
        DragRequestID::UPDATE_PREVIEW_STYLE_WITH_ANIMATION, DragRequestID::SET_DRAG_WINDOW_SCREEN_ID,
        DragRequestID::SET_DRAG_SWITCH_STATE, DragRequestID::SET_APP_DRAG_SWITCH_STATE,
        DragRequestID::SET_DRAGGABLE_STATE, DragRequestID::SET_DRAGABLE_STATE_ASYNC};
    for (const auto& dragRequestID : dragRequestIDs) {
        GTEST_LOG_(INFO) << "dragRequestID: " << dragRequestID;
        ASSERT_NO_FATAL_FAILURE(g_dragServer->SetParam(context, dragRequestID, datas, reply));
    }
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
    int32_t ret = -1;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    std::vector<DragRequestID> dragRequestIDs = {DragRequestID::UNKNOWN_DRAG_ACTION,
        DragRequestID::GET_DRAG_TARGET_PID, DragRequestID::GET_UDKEY,
        DragRequestID::GET_SHADOW_OFFSET, DragRequestID::GET_DRAG_DATA,
        DragRequestID::GET_DRAG_STATE, DragRequestID::GET_DRAG_SUMMARY,
        DragRequestID::GET_DRAG_ACTION, DragRequestID::GET_EXTRA_INFO};
    for (const auto& dragRequestID : dragRequestIDs) {
        GTEST_LOG_(INFO) << "dragRequestID: " << dragRequestID;
        if (dragRequestID == DragRequestID::UNKNOWN_DRAG_ACTION ||
            dragRequestID == DragRequestID::GET_UDKEY ||
            dragRequestID == DragRequestID::GET_SHADOW_OFFSET ||
            dragRequestID == DragRequestID::GET_DRAG_SUMMARY ||
            dragRequestID == DragRequestID::GET_DRAG_DATA ||
            dragRequestID == DragRequestID::GET_DRAG_ACTION||
            dragRequestID == DragRequestID::GET_EXTRA_INFO) {
                ret = g_dragServer->GetParam(context, dragRequestID, datas, reply);
                EXPECT_EQ(ret, RET_ERR);
        } else {
            ret = g_dragServer->GetParam(context, dragRequestID, datas, reply);
            EXPECT_EQ(ret, RET_OK);
        }
    }
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
    int32_t ret = -1;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    std::vector<DragRequestID> dragRequestIDs = {DragRequestID::UNKNOWN_DRAG_ACTION,
        DragRequestID::ADD_PRIVILEGE, DragRequestID::ENTER_TEXT_EDITOR_AREA,
        DragRequestID::ROTATE_DRAG_WINDOW_SYNC, DragRequestID::ERASE_MOUSE_ICON,
        DragRequestID::SET_MOUSE_DRAG_MONITOR_STATE};
    for (const auto& dragRequestID : dragRequestIDs) {
        GTEST_LOG_(INFO) << "dragRequestID: " << dragRequestID;
        ret = g_dragServer->Control(context, dragRequestID, datas, reply);
        EXPECT_EQ(ret, RET_ERR);
    }
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
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->SetDragWindowVisible(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->UpdateDragStyle(context, datas, reply);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->UpdateShadowPic(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->UpdatePreviewStyle(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->UpdatePreviewAnimation(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetDragTargetPid(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
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
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    DRAG_DATA_MGR.Init(dragData.value());
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetUdKey(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
    DRAG_DATA_MGR.dragData_ = {};
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetShadowOffset(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetDragData(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest19
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest19, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetDragState(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetDragSummary(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetDragAction(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetExtraInfo(context, datas, reply);
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
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->EnterTextEditorArea(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
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
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetUdKey(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
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
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    DRAG_DATA_MGR.Init(dragData.value());
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetShadowOffset(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
    DRAG_DATA_MGR.dragData_ = {};
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
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    DRAG_DATA_MGR.Init(dragData.value());
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetExtraInfo(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
    DRAG_DATA_MGR.dragData_ = {};
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
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    
    MessageParcel reply;
    MessageParcel datas;
    g_dragMgr.dragState_ = DragState::START;
    SetDragWindowVisibleParam param { true, true };
    int32_t ret = param.Marshalling(datas);
    EXPECT_EQ(ret, READ_OK);
    ret = g_dragServer->SetDragWindowVisible(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.dragState_  = DragState::STOP;
    DRAG_DATA_MGR.dragData_ = {};
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
    MessageParcel reply;
    MessageParcel datas;
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    g_dragMgr.dragState_ = DragState::START;
    StopDragParam param { dropResult };

    int32_t ret = param.Marshalling(datas);
    EXPECT_EQ(ret, READ_OK);
    ret = g_dragServer->Stop(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    DragDropResult dropResult { DragResult::DRAG_SUCCESS, HAS_CUSTOM_ANIMATION, WINDOW_ID };
    g_dragMgr.dragState_ = DragState::START;
    StopDragParam param { dropResult };

    int32_t ret = param.Marshalling(datas);
    EXPECT_EQ(ret, READ_OK);
    ret = g_dragServerOne->Stop(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragState_ = DragState::STOP;
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
    MessageParcel datas;
    MessageParcel reply;
    g_dragMgr.dragState_ = DragState::START;
    UpdateDragStyleParam param { DragCursorStyle::COPY, -1 };
    bool ret = param.Marshalling(datas);
    EXPECT_EQ(ret, READ_OK);
    ret = g_dragServer->UpdateDragStyle(context, datas, reply);
    EXPECT_TRUE(ret);
    g_dragMgr.dragState_ = DragState::STOP;
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
    MessageParcel datas;
    MessageParcel reply;
    g_dragMgr.dragState_ = DragState::START;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(PIXEL_MAP_WIDTH, PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    ShadowInfo shadowInfo = { pixelMap, 0, 0 };
    std::string extraInfo;
    UpdateShadowPicParam param { shadowInfo };
    bool ret = param.Marshalling(datas);;
    EXPECT_EQ(ret, READ_OK);
    ret = g_dragServer->UpdateShadowPic(context, datas, reply);
    EXPECT_TRUE(ret);
    g_dragMgr.dragState_ = DragState::STOP;
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
    MessageParcel datas;
    MessageParcel reply;
    g_dragMgr.dragState_ = DragState::START;
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    UpdatePreviewStyleParam param { previewStyleIn };
    bool ret = param.Marshalling(datas);;
    EXPECT_EQ(ret, READ_OK);
    ret = g_dragServer->UpdatePreviewStyle(context, datas, reply);
    EXPECT_TRUE(ret);
    g_dragMgr.dragState_ = DragState::STOP;
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
    MessageParcel datas;
    MessageParcel reply;
    g_dragMgr.dragState_ = DragState::START;
    PreviewStyle previewStyleIn;
    previewStyleIn.types = { PreviewType::FOREGROUND_COLOR };
    previewStyleIn.foregroundColor = FOREGROUND_COLOR_IN;
    PreviewAnimation animationOut;
    AssignToAnimation(animationOut);
    UpdatePreviewAnimationParam param { previewStyleIn, animationOut };
    bool ret = param.Marshalling(datas);;
    EXPECT_EQ(ret, READ_OK);
    ret = g_dragServer->UpdatePreviewAnimation(context, datas, reply);
    EXPECT_FALSE(ret);
    g_dragMgr.dragState_ = DragState::STOP;
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    MessageParcel reply;
    g_dragMgr.dragState_ = DragState::START;
    GetDragTargetPidReply targetPidReply { IPCSkeleton::GetCallingPid() };
    bool ret = targetPidReply.Marshalling(datas);
    EXPECT_EQ(ret, READ_OK);
    ret = g_dragServer->GetDragTargetPid(context, datas, reply);
    EXPECT_FALSE(ret);
    g_dragMgr.dragState_ = DragState::STOP;
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
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    g_dragMgr.dragState_ = DragState::START;
    MessageParcel reply;
    MessageParcel datas;
    DRAG_DATA_MGR.Init(dragData.value());
    int32_t ret = g_dragServer->GetDragData(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
    DRAG_DATA_MGR.dragData_ = {};
    ret = g_dragServer->GetDragData(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: DragServerTest36
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest36, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    g_dragMgr.dragState_ = DragState::ERROR;
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetDragState(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragState_ = DragState::START;
    ret = g_dragServer->GetDragState(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: DragServerTest37
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest37, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    g_dragMgr.dragState_ = DragState::ERROR;
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->GetDragAction(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
    g_dragMgr.dragState_ = DragState::START;
    ret = g_dragServer->GetDragAction(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
    g_dragMgr.dragState_ = DragState::STOP;
}

/**
 * @tc.name: DragServerTest38
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest38, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::optional<DragData> dragData = CreateDragData(
        MMI::PointerEvent::SOURCE_TYPE_MOUSE, POINTER_ID, DRAG_NUM_ONE, false, SHADOW_NUM_ONE);
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    DRAG_DATA_MGR.Init(dragData.value());
    int32_t ret = g_dragServer->GetExtraInfo(context, datas, reply);
    EXPECT_EQ(ret, RET_OK);
    DRAG_DATA_MGR.dragData_ = {};
    ret = g_dragServer->GetExtraInfo(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest39
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest39, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    g_dragServer->GetPackageName(IPCSkeleton::GetCallingTokenID());
    g_dragServer->GetPackageName(-1);
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    EnterTextEditorAreaParam param { true };
    bool ret = param.Marshalling(datas);;
    EXPECT_EQ(ret, READ_OK);
    ret = g_dragServer->EnterTextEditorArea(context, datas, reply);
    EXPECT_EQ(ret, READ_OK);
}

/**
 * @tc.name: DragServerTest40
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest40, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    bool ret = DRAG_DATA_MGR.GetDragWindowVisible();
    EXPECT_FALSE(ret);
    int32_t tid = DRAG_DATA_MGR.GetTargetTid();
    EXPECT_NE(tid, READ_OK);
    float dragOriginDpi = DRAG_DATA_MGR.GetDragOriginDpi();
    EXPECT_TRUE(dragOriginDpi == 0.0f);
}

/**
 * @tc.name: DragServerTest42
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest42, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DRAG_DATA_MGR.SetTextEditorAreaFlag(true);
    DRAG_DATA_MGR.SetPixelMapLocation({1, 1});
    bool ret = DRAG_DATA_MGR.GetCoordinateCorrected();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: DragServerTest43
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest43, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    DRAG_DATA_MGR.initialPixelMapLocation_ = {1, 1};
    DRAG_DATA_MGR.SetInitialPixelMapLocation(DRAG_DATA_MGR.GetInitialPixelMapLocation());
    DRAG_DATA_MGR.SetDragOriginDpi(1);
    bool ret = DRAG_DATA_MGR.GetTextEditorAreaFlag();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: DragServerTest44
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest44, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->Start(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest45
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest45, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    bool ret = g_dragServer->IsSystemServiceCalling(context);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: DragServerTest46
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest46, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->RotateDragWindowSync(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest47
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest47, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->SetDragWindowScreenId(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
    uint64_t displayId = 0;
    uint64_t screenId = 0;
    SetDragWindowScreenIdParam param { displayId, screenId };
    bool ret1 = param.Marshalling(datas);
    EXPECT_EQ(ret1, true);
    int32_t ret2 = g_dragServer->SetDragWindowScreenId(context, datas, reply);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: DragServerTest48
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest48, TestSize.Level0)
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
 * @tc.name: DragServerTest49
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest49, TestSize.Level0)
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
 * @tc.name: DragClientTest50
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragClientTest50, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    uint16_t displayId = 0;
    uint64_t screenId = 0;
    int32_t ret = g_dragClient.SetDragWindowScreenId(*g_tunnel, displayId, screenId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragClientTest51
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragClientTest51, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<StreamClient> g_streamClient { nullptr };
    NetPacket packet(MessageId::DRAG_NOTIFY_RESULT);
    int32_t ret = g_dragClient.OnNotifyHideIcon(*g_streamClient, packet);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragClientTest52
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragClientTest52, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<StreamClient> g_streamClient { nullptr };
    NetPacket packet(MessageId::DRAG_NOTIFY_RESULT);
    auto dragEndHandler = [](const DragNotifyMsg& msg) {
        FI_HILOGI("TEST");
    };
    g_dragClient.startDragListener_ = std::make_shared<TestStartDragListener>(dragEndHandler);
    int32_t ret = g_dragClient.OnNotifyHideIcon(*g_streamClient, packet);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DragClientTest53
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragClientTest53, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<StreamClient> g_streamClient { nullptr };
    NetPacket packet(MessageId::DRAG_NOTIFY_RESULT);
    int32_t ret = g_dragClient.OnDragStyleChangedMessage(*g_streamClient, packet);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DragServerTest54
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest54, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel datas;
    bool isJsCaller = -1;
    RemoveDraglistenerParam param { isJsCaller };
    bool ret = param.Marshalling(datas);
    EXPECT_EQ(ret, true);
    int32_t ret1 = g_dragServer->RemoveListener(context, datas);
    EXPECT_EQ(ret1, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: DragServerTest55
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest55, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->SetMouseDragMonitorState(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
    bool state = true;
    SetMouseDragMonitorStateParam param { state };
    bool ret1 = param.Marshalling(datas);
    EXPECT_EQ(ret1, true);
    int32_t ret2 = g_dragServer->SetMouseDragMonitorState(context, datas, reply);
    EXPECT_EQ(ret2, RET_ERR);
}

/**
 * @tc.name: DragServerTest56
 * @tc.desc: Drag Drawing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DragServerTest, DragServerTest56, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    CallingContext context {
        .intention = g_intention,
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
    MessageParcel reply;
    MessageParcel datas;
    int32_t ret = g_dragServer->SetDraggableState(context, datas, reply);
    EXPECT_EQ(ret, RET_ERR);
    bool state = true;
    SetDraggableStateParam param { state };
    bool ret1 = param.Marshalling(datas);
    EXPECT_EQ(ret1, true);
    int32_t ret2 = g_dragServer->SetDraggableState(context, datas, reply);
    EXPECT_EQ(ret2, RET_OK);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
