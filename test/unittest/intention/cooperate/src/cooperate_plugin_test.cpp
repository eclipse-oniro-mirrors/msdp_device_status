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
#include "cooperate_plugin_test.h"

#include "cooperate_context.h"
#include "cooperate_free.h"
#include "cooperate_in.h"
#include "cooperate_out.h"
#include "ddm_adapter.h"
#include "device.h"
#include "dsoftbus_adapter.h"
#include "i_device.h"
#include "i_cooperate_state.h"
#include "input_adapter.h"
#include "ipc_skeleton.h"
#include "mouse_location.h"
#include "socket_session.h"
#include "state_machine.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace Cooperate;
namespace {
constexpr int32_t DEVICE_ID { 0 };
const std::string TEST_DEV_NODE { "/dev/input/TestDeviceNode" };
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr int32_t HOTAREA_500 { 500 };
constexpr int32_t HOTAREA_NEGATIVE_500 { -500 };
constexpr int32_t HOTAREA_NEGATIVE_200 { -200 };
constexpr int32_t HOTAREA_250 { 250 };
constexpr int32_t HOTAREA_200 { 200 };
constexpr int32_t HOTAREA_150 { 150 };
constexpr int32_t HOTAREA_50 { 50 };
constexpr int32_t VREMOTE_NETWORKID { 987654321 };
std::shared_ptr<Context> g_context { nullptr };
std::shared_ptr<Context> g_contextOne { nullptr };
std::shared_ptr<HotplugObserver> g_observer { nullptr };
ContextService *g_instance = nullptr;
IContext *g_icontext { nullptr };
std::shared_ptr<SocketSession> g_session { nullptr };
DelegateTasks g_delegateTasks;
DeviceManager g_devMgr;
TimerManager g_timerMgr;
DragManager g_dragMgr;
SocketSessionManager g_socketSessionMgr;
std::unique_ptr<IDDMAdapter> g_ddm { nullptr };
std::unique_ptr<IInputAdapter> g_input { nullptr };
std::unique_ptr<IPluginManager> g_pluginMgr { nullptr };
std::unique_ptr<IDSoftbusAdapter> g_dsoftbus { nullptr };
std::shared_ptr<Cooperate::StateMachine> g_stateMachine { nullptr };
const std::string LOCAL_NETWORKID { "testLocalNetworkId" };
const std::string REMOTE_NETWORKID { "testRemoteNetworkId" };
} // namespace

ContextService::ContextService()
{
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
    return *g_ddm;
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

MMI::PointerEvent::PointerItem CooperatePluginTest::CreatePointerItem(int32_t pointerId, int32_t deviceId,
    const std::pair<int32_t, int32_t> &displayLocation, bool isPressed)
{
    MMI::PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetDeviceId(deviceId);
    item.SetDisplayX(displayLocation.first);
    item.SetDisplayY(displayLocation.second);
    item.SetPressed(isPressed);
    return item;
}

void CooperatePluginTest::NotifyCooperate()
{
    int32_t errCode { static_cast<int32_t>(CoordinationErrCode::COORDINATION_OK) };
    EventManager::CooperateStateNotice cooperateStateNotice{IPCSkeleton::GetCallingPid(),
        MessageId::COORDINATION_MESSAGE, 1, true, errCode};
    g_contextOne->eventMgr_.NotifyCooperateState(cooperateStateNotice);
    g_context->eventMgr_.NotifyCooperateState(cooperateStateNotice);
    g_socketSessionMgr.AddSession(g_session);
    g_context->eventMgr_.NotifyCooperateState(cooperateStateNotice);
    g_context->eventMgr_.GetCooperateState(cooperateStateNotice);
}

void CooperatePluginTest::CheckInHot()
{
    g_context->hotArea_.displayX_ = 0;
    g_context->hotArea_.height_ = HOTAREA_500;
    g_context->hotArea_.displayY_ = HOTAREA_250;
    g_context->hotArea_.CheckInHotArea();
    g_context->hotArea_.width_ = HOTAREA_200;
    g_context->hotArea_.displayX_ = HOTAREA_150;
    g_context->hotArea_.height_ = HOTAREA_500;
    g_context->hotArea_.displayY_ = HOTAREA_250;
    g_context->hotArea_.CheckInHotArea();
    g_context->hotArea_.displayY_ = HOTAREA_50;
    g_context->hotArea_.width_ = HOTAREA_500;
    g_context->hotArea_.displayX_ = HOTAREA_250;
    g_context->hotArea_.CheckInHotArea();
    g_context->hotArea_.height_ = HOTAREA_500;
    g_context->hotArea_.displayY_ = HOTAREA_500;
    g_context->hotArea_.width_ = HOTAREA_500;
    g_context->hotArea_.displayX_ = HOTAREA_250;
    g_context->hotArea_.CheckInHotArea();
    g_context->hotArea_.height_ = HOTAREA_500;
    g_context->hotArea_.displayY_ = HOTAREA_NEGATIVE_500;
    g_context->hotArea_.width_ = HOTAREA_500;
    g_context->hotArea_.displayX_ = HOTAREA_NEGATIVE_200;
    g_context->hotArea_.CheckInHotArea();
}

void CooperatePluginTest::SetUpTestCase() {}

void CooperatePluginTest::SetUp()
{
    g_ddm = std::make_unique<DDMAdapter>();
    g_input = std::make_unique<InputAdapter>();
    g_dsoftbus = std::make_unique<DSoftbusAdapter>();
    g_contextOne = std::make_shared<Context>(g_icontext);
    auto env = ContextService::GetInstance();
    g_context = std::make_shared<Context>(env);
    int32_t moduleType = 1;
    int32_t tokenType = 1;
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t sockFds[2] { 0, -1 };
    g_session = std::make_shared<SocketSession>("test", moduleType, tokenType, sockFds[0], uid, pid);
}

void CooperatePluginTest::TearDown()
{
    g_context = nullptr;
    g_contextOne = nullptr;
    g_session = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void CooperatePluginTest::OnThreeStates(const CooperateEvent &event)
{
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_OUT;
    g_stateMachine->OnEvent(cooperateContext, event);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    g_stateMachine->OnEvent(cooperateContext, event);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_FREE;
    g_stateMachine->OnEvent(cooperateContext, event);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

class CooperateObserver final : public ICooperateObserver {
public:
    CooperateObserver() = default;
    virtual ~CooperateObserver() = default;

    virtual bool IsAllowCooperate()
    {
        return true;
    }
    virtual void OnStartCooperate(StartCooperateData &data) {}
    virtual void OnRemoteStartCooperate(RemoteStartCooperateData &data) {}
    virtual void OnStopCooperate(const std::string &remoteNetworkId) {}
    virtual void OnTransitionOut(const std::string &remoteNetworkId, const NormalizedCoordinate &cursorPos) {}
    virtual void OnTransitionIn(const std::string &remoteNetworkId, const NormalizedCoordinate &cursorPos) {}
    virtual void OnBack(const std::string &remoteNetworkId, const NormalizedCoordinate &cursorPos) {}
    virtual void OnRelay(const std::string &remoteNetworkId, const NormalizedCoordinate &cursorPos) {}
    virtual void OnReset() {}
    virtual void CloseDistributedFileConnection(const std::string &remoteNetworkId) {}
};

/**
 * @tc.name: CooperatePluginTest1
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::RegisterEventListenerEvent registerEventListenerEvent {};
    g_contextOne->mouseLocation_.AddListener(registerEventListenerEvent);
    g_contextOne->mouseLocation_.RemoveListener(registerEventListenerEvent);
    DSoftbusSubscribeMouseLocation dSoftbusSubscribeMouseLocation {};
    g_contextOne->mouseLocation_.OnSubscribeMouseLocation(dSoftbusSubscribeMouseLocation);
    g_contextOne->mouseLocation_.OnUnSubscribeMouseLocation(dSoftbusSubscribeMouseLocation);

    g_context->mouseLocation_.AddListener(registerEventListenerEvent);
    g_context->mouseLocation_.RemoveListener(registerEventListenerEvent);
    
    Cooperate::RegisterEventListenerEvent registerEventListenerEvent1 {IPCSkeleton::GetCallingPid(), "test"};
    g_context->mouseLocation_.AddListener(registerEventListenerEvent1);
    g_context->mouseLocation_.ProcessData(MMI::PointerEvent::Create());
    g_context->mouseLocation_.RemoveListener(registerEventListenerEvent1);
    Cooperate::LocationInfo locationInfo {1, 1, 1, 1};
    
    DSoftbusSyncMouseLocation dSoftbusSyncMouseLocation{"test", "test", locationInfo};
    g_context->mouseLocation_.OnRemoteMouseLocation(dSoftbusSyncMouseLocation);
    
    g_context->mouseLocation_.listeners_.clear();
    g_context->mouseLocation_.RemoveListener(registerEventListenerEvent1);
    g_context->mouseLocation_.OnRemoteMouseLocation(dSoftbusSyncMouseLocation);

    DSoftbusSubscribeMouseLocation dSoftbusSubscribeMouseLocation1 {"test", "test1"};
    g_context->mouseLocation_.OnSubscribeMouseLocation(dSoftbusSubscribeMouseLocation1);
    g_context->mouseLocation_.ProcessData(MMI::PointerEvent::Create());
    g_context->mouseLocation_.OnUnSubscribeMouseLocation(dSoftbusSubscribeMouseLocation1);
    
    g_context->mouseLocation_.remoteSubscribers_.clear();
    g_context->mouseLocation_.ProcessData(MMI::PointerEvent::Create());
    g_context->mouseLocation_.OnUnSubscribeMouseLocation(dSoftbusSubscribeMouseLocation1);

    DSoftbusReplySubscribeMouseLocation dSoftbusReplySubscribeMouseLocation {"test", "test1", true};
    g_context->mouseLocation_.OnReplySubscribeMouseLocation(dSoftbusReplySubscribeMouseLocation);
    g_context->mouseLocation_.OnReplyUnSubscribeMouseLocation(dSoftbusReplySubscribeMouseLocation);
    DSoftbusReplySubscribeMouseLocation dSoftbusReplySubscribeMouseLocation1 {"test", "test1", false};
    g_context->mouseLocation_.OnReplySubscribeMouseLocation(dSoftbusReplySubscribeMouseLocation1);
    g_context->mouseLocation_.OnReplyUnSubscribeMouseLocation(dSoftbusReplySubscribeMouseLocation1);

    int32_t ret = g_context->mouseLocation_.ReplySubscribeMouseLocation(dSoftbusReplySubscribeMouseLocation);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperatePluginTest2
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest2, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::RegisterEventListenerEvent registerEventListenerEvent1 {IPCSkeleton::GetCallingPid(), "test"};
    g_context->mouseLocation_.AddListener(registerEventListenerEvent1);
    g_socketSessionMgr.Enable();
    g_socketSessionMgr.AddSession(g_session);
    g_contextOne->mouseLocation_.ReportMouseLocationToListener("test", {}, IPCSkeleton::GetCallingPid());
    g_context->mouseLocation_.ReportMouseLocationToListener("test", {}, IPCSkeleton::GetCallingPid());
    g_context->mouseLocation_.localListeners_.clear();
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperatePluginTest3
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest3, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_context->mouseLocation_.ProcessData(nullptr);
    auto pointerEvent = MMI::PointerEvent::Create();
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->SetPointerId(1);
    MMI::PointerEvent::PointerItem curPointerItem = CreatePointerItem(1, 1, { 0, 0 }, true);
    pointerEvent->AddPointerItem(curPointerItem);
    g_context->mouseLocation_.ProcessData(pointerEvent);
    NetPacket pkt(MessageId::COORDINATION_MESSAGE);
    int32_t ret = g_context->mouseLocation_.SendPacket("test", pkt);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperatePluginTest4
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest4, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_socketSessionMgr.Enable();
    RegisterHotareaListenerEvent registerHotareaListenerEvent{IPCSkeleton::GetCallingPid(), 1};
    g_context->hotArea_.AddListener(registerHotareaListenerEvent);
    g_context->hotArea_.OnHotAreaMessage(HotAreaType::AREA_LEFT, true);
    g_contextOne->hotArea_.AddListener(registerHotareaListenerEvent);
    g_contextOne->hotArea_.OnHotAreaMessage(HotAreaType::AREA_LEFT, true);
    g_socketSessionMgr.sessions_.clear();
    g_context->hotArea_.OnHotAreaMessage(HotAreaType::AREA_LEFT, true);
    g_context->hotArea_.RemoveListener(registerHotareaListenerEvent);
    EnableCooperateEvent enableCooperateEvent{1, 1, 1};
    g_context->hotArea_.EnableCooperate(enableCooperateEvent);
    CheckInHot();
    g_context->hotArea_.CheckPointerToEdge(HotAreaType::AREA_LEFT);
    g_context->hotArea_.CheckPointerToEdge(HotAreaType::AREA_RIGHT);
    g_context->hotArea_.CheckPointerToEdge(HotAreaType::AREA_TOP);
    g_context->hotArea_.CheckPointerToEdge(HotAreaType::AREA_BOTTOM);
    g_context->hotArea_.CheckPointerToEdge(HotAreaType::AREA_NONE);
    g_context->hotArea_.NotifyMessage();

    int32_t ret = g_context->hotArea_.ProcessData(nullptr);
    EXPECT_EQ(ret, RET_ERR);
    ret =  g_context->hotArea_.ProcessData(MMI::PointerEvent::Create());
    EXPECT_EQ(ret, RET_ERR);
    auto pointerEvent = MMI::PointerEvent::Create();
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->SetPointerId(1);
    MMI::PointerEvent::PointerItem curPointerItem = CreatePointerItem(1, 1, { 0, 0 }, true);
    pointerEvent->AddPointerItem(curPointerItem);
    ret = g_context->hotArea_.ProcessData(pointerEvent);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperatePluginTest5
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest5, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto [sender, receiver] = Channel<CooperateEvent>::OpenChannel();
    g_context->dsoftbus_.AttachSender(sender);
    int32_t ret = g_context->dsoftbus_.OpenSession("test");
    EXPECT_EQ(ret, RET_ERR);
    g_context->dsoftbus_.CloseSession("test");
    g_context->dsoftbus_.CloseAllSessions();
}

/**
 * @tc.name: CooperatePluginTest6
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest6, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.StartCooperate("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperatePluginTest7
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest7, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.StopCooperate("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperatePluginTest8
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest8, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.ComeBack("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperatePluginTest9
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest9, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.RelayCooperate("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperatePluginTest10
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest10, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_context->dsoftbus_.GetLocalNetworkId();
    g_context->dsoftbus_.OnBind("test");
    g_context->dsoftbus_.OnShutdown("test");
    int32_t ret = g_context->dsoftbus_.RelayCooperateFinish("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperatePluginTest11
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest11, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event{};
    NetPacket packet(MessageId::DSOFTBUS_START_COOPERATE);
    g_context->dsoftbus_.SendEvent(event);
    g_context->dsoftbus_.OnCommunicationFailure("test");
    g_context->dsoftbus_.OnStartCooperate("test", packet);
    g_context->dsoftbus_.OnStopCooperate("test", packet);
    g_context->dsoftbus_.OnComeBack("test", packet);
    g_context->dsoftbus_.OnRelayCooperate("test", packet);
    g_context->dsoftbus_.OnRelayCooperateFinish("test", packet);
    g_context->dsoftbus_.OnSubscribeMouseLocation("test", packet);
    g_context->dsoftbus_.OnUnSubscribeMouseLocation("test", packet);
    g_context->dsoftbus_.OnReplySubscribeLocation("test", packet);
    g_context->dsoftbus_.OnReplyUnSubscribeLocation("test", packet);
    g_context->dsoftbus_.OnRemoteMouseLocation("test", packet);
    bool ret = g_context->dsoftbus_.OnPacket("test", packet);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: CooperatePluginTest12
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest12, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RegisterListenerEvent registerListenerEvent{IPCSkeleton::GetCallingPid(), 1};
    g_context->eventMgr_.RegisterListener(registerListenerEvent);
    g_context->eventMgr_.RegisterListener(registerListenerEvent);

    EnableCooperateEvent enableCooperateEvent{1, 1, 1};
    g_context->eventMgr_.EnableCooperate(enableCooperateEvent);
    g_context->eventMgr_.DisableCooperate(registerListenerEvent);

    StartCooperateEvent event {
        .pid = IPCSkeleton::GetCallingPid(),
        .userData = 1,
        .remoteNetworkId = "test",
        .startDeviceId = 1,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    };
    g_context->eventMgr_.StartCooperate(event);
    DSoftbusStartCooperate startEvent {
        .networkId = "test",
        .success = true,
    };
    g_context->eventMgr_.StartCooperateFinish(startEvent);
    g_context->eventMgr_.RemoteStart(startEvent);
    g_context->eventMgr_.RemoteStartFinish(startEvent);
    StopCooperateEvent stopEvent {
        .pid = IPCSkeleton::GetCallingPid(),
        .userData = 1,
        .isUnchained = true,
    };
    g_context->eventMgr_.OnUnchain(stopEvent);
    g_context->eventMgr_.StopCooperate(stopEvent);

    DDMBoardOnlineEvent dDMBoardOnlineEvent {
        .networkId = "test",
        .normal = true,
    };
    g_context->eventMgr_.StopCooperateFinish(dDMBoardOnlineEvent);
    g_context->eventMgr_.RemoteStopFinish(dDMBoardOnlineEvent);
    g_context->eventMgr_.OnProfileChanged(dDMBoardOnlineEvent);
    g_context->eventMgr_.OnSoftbusSessionClosed(dDMBoardOnlineEvent);
    NotifyCooperate();
    g_context->eventMgr_.OnSoftbusSessionClosed(dDMBoardOnlineEvent);
    g_context->eventMgr_.RemoteStop(dDMBoardOnlineEvent);
    g_context->eventMgr_.UnregisterListener(registerListenerEvent);
    NetPacket packet1(MessageId::INVALID);
    bool ret = g_context->dsoftbus_.OnPacket("test", packet1);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperatePluginTest13
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest13, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->StartEventHandler();
    EXPECT_EQ(ret, RET_OK);
    auto [sender, receiver] = Channel<CooperateEvent>::OpenChannel();
    g_context->AttachSender(sender);
    std::shared_ptr<ICooperateObserver> observer = std::make_shared<CooperateObserver>();
    g_context->AddObserver(observer);
    g_context->OnTransitionOut();
    g_context->OnTransitionIn();
    g_context->OnBack();
    g_context->RemoveObserver(observer);
    g_context->Enable();
    g_context->Disable();
    g_context->StopEventHandler();
}

/**
 * @tc.name: CooperatePluginTest14
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest14, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_context->EnableDDM();
    g_context->boardObserver_->OnBoardOnline("test");
    g_context->boardObserver_->OnBoardOffline("test");
    ASSERT_NO_FATAL_FAILURE(g_context->DisableDDM());
}

/**
 * @tc.name: CooperatePluginTest16
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest16, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->EnableDevMgr();
    EXPECT_EQ(ret, RET_OK);
    g_context->DisableDevMgr();
    g_context->NormalizedCursorPosition();
}

/**
 * @tc.name: CooperatePluginTest17
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest17, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EnableCooperateEvent enableCooperateEvent{1, 1, 1};
    RegisterListenerEvent registerListenerEvent{IPCSkeleton::GetCallingPid(), 1};
    g_context->EnableCooperate(enableCooperateEvent);
    g_context->DisableCooperate(registerListenerEvent);
    StartCooperateEvent event {
        .pid = IPCSkeleton::GetCallingPid(),
        .userData = 1,
        .remoteNetworkId = "test",
        .startDeviceId = 1,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    };
    g_context->StartCooperate(event);
    InputPointerEvent inputPointerEvent{
        .deviceId = 1,
        .pointerAction = 1,
        .sourceType = 1,
        .position = Coordinate {
            .x = 1,
            .y = 1,
        }
    };
    g_context->OnPointerEvent(inputPointerEvent);
    DSoftbusStartCooperateFinished failNotice {
        .success = false,
        .originNetworkId = "test",
    };
    g_context->RemoteStartSuccess(failNotice);
    DSoftbusRelayCooperate dSoftbusRelayCooperate {
        .networkId = "test",
        .targetNetworkId = "test1"
    };
    g_context->RelayCooperate(dSoftbusRelayCooperate);
    g_context->observers_.clear();
    g_context->OnTransitionOut();
    g_context->CloseDistributedFileConnection("test");
    g_context->OnTransitionIn();
    g_context->OnResetCooperation();
    g_context->OnBack();
    g_context->OnRelayCooperation("test", NormalizedCoordinate());
    bool ret = g_context->IsAllowCooperate();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: CooperatePluginTest18
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest18, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<ICooperateObserver> observer = std::make_shared<CooperateObserver>();
    g_context->AddObserver(observer);
    EnableCooperateEvent enableCooperateEvent{1, 1, 1};
    RegisterListenerEvent registerListenerEvent{IPCSkeleton::GetCallingPid(), 1};
    g_context->EnableCooperate(enableCooperateEvent);
    g_context->DisableCooperate(registerListenerEvent);
    StartCooperateEvent event {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    g_context->StartCooperate(event);
    InputPointerEvent inputPointerEvent{1, 1, 1, Coordinate {1, 1}};
    g_context->OnPointerEvent(inputPointerEvent);
    DSoftbusStartCooperateFinished failNotice {
        .success = false, .originNetworkId = "test",
    };
    g_context->RemoteStartSuccess(failNotice);
    DSoftbusRelayCooperate dSoftbusRelayCooperate {
        .networkId = "test", .targetNetworkId = "test1",
    };
    g_context->RelayCooperate(dSoftbusRelayCooperate);
    g_context->UpdateCursorPosition();
    g_context->ResetCursorPosition();
    #ifdef ENABLE_PERFORMANCE_CHECK
    g_context->StartTrace("test");
    g_context->StartTrace("test");
    g_context->FinishTrace("test");
    #endif // ENABLE_PERFORMANCE_CHECK
    bool ret = g_context->IsAllowCooperate();
    EXPECT_TRUE(ret);
    Coordinate coordinate{1, 1};
    g_context->SetCursorPosition(coordinate);
    g_context->OnTransitionOut();
    g_context->OnTransitionIn();
    g_context->OnBack();
    g_context->OnRelayCooperation("test", NormalizedCoordinate());
    g_context->CloseDistributedFileConnection("test");
    g_context->OnResetCooperation();
    g_context->RemoveObserver(observer);
    ret = g_context->StartEventHandler();
    EXPECT_EQ(ret, RET_OK);
    g_context->OnTransitionOut();
    g_context->OnTransitionIn();
    g_context->OnBack();
    g_context->OnRelayCooperation("test", NormalizedCoordinate());
    g_context->CloseDistributedFileConnection("test");
    g_context->OnResetCooperation();
    g_context->StopEventHandler();
}

/**
 * @tc.name: CooperatePluginTest19
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest19, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::RegisterEventListenerEvent registerEventListenerEvent1 {IPCSkeleton::GetCallingPid(), "test"};
    g_context->mouseLocation_.AddListener(registerEventListenerEvent1);
    int32_t pid = 1;
    CooperateEvent event(CooperateEventType::APP_CLOSED,
        ClientDiedEvent {
            .pid = pid,
        });
    ClientDiedEvent notice = std::get<ClientDiedEvent>(event.event);
    g_context->mouseLocation_.listeners_["test"].insert(registerEventListenerEvent1.pid);
    g_context->mouseLocation_.OnClientDied(notice);
    g_context->mouseLocation_.RemoveListener(registerEventListenerEvent1);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperatePluginTest20
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest20, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::RegisterEventListenerEvent registerEventListenerEvent1 {IPCSkeleton::GetCallingPid(), "test"};
    g_context->mouseLocation_.AddListener(registerEventListenerEvent1);
    std::string remoteNetworkId("test");
    std::string networkId("test");
    CooperateEvent event(
       CooperateEventType::DSOFTBUS_MOUSE_LOCATION,
        DSoftbusSyncMouseLocation {
            .networkId = networkId,
            .remoteNetworkId = remoteNetworkId,
            .mouseLocation = {
                .displayX = 50,
                .displayY = 50,
                .displayWidth = 25,
                .displayHeight = 25,
            },
        });
    DSoftbusSyncMouseLocation notice = std::get<DSoftbusSyncMouseLocation>(event.event);
    g_context->mouseLocation_.SyncMouseLocation(notice);
    g_context->mouseLocation_.RemoveListener(registerEventListenerEvent1);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperatePluginTest21
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest21, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::DSoftbusSubscribeMouseLocation subscribeMouseLocation {
        .networkId = "test",
    };
    g_context->mouseLocation_.OnSubscribeMouseLocation(subscribeMouseLocation);
    CooperateEvent event(CooperateEventType::APP_CLOSED,
        DDMBoardOnlineEvent {
        .networkId = "test",
        .normal = true,
    });
    DDMBoardOnlineEvent notice = std::get<DDMBoardOnlineEvent>(event.event);
    g_context->mouseLocation_.OnSoftbusSessionClosed(notice);
    auto pointerEvent = MMI::PointerEvent::Create();
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    MMI::PointerEvent::PointerItem curPointerItem = CreatePointerItem(1, 1, { 0, 0 }, true);
    pointerEvent->AddPointerItem(curPointerItem);
    g_context->mouseLocation_.ProcessData(pointerEvent);
    g_context->mouseLocation_.OnUnSubscribeMouseLocation(subscribeMouseLocation);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperatePluginTest22
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest22, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Cooperate::RegisterEventListenerEvent registerEventListenerEvent1 {IPCSkeleton::GetCallingPid(), "test"};
    g_context->mouseLocation_.AddListener(registerEventListenerEvent1);
    Cooperate::DSoftbusSubscribeMouseLocation subscribeMouseLocation {
        .networkId = "test",
    };
    g_context->mouseLocation_.OnSubscribeMouseLocation(subscribeMouseLocation);
    CooperateEvent event(CooperateEventType::APP_CLOSED,
        DDMBoardOnlineEvent {
        .networkId = "test",
        .normal = true,
    });
    DDMBoardOnlineEvent notice = std::get<DDMBoardOnlineEvent>(event.event);
    g_context->mouseLocation_.OnSoftbusSessionClosed(notice);
    auto pointerEvent = MMI::PointerEvent::Create();
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    MMI::PointerEvent::PointerItem curPointerItem = CreatePointerItem(1, 1, { 0, 0 }, true);
    pointerEvent->AddPointerItem(curPointerItem);
    g_context->mouseLocation_.localListeners_.insert(registerEventListenerEvent1.pid);
    g_context->mouseLocation_.remoteSubscribers_.insert(subscribeMouseLocation.networkId);
    g_context->mouseLocation_.ProcessData(pointerEvent);
    ASSERT_NO_FATAL_FAILURE(g_context->mouseLocation_.OnUnSubscribeMouseLocation(subscribeMouseLocation));
    g_context->mouseLocation_.localListeners_.clear();
    g_context->mouseLocation_.remoteSubscribers_.clear();
}

/**
 * @tc.name: CooperatePluginTest23
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest23, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    auto dev = g_devMgr.AddDevice(TEST_DEV_NODE);
    EXPECT_EQ(dev, nullptr);
    g_observer->OnDeviceAdded(dev);
}

/**
 * @tc.name: CooperatePluginTest24
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, CooperatePluginTest24, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    auto dev = g_devMgr.AddDevice(TEST_DEV_NODE);
    EXPECT_EQ(dev, nullptr);
    g_observer->OnDeviceRemoved(dev);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event;
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(CooperateEventType::QUIT);
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DDM_BOARD_OFFLINE,
        DDMBoardOfflineEvent {
            .networkId = LOCAL_NETWORKID
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool switchStatus = false;
    CooperateEvent event(
        CooperateEventType::DDP_COOPERATE_SWITCH_CHANGED,
        DDPCooperateSwitchChanged {
            .networkId = LOCAL_NETWORKID,
            .normal = switchStatus,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::INPUT_HOTPLUG_EVENT,
        InputHotplugEvent {
            .deviceId = -1,
            .type = InputHotplugType::PLUG,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::INPUT_HOTPLUG_EVENT,
        InputHotplugEvent {
            .deviceId = -1,
            .type = InputHotplugType::UNPLUG,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);

    CooperateEvent event(
        CooperateEventType::INPUT_POINTER_EVENT,
        InputPointerEvent {
            .deviceId = pointerEvent->GetDeviceId(),
            .pointerAction = pointerEvent->GetPointerAction(),
            .sourceType = pointerEvent->GetSourceType(),
            .position = Coordinate {
                .x = pointerItem.GetDisplayX(),
                .y = pointerItem.GetDisplayY(),
            }
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    MMI::PointerEvent::PointerItem pointerItem = CreatePointerItem(1, 1, { 0, 0 }, true);

    CooperateEvent event(
        CooperateEventType::INPUT_POINTER_EVENT,
        InputPointerEvent {
            .deviceId = pointerEvent->GetDeviceId(),
            .pointerAction = pointerEvent->GetPointerAction(),
            .sourceType = pointerEvent->GetSourceType(),
            .position = Coordinate {
                .x = pointerItem.GetDisplayX(),
                .y = pointerItem.GetDisplayY(),
            }
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t fd = -1;
    CooperateEvent event(
        CooperateEventType::DUMP,
        DumpEvent {
            .fd = fd
        });

    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    CooperateEvent registerEvent(
        CooperateEventType::REGISTER_EVENT_LISTENER,
        RegisterEventListenerEvent {
            .pid = pid,
            .networkId = LOCAL_NETWORKID,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, registerEvent);

    CooperateEvent unregisterEvent(
        CooperateEventType::UNREGISTER_EVENT_LISTENER,
        UnregisterEventListenerEvent {
            .pid = pid,
            .networkId = LOCAL_NETWORKID,
        });
    g_stateMachine->OnEvent(cooperateContext, unregisterEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(CooperateEventType::NOOP);
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userData { 0 };
    int32_t pid = IPCSkeleton::GetCallingPid();
    CooperateEvent event(
        CooperateEventType::GET_COOPERATE_STATE,
        GetCooperateStateEvent {
            .pid = pid,
            .userData = userData,
            .networkId = LOCAL_NETWORKID,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<ICooperateObserver> observer { nullptr };
    CooperateEvent addEvent(
        CooperateEventType::ADD_OBSERVER,
        AddObserverEvent {
            .observer = observer
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, addEvent);
    CooperateEvent removeEvent(
       CooperateEventType::REMOVE_OBSERVER,
        RemoveObserverEvent {
            .observer = observer
        });
    g_stateMachine->OnEvent(cooperateContext, removeEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent onlineEvent(
        CooperateEventType::DDM_BOARD_ONLINE,
        DDMBoardOnlineEvent {
            .networkId = LOCAL_NETWORKID
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, onlineEvent);
    CooperateEvent offlineEvent(
        CooperateEventType::DDM_BOARD_OFFLINE,
        DDMBoardOfflineEvent {
            .networkId = LOCAL_NETWORKID
        });
    g_stateMachine->OnEvent(cooperateContext, offlineEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    CooperateEvent event(CooperateEventType::APP_CLOSED,
        ClientDiedEvent {
            .pid = pid,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    CooperateEvent registerEvent(
       CooperateEventType::REGISTER_LISTENER,
        UnregisterListenerEvent {
            .pid = pid
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, registerEvent);
    CooperateEvent unregisterEvent(
       CooperateEventType::UNREGISTER_LISTENER,
        UnregisterListenerEvent {
            .pid = pid
        });
    g_stateMachine->OnEvent(cooperateContext, unregisterEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    CooperateEvent registerEvent(
       CooperateEventType::REGISTER_HOTAREA_LISTENER,
        RegisterHotareaListenerEvent {
            .pid = pid
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, registerEvent);
    CooperateEvent unregisterEvent(
       CooperateEventType::UNREGISTER_HOTAREA_LISTENER,
        UnregisterHotareaListenerEvent {
            .pid = pid
        });
    g_stateMachine->OnEvent(cooperateContext, unregisterEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t userData = 0;
    std::string remoteNetworkId("");
    int32_t startDeviceId = 1;
    bool isUnchained = true;
    CooperateEvent startEvent(
        CooperateEventType::START,
        StartCooperateEvent{
        .pid = pid,
        .userData = userData,
        .remoteNetworkId = remoteNetworkId,
        .startDeviceId = startDeviceId,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, startEvent);
    CooperateEvent stopEvent(
        CooperateEventType::STOP,
        StopCooperateEvent {
            .pid = pid,
            .userData = userData,
            .isUnchained = isUnchained,
        });
    g_stateMachine->OnEvent(cooperateContext, stopEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t tokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    int32_t userData = 0;
    CooperateEvent enableEvent(
        CooperateEventType::ENABLE,
        EnableCooperateEvent {
            .tokenId = tokenId,
            .pid = pid,
            .userData = userData,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, enableEvent);
    CooperateEvent disableEvent(
        CooperateEventType::DISABLE,
        DisableCooperateEvent {
            .pid = pid,
            .userData = userData,
        });
    g_stateMachine->OnEvent(cooperateContext, disableEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string remoteNetworkId("");
    bool normal = false;
    CooperateEvent dsoEvent(
       CooperateEventType::DSOFTBUS_RELAY_COOPERATE,
        DSoftbusRelayCooperate {
            .networkId = remoteNetworkId,
            .normal = normal,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, dsoEvent);
    CooperateEvent dsoFinishedEvent(
       CooperateEventType::DSOFTBUS_RELAY_COOPERATE_FINISHED,
        DSoftbusRelayCooperateFinished {
            .networkId = remoteNetworkId,
            .normal = normal,
        });
    g_stateMachine->OnEvent(cooperateContext, dsoFinishedEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent021, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string remoteNetworkId("");
    std::string networkId("");
    CooperateEvent subscribeMouseEvent(
       CooperateEventType::DSOFTBUS_SUBSCRIBE_MOUSE_LOCATION,
        DSoftbusSubscribeMouseLocation {
            .networkId = networkId,
            .remoteNetworkId = remoteNetworkId,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, subscribeMouseEvent);
    CooperateEvent unSubscribeMouseEvent(
       CooperateEventType::DSOFTBUS_UNSUBSCRIBE_MOUSE_LOCATION,
        DSoftbusUnSubscribeMouseLocation {
            .networkId = networkId,
            .remoteNetworkId = remoteNetworkId,
        });
    g_stateMachine->OnEvent(cooperateContext, unSubscribeMouseEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent022, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string remoteNetworkId("");
    std::string networkId("");
    bool result { false };
    CooperateEvent replySubscribeMouseEvent(
       CooperateEventType::DSOFTBUS_REPLY_SUBSCRIBE_MOUSE_LOCATION,
        DSoftbusReplySubscribeMouseLocation {
            .networkId = networkId,
            .remoteNetworkId = remoteNetworkId,
            .result = result,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, replySubscribeMouseEvent);
    CooperateEvent unReplySubscribeMouseEvent(
       CooperateEventType::DSOFTBUS_REPLY_UNSUBSCRIBE_MOUSE_LOCATION,
        DSoftbusReplyUnSubscribeMouseLocation {
            .networkId = networkId,
            .remoteNetworkId = remoteNetworkId,
            .result = result,
        });
    g_stateMachine->OnEvent(cooperateContext, unReplySubscribeMouseEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent023, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string remoteNetworkId("");
    std::string networkId("");
    CooperateEvent event(
       CooperateEventType::DSOFTBUS_MOUSE_LOCATION,
        DSoftbusSyncMouseLocation {
            .networkId = networkId,
            .remoteNetworkId = remoteNetworkId,
            .mouseLocation = {
                .displayX = 50,
                .displayY = 50,
                .displayWidth = 25,
                .displayHeight = 25,
            },
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnEnterState and OnLeaveState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent024, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event;
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_FREE;
    g_stateMachine->TransiteTo(cooperateContext, CooperateState::COOPERATE_STATE_OUT);
    g_stateMachine->TransiteTo(cooperateContext, CooperateState::COOPERATE_STATE_IN);
    g_stateMachine->TransiteTo(cooperateContext, CooperateState::COOPERATE_STATE_FREE);

    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent025, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent onlineEvent(
        CooperateEventType::DDM_BOARD_ONLINE,
        DDMBoardOnlineEvent {
            .networkId = LOCAL_NETWORKID
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    CooperateEvent offlineEvent(
        CooperateEventType::DDM_BOARD_OFFLINE,
        DDMBoardOfflineEvent {
            .networkId = LOCAL_NETWORKID
        });
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_OUT;
    g_stateMachine->OnEvent(cooperateContext, onlineEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->OnEvent(cooperateContext, offlineEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    g_stateMachine->OnEvent(cooperateContext, onlineEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->OnEvent(cooperateContext, offlineEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_FREE;
    g_stateMachine->OnEvent(cooperateContext, onlineEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->OnEvent(cooperateContext, offlineEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent026, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t userData = 0;
    std::string remoteNetworkId("");
    int32_t startDeviceId = 1;
    bool isUnchained = true;
    CooperateEvent startEvent(
        CooperateEventType::START,
        StartCooperateEvent{
        .pid = pid,
        .userData = userData,
        .remoteNetworkId = remoteNetworkId,
        .startDeviceId = startDeviceId,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    CooperateEvent stopEvent(
        CooperateEventType::STOP,
        StopCooperateEvent {
            .pid = pid,
            .userData = userData,
            .isUnchained = isUnchained,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    g_stateMachine->OnEvent(cooperateContext, startEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->OnEvent(cooperateContext, stopEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    CooperateEvent startRemoteEvent(
        CooperateEventType::START,
        StartCooperateEvent{
        .pid = pid,
        .userData = userData,
        .remoteNetworkId = "remoteNetworkId",
        .startDeviceId = startDeviceId,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    CooperateEvent stopRemoteEvent = stopEvent;
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_OUT;
    g_stateMachine->OnEvent(cooperateContext, startRemoteEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->OnEvent(cooperateContext, stopRemoteEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnAppClosed interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent027, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    CooperateEvent event(CooperateEventType::APP_CLOSED,
        ClientDiedEvent {
            .pid = pid,
        });
    OnThreeStates(event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnSwitchChanged interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent028, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool switchStatus = false;
    CooperateEvent event(
        CooperateEventType::DDP_COOPERATE_SWITCH_CHANGED,
        DDPCooperateSwitchChanged {
            .networkId = LOCAL_NETWORKID,
            .normal = switchStatus,
        });
    OnThreeStates(event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnReset interface
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent029, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t userData = 0;
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    cooperateContext.Enable();
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    std::string remoteNetworkId("");
    int32_t startDeviceId = 1;
    bool isUnchained = true;
    CooperateEvent startEvent(
        CooperateEventType::START,
        StartCooperateEvent{
        .pid = pid,
        .userData = userData,
        .remoteNetworkId = remoteNetworkId,
        .startDeviceId = startDeviceId,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    CooperateEvent stopEvent(
        CooperateEventType::STOP,
        StopCooperateEvent {
            .pid = pid,
            .userData = userData,
            .isUnchained = isUnchained,
        });
    g_stateMachine->OnEvent(cooperateContext, startEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->OnEvent(cooperateContext, stopEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    cooperateContext.Disable();
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnPointerEvent interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent030, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    CooperateEvent event(
        CooperateEventType::INPUT_POINTER_EVENT,
        InputPointerEvent {
            .deviceId = pointerEvent->GetDeviceId(),
            .pointerAction = pointerEvent->GetPointerAction(),
            .sourceType = pointerEvent->GetSourceType(),
            .position = Coordinate {
                .x = pointerItem.GetDisplayX(),
                .y = pointerItem.GetDisplayY(),
            }
        });
    OnThreeStates(event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnHotplug interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent031, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::INPUT_HOTPLUG_EVENT,
        InputHotplugEvent {
            .deviceId = -1,
            .type = InputHotplugType::PLUG,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_OUT;
    g_stateMachine->OnEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test Enable and Disable interfaces
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent032, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t tokenId = static_cast<int32_t>(IPCSkeleton::GetCallingTokenID());
    int32_t userData = 0;
    CooperateEvent enableEvent(
        CooperateEventType::ENABLE,
        EnableCooperateEvent {
            .tokenId = tokenId,
            .pid = pid,
            .userData = userData,
        });
    CooperateEvent disableEvent(
        CooperateEventType::DISABLE,
        DisableCooperateEvent {
            .pid = pid,
            .userData = userData,
        });
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    g_stateMachine->OnEvent(cooperateContext, enableEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->OnEvent(cooperateContext, disableEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));

    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_OUT;
    g_stateMachine->OnEvent(cooperateContext, enableEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->OnEvent(cooperateContext, disableEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test IsRemoteInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent033, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto dev = std::make_shared<Device>(DEVICE_ID);
    dev->name_ = "DistributedInput ";
    auto env = ContextService::GetInstance();
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree state(*g_stateMachine, env);
    bool ret = dev->IsRemote();
    EXPECT_TRUE(ret);
    dev->name_ = "Not distributed input ";
    ret = dev->IsRemote();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test HasLocalPointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent034, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    auto dev = g_devMgr.AddDevice(TEST_DEV_NODE);
    EXPECT_EQ(dev, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_FREE;
    g_stateMachine->TransiteTo(cooperateContext, CooperateState::COOPERATE_STATE_OUT);
    g_stateMachine->TransiteTo(cooperateContext, CooperateState::COOPERATE_STATE_IN);
    g_stateMachine->TransiteTo(cooperateContext, CooperateState::COOPERATE_STATE_FREE);
    dev = g_devMgr.RemoveDevice(TEST_DEV_NODE);
    EXPECT_EQ(dev, nullptr);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnProgress and OnReset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent035, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    stateFree.initial_->OnProgress(cooperateContext, event);
    stateFree.initial_->OnReset(cooperateContext, event);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    stateIn.initial_->OnProgress(cooperateContext, event);
    stateIn.initial_->OnReset(cooperateContext, event);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.initial_->OnProgress(cooperateContext, event);
    stateOut.initial_->OnReset(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnProgress and OnReset in the RelayConfirmation class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent036, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    ASSERT_NE(stateIn.initial_->relay_, nullptr);
    stateIn.initial_->relay_->OnProgress(cooperateContext, event);
    stateIn.initial_->relay_->OnReset(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnBoardOffline in the Initial class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent037, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DDM_BOARD_OFFLINE,
        DDMBoardOfflineEvent {
            .networkId = REMOTE_NETWORKID
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    stateIn.initial_->OnBoardOffline(cooperateContext, event);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    stateIn.initial_->OnBoardOffline(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnBoardOffline in the Initial class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent038, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DDM_BOARD_OFFLINE,
        DDMBoardOfflineEvent {
            .networkId = REMOTE_NETWORKID
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnBoardOffline(cooperateContext, event);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    relay->OnBoardOffline(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnRelay in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent039, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE,
        StartCooperateEvent{
            .pid = IPCSkeleton::GetCallingPid(),
            .userData = 1,
            .remoteNetworkId = "test",
            .startDeviceId = 1,
            .errCode = std::make_shared<std::promise<int32_t>>(),
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    stateIn.initial_->OnRelay(cooperateContext, event);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    stateIn.initial_->OnRelay(cooperateContext, event);
    stateIn.initial_->relay_ = nullptr;
    stateIn.initial_->OnRelay(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnRelay in the CooperateOut class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent040, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool normal = false;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE,
        DSoftbusRelayCooperate {
            .networkId = REMOTE_NETWORKID,
            .normal = normal,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.initial_->OnRelay(cooperateContext, event);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    stateOut.initial_->OnRelay(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnComeBack in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent041, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool normal = false;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COME_BACK,
        DSoftbusRelayCooperate {
            .networkId = REMOTE_NETWORKID,
            .normal = normal,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    stateIn.initial_->OnComeBack(cooperateContext, event);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    stateIn.initial_->OnComeBack(cooperateContext, event);
    stateIn.initial_->relay_ = nullptr;
    stateIn.initial_->OnComeBack(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnComeBack in the CooperateOut class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent042, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto cursorpos = g_context->NormalizedCursorPosition();
    CooperateEvent comeBackEvent(
        CooperateEventType::DSOFTBUS_COME_BACK,
        DSoftbusComeBack {
            .originNetworkId = LOCAL_NETWORKID,
            .success = true,
            .cursorPos = cursorpos,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    stateOut.initial_->OnComeBack(cooperateContext, comeBackEvent);
    cooperateContext.remoteNetworkId_ = LOCAL_NETWORKID;
    stateOut.initial_->OnComeBack(cooperateContext, comeBackEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnResponse in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent043, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent normalEvent(
       CooperateEventType::DSOFTBUS_RELAY_COOPERATE_FINISHED,
        DSoftbusRelayCooperateFinished {
            .networkId = REMOTE_NETWORKID,
            .normal = true,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnResponse(cooperateContext, normalEvent);
    CooperateEvent unnormalEvent(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE_FINISHED,
        DSoftbusRelayCooperateFinished {
            .networkId = REMOTE_NETWORKID,
            .normal = false,
        });
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    relay->OnResponse(cooperateContext, normalEvent);
    relay->OnResponse(cooperateContext, unnormalEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnQuit in the StateMachine class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent044, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnQuit(cooperateContext);
    CooperateEvent onlineEvent(
        CooperateEventType::DDM_BOARD_ONLINE,
        DDMBoardOnlineEvent {
            .networkId = LOCAL_NETWORKID
        });
    g_stateMachine->OnEvent(cooperateContext, onlineEvent);
    g_stateMachine->monitorId_ = 0;
    g_stateMachine->OnQuit(cooperateContext);
    g_stateMachine->monitorId_ = -1;
    g_stateMachine->OnQuit(cooperateContext);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnHotplug in the CooperateOut class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent045, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    cooperateContext.startDeviceId_ = 0;
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_OUT;
        CooperateEvent plugEvent(
        CooperateEventType::INPUT_HOTPLUG_EVENT,
        InputHotplugEvent {
            .deviceId = -1,
            .type = InputHotplugType::PLUG,
        });
    g_stateMachine->OnEvent(cooperateContext, plugEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    CooperateEvent unplugEvent(
        CooperateEventType::INPUT_HOTPLUG_EVENT,
        InputHotplugEvent {
            .deviceId = -1,
            .type = InputHotplugType::UNPLUG,
        });
    g_stateMachine->OnEvent(cooperateContext, unplugEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnHotplug in the CooperateOut class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent046, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    Context cooperateContext(env);
    cooperateContext.startDeviceId_ = -1;
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_OUT;
        CooperateEvent plugEvent(
        CooperateEventType::INPUT_HOTPLUG_EVENT,
        InputHotplugEvent {
            .deviceId = 0,
            .type = InputHotplugType::PLUG,
        });
    g_stateMachine->OnEvent(cooperateContext, plugEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    CooperateEvent unplugEvent(
        CooperateEventType::INPUT_HOTPLUG_EVENT,
        InputHotplugEvent {
            .deviceId = 0,
            .type = InputHotplugType::UNPLUG,
        });
    g_stateMachine->OnEvent(cooperateContext, unplugEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnComeBack in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent047, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    std::string remoteNetworkId = stateIn.process_.Peer();
    bool isPeer = stateIn.process_.IsPeer(remoteNetworkId);
    EXPECT_TRUE(isPeer);
    int32_t startDeviceId = stateIn.process_.StartDeviceId();
    StartCooperateEvent startEvent{
        .remoteNetworkId = "",
        .startDeviceId = startDeviceId,
    };
    stateIn.process_.StartCooperate(cooperateContext, startEvent);
    DSoftbusStartCooperate dSoftbusStartCooperate {
        .networkId = "test"
    };
    stateIn.process_.RemoteStart(cooperateContext, dSoftbusStartCooperate);
    DSoftbusRelayCooperate dSoftbusRelayCooperate {
        .targetNetworkId = ""
    };
    stateIn.process_.RelayCooperate(cooperateContext, dSoftbusRelayCooperate);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnDisable in the RelayConfirmation class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent048, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t userData = 0;
    CooperateEvent disableEvent(
        CooperateEventType::DISABLE,
        DisableCooperateEvent {
            .pid = pid,
            .userData = userData,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnDisable(cooperateContext, disableEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnStop in the RelayConfirmation class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent049, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = IPCSkeleton::GetCallingPid();
    int32_t userData = 0;
    bool isUnchained = true;
    CooperateEvent stopEvent(
        CooperateEventType::STOP,
        StopCooperateEvent {
            .pid = pid,
            .userData = userData,
            .isUnchained = isUnchained,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnStop(cooperateContext, stopEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnRemoteStart
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent050, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    CooperateEvent bothLocalEvent(
        CooperateEventType::DSOFTBUS_START_COOPERATE,
        DSoftbusStartCooperate {
            .networkId = localNetworkId
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    cooperateContext.remoteNetworkId_ = localNetworkId;
    stateIn.initial_->OnRemoteStart(cooperateContext, bothLocalEvent);
    relay->OnRemoteStart(cooperateContext, bothLocalEvent);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.initial_->OnRemoteStart(cooperateContext, bothLocalEvent);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    stateFree.initial_->OnRemoteStart(cooperateContext, bothLocalEvent);
    CooperateEvent bothLocalEventStop(
        CooperateEventType::DSOFTBUS_STOP_COOPERATE,
        DDMBoardOnlineEvent {
            .networkId = localNetworkId
        });
    stateIn.initial_->OnRemoteStop(cooperateContext, bothLocalEventStop);
    relay->OnRemoteStop(cooperateContext, bothLocalEventStop);
    stateOut.initial_->OnRemoteStop(cooperateContext, bothLocalEventStop);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnRemoteStart
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent051, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    CooperateEvent bothRemotEvent(
        CooperateEventType::DSOFTBUS_START_COOPERATE,
        DSoftbusStartCooperate {
            .networkId = REMOTE_NETWORKID
        });
    stateIn.initial_->OnRemoteStart(cooperateContext, bothRemotEvent);
    relay->OnRemoteStart(cooperateContext, bothRemotEvent);
    stateOut.initial_->OnRemoteStart(cooperateContext, bothRemotEvent);
    stateFree.initial_->OnRemoteStart(cooperateContext, bothRemotEvent);
    CooperateEvent bothRemotEventStop(
        CooperateEventType::DSOFTBUS_STOP_COOPERATE,
        DDMBoardOnlineEvent {
            .networkId = REMOTE_NETWORKID
        });
    stateIn.initial_->OnRemoteStop(cooperateContext, bothRemotEventStop);
    relay->OnRemoteStop(cooperateContext, bothRemotEventStop);
    stateOut.initial_->OnRemoteStop(cooperateContext, bothRemotEventStop);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnRemoteStart
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent052, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    CooperateEvent startEvent(
        CooperateEventType::DSOFTBUS_START_COOPERATE,
        DSoftbusStartCooperate {
            .networkId = LOCAL_NETWORKID
        });
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    stateIn.initial_->OnRemoteStart(cooperateContext, startEvent);
    relay->OnRemoteStart(cooperateContext, startEvent);
    stateOut.initial_->OnRemoteStart(cooperateContext, startEvent);
    stateFree.initial_->OnRemoteStart(cooperateContext, startEvent);
    CooperateEvent stopEvent(
        CooperateEventType::DSOFTBUS_STOP_COOPERATE,
        DDMBoardOnlineEvent {
            .networkId = LOCAL_NETWORKID
        });
    stateIn.initial_->OnRemoteStop(cooperateContext, stopEvent);
    relay->OnRemoteStop(cooperateContext, stopEvent);
    stateOut.initial_->OnRemoteStop(cooperateContext, stopEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnRemoteStop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent053, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent stopEvent(
        CooperateEventType::DSOFTBUS_STOP_COOPERATE,
        DDMBoardOnlineEvent {
            .networkId = LOCAL_NETWORKID
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    stateIn.initial_->OnRemoteStop(cooperateContext, stopEvent);
    relay->OnRemoteStop(cooperateContext, stopEvent);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.initial_->OnRemoteStop(cooperateContext, stopEvent);

    cooperateContext.remoteNetworkId_ = LOCAL_NETWORKID;
    stateIn.initial_->OnRemoteStop(cooperateContext, stopEvent);
    relay->OnRemoteStop(cooperateContext, stopEvent);
    stateOut.initial_->OnRemoteStop(cooperateContext, stopEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnSoftbusSessionClosed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent054, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent closeEvent(
        CooperateEventType::DSOFTBUS_SESSION_CLOSED,
        DSoftbusSessionClosed {
            .networkId = LOCAL_NETWORKID
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    g_stateMachine->OnEvent(cooperateContext, closeEvent);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    stateIn.initial_->OnSoftbusSessionClosed(cooperateContext, closeEvent);
    relay->OnSoftbusSessionClosed(cooperateContext, closeEvent);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.initial_->OnSoftbusSessionClosed(cooperateContext, closeEvent);

    cooperateContext.remoteNetworkId_ = LOCAL_NETWORKID;
    stateIn.initial_->OnSoftbusSessionClosed(cooperateContext, closeEvent);
    relay->OnSoftbusSessionClosed(cooperateContext, closeEvent);
    stateOut.initial_->OnSoftbusSessionClosed(cooperateContext, closeEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: inputDevcieMgr_test056
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, inputDevcieMgr_test055, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto [sender, receiver] = Channel<CooperateEvent>::OpenChannel();
    g_context->AttachSender(sender);
    g_context->inputDevMgr_.Enable(sender);
    bool switchStatus = false;
    DSoftbusSessionOpened notice = {
            .networkId = LOCAL_NETWORKID,
            .normal = switchStatus,
    };
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.OnSoftbusSessionOpened(notice));
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.OnSoftbusSessionClosed(notice));
}

/**
 * @tc.name: inputDevcieMgr_test057
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, inputDevcieMgr_test056, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusSyncInputDevice dSoftbusSyncInputDevice {};
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.OnRemoteInputDevice(dSoftbusSyncInputDevice));
    DSoftbusHotPlugEvent dSoftbusHotPlugEvent {};
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.OnRemoteHotPlug(dSoftbusHotPlugEvent));
}

/**
 * @tc.name: inputDevcieMgr_test058
 * @tc.desc: Test cooperate plugin HandleRemoteHotPlug
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, inputDevcieMgr_test057, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusHotPlugEvent notice1 = {
            .networkId = LOCAL_NETWORKID,
            .type = InputHotplugType::PLUG,
            .device = std::make_shared<Device>(VREMOTE_NETWORKID),
    };
    DSoftbusHotPlugEvent notice2 = {
            .networkId = LOCAL_NETWORKID,
            .type = InputHotplugType::UNPLUG,
            .device = std::make_shared<Device>(VREMOTE_NETWORKID),
    };
    g_context->inputDevMgr_.AddVirtualInputDevice(notice1.networkId, 987654321);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.HandleRemoteHotPlug(notice2));
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.HandleRemoteHotPlug(notice1));
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.HandleRemoteHotPlug(notice2));
}

/**
 * @tc.name: inputDevcieMgr_test059
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, inputDevcieMgr_test058, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.NotifyInputDeviceToRemote(REMOTE_NETWORKID));
    std::shared_ptr<IDevice> g_device = std::make_shared<Device>(VREMOTE_NETWORKID);
    g_context->inputDevMgr_.AddRemoteInputDevice(LOCAL_NETWORKID, g_device);
    g_context->inputDevMgr_.AddRemoteInputDevice(LOCAL_NETWORKID, g_device);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.RemoveRemoteInputDevice(LOCAL_NETWORKID, g_device));
    g_context->inputDevMgr_.AddRemoteInputDevice(LOCAL_NETWORKID, g_device);
    g_context->inputDevMgr_.RemoveAllRemoteInputDevice(REMOTE_NETWORKID);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.RemoveAllRemoteInputDevice(LOCAL_NETWORKID));
    g_context->inputDevMgr_.DumpRemoteInputDevice(LOCAL_NETWORKID);
    g_context->inputDevMgr_.AddRemoteInputDevice(LOCAL_NETWORKID, g_device);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.DumpRemoteInputDevice(LOCAL_NETWORKID));
    NetPacket packet(MessageId::DSOFTBUS_INPUT_DEV_SYNC);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.SerializeDevice(g_device, packet));
    g_device = nullptr;
}

/**
 * @tc.name: inputDevcieMgr_test060
 * @tc.desc: Test cooperate plugin HandleRemoteHotPlug
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, inputDevcieMgr_test059, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<IDevice> g_device = std::make_shared<Device>(VREMOTE_NETWORKID);
    NetPacket pkt1(MessageId::INVALID);
    int32_t ret = g_context->dsoftbus_.DeserializeDevice(g_device, pkt1);
    EXPECT_EQ(ret, RET_ERR);
    NetPacket pkt2(MessageId::DSOFTBUS_INPUT_DEV_SYNC);
    ret = g_context->dsoftbus_.DeserializeDevice(g_device, pkt2);
    EXPECT_EQ(ret, RET_ERR);
    NetPacket pkt3(MessageId::DSOFTBUS_INPUT_DEV_HOT_PLUG);
    ret = g_context->dsoftbus_.DeserializeDevice(g_device, pkt3);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: inputDevcieMgr_test061
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, inputDevcieMgr_test060, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<IDevice> g_device = std::make_shared<Device>(VREMOTE_NETWORKID);
    auto inputDev = std::make_shared<MMI::InputDevice>();
    g_device->AddCapability(Device::Capability::DEVICE_CAP_MAX);
    inputDev = g_context->inputDevMgr_.Transform(g_device);
    g_device->AddCapability(Device::Capability::DEVICE_CAP_KEYBOARD);
    inputDev = g_context->inputDevMgr_.Transform(g_device);
    EXPECT_NE(inputDev, nullptr);
    g_device->AddCapability(Device::Capability::DEVICE_CAP_POINTER);
    inputDev = g_context->inputDevMgr_.Transform(g_device);
    EXPECT_NE(inputDev, nullptr);
}

/**
 * @tc.name: inputDevcieMgr_test062
 * @tc.desc: Test cooperate plugin GetRemoteDeviceById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, inputDevcieMgr_test061, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<IDevice> g_device = std::make_shared<Device>(VREMOTE_NETWORKID);
    auto ret = g_context->inputDevMgr_.GetRemoteDeviceById(LOCAL_NETWORKID, VREMOTE_NETWORKID);
    EXPECT_EQ(ret, nullptr);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.RemoveVirtualInputDevice(LOCAL_NETWORKID, VREMOTE_NETWORKID));
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.AddRemoteInputDevice(LOCAL_NETWORKID, g_device));
    ret = g_context->inputDevMgr_.GetRemoteDeviceById(LOCAL_NETWORKID, VREMOTE_NETWORKID);
    EXPECT_NE(ret, nullptr);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.AddVirtualInputDevice(LOCAL_NETWORKID, VREMOTE_NETWORKID));
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.RemoveVirtualInputDevice(LOCAL_NETWORKID, VREMOTE_NETWORKID));
}

/**
 * @tc.name: inputDevcieMgr_test063
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, inputDevcieMgr_test063, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    std::string TEST_DEV_NODE { "/dev/input/TestDeviceNode" };
    env->devMgr_.AddDevice(TEST_DEV_NODE);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.NotifyInputDeviceToRemote(REMOTE_NETWORKID));
}

/**
 * @tc.name: inputDevcieMgr_test064
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, inputDevcieMgr_test064, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceStatus::InputHotplugEvent inputHotplugEvent;
    inputHotplugEvent.isKeyboard = true;
    inputHotplugEvent.deviceId = 1;
    inputHotplugEvent.type = InputHotplugType::UNPLUG;
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.BroadcastHotPlugToRemote(inputHotplugEvent));
}

/**
 * @tc.name: inputDevcieMgr_test065
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, inputDevcieMgr_test065, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceStatus::InputHotplugEvent inputHotplugEvent;
    inputHotplugEvent.isKeyboard = true;
    inputHotplugEvent.deviceId = 1;
    inputHotplugEvent.type = InputHotplugType::PLUG;
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.BroadcastHotPlugToRemote(inputHotplugEvent));
}

/**
 * @tc.name: stateMachine_test065
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test065, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_context->inputDevMgr_.enable_ = true;
    auto [sender, receiver] = Channel<CooperateEvent>::OpenChannel();
    g_context->AttachSender(sender);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.Enable(sender));
}

/**
 * @tc.name: stateMachine_test067
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test067, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    CooperateEvent startEvent (
        CooperateEventType::DSOFTBUS_START_COOPERATE,
        DSoftbusStartCooperate {
            .networkId = LOCAL_NETWORKID
    });
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnRemoteStart(cooperateContext, startEvent));
}

/**
 * @tc.name: stateMachine_test068
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test068, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    CooperateEvent startEvent (
        CooperateEventType::DSOFTBUS_START_COOPERATE,
        DSoftbusStartCooperate {
            .networkId = LOCAL_NETWORKID
    });
    g_stateMachine->isCooperateEnable_ = true;
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnRemoteStart(cooperateContext, startEvent));
}

/**
 * @tc.name: stateMachine_test069
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test069, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    int32_t pid = IPCSkeleton::GetCallingPid();
    Channel<CooperateEvent>::Sender sender;
    auto appStateObserver_ = sptr<StateMachine::AppStateObserver>::MakeSptr(sender, pid);
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->UnregisterApplicationStateObserver());
}

/**
 * @tc.name: stateMachine_test070
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test070, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    std::string commonEvent = EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF;
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnCommonEvent(cooperateContext, commonEvent));
}

/**
 * @tc.name: stateMachine_test071
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test071, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    std::string commonEvent = "-1";
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnCommonEvent(cooperateContext, commonEvent));
}

/**
 * @tc.name: stateMachine_test072
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent072, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent closeEvent(
        CooperateEventType::DSOFTBUS_INPUT_DEV_SYNC,
        DSoftbusSyncInputDevice {
            .networkId = LOCAL_NETWORKID,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnRemoteInputDevice(cooperateContext, closeEvent);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: dsoftbusHandler_test073
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, dsoftbusHandler_test073, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    ASSERT_NO_FATAL_FAILURE(g_context->dsoftbus_.OnConnected(localNetworkId));
}

/**
 * @tc.name: dsoftbusHandler_test074
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, dsoftbusHandler_test074, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MessageId::DSOFTBUS_START_COOPERATE);
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    ASSERT_NO_FATAL_FAILURE(g_context->dsoftbus_.OnRemoteInputDevice(localNetworkId, pkt));
}

/**
 * @tc.name: dsoftbusHandler_test075
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, dsoftbusHandler_test075, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MessageId::DSOFTBUS_START_COOPERATE);
    int32_t testData = 10;
    pkt << testData;
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    ASSERT_NO_FATAL_FAILURE(g_context->dsoftbus_.OnRemoteInputDevice(localNetworkId, pkt));
}

/**
 * @tc.name: dsoftbusHandler_test076
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, dsoftbusHandler_test076, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MessageId::DSOFTBUS_START_COOPERATE);
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    ASSERT_NO_FATAL_FAILURE(g_context->dsoftbus_.OnRemoteHotPlug(localNetworkId, pkt));
}

/**
 * @tc.name: dsoftbusHandler_test077
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, dsoftbusHandler_test077, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MessageId::DSOFTBUS_START_COOPERATE);
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    ASSERT_NO_FATAL_FAILURE(g_context->dsoftbus_.OnRemoteHotPlug(localNetworkId, pkt));
}

/**
 * @tc.name: stateMachine_test078
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test078, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    int32_t testErrCode = 0;
    CooperateEvent startEvent (
        CooperateEventType::DSOFTBUS_SESSION_OPENED,
        DDMBoardOnlineEvent {
            .networkId = LOCAL_NETWORKID,
            .normal = true,
            .errCode = testErrCode,
    });
    g_stateMachine->isCooperateEnable_ = true;
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnSoftbusSessionOpened(cooperateContext, startEvent));
}

/**
 * @tc.name: stateMachine_test079
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test079, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    CooperateEvent startEvent (
        CooperateEventType::DSOFTBUS_INPUT_DEV_SYNC,
        DSoftbusSyncInputDevice {
            .networkId = LOCAL_NETWORKID,
    });
    g_stateMachine->isCooperateEnable_ = true;
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnRemoteInputDevice(cooperateContext, startEvent));
}

/**
 * @tc.name: stateMachine_test080
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test080, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    CooperateEvent startEvent (
        CooperateEventType::DSOFTBUS_INPUT_DEV_HOT_PLUG,
        DSoftbusHotPlugEvent {
            .networkId = LOCAL_NETWORKID,
            .type = InputHotplugType::UNPLUG,
    });
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    g_stateMachine->isCooperateEnable_ = true;
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnRemoteHotPlug(cooperateContext, startEvent));
}

/**
 * @tc.name: cooperateIn_test081
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, cooperateIn_test081, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    CooperateEvent startEvent (
        CooperateEventType::DSOFTBUS_INPUT_DEV_HOT_PLUG,
        DSoftbusStartCooperate {
            .networkId = LOCAL_NETWORKID
    });
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    g_stateMachine->isCooperateEnable_ = true;
    ASSERT_NO_FATAL_FAILURE(relay->OnAppClosed(cooperateContext, startEvent));
}

/**
 * @tc.name: cooperateIn_test082
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, cooperateIn_test082, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    CooperateEvent event(
        CooperateEventType::INPUT_POINTER_EVENT,
        InputPointerEvent {
            .deviceId = pointerEvent->GetDeviceId(),
            .pointerAction = pointerEvent->GetPointerAction(),
            .sourceType = pointerEvent->GetSourceType(),
            .position = Coordinate {
                .x = pointerItem.GetDisplayX(),
                .y = pointerItem.GetDisplayY(),
            }
        });
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    g_stateMachine->isCooperateEnable_ = true;
    ASSERT_NO_FATAL_FAILURE(relay->OnPointerEvent(cooperateContext, event));
}

/**
 * @tc.name: cooperateIn_test083
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, cooperateIn_test083, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    int32_t testDeviceId = 10;
    CooperateEvent event(
        CooperateEventType::INPUT_POINTER_EVENT,
        InputPointerEvent {
            .deviceId = testDeviceId,
            .pointerAction = pointerEvent->GetPointerAction(),
            .sourceType = pointerEvent->GetSourceType(),
            .position = Coordinate {
                .x = pointerItem.GetDisplayX(),
                .y = pointerItem.GetDisplayY(),
            }
        });
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    g_stateMachine->isCooperateEnable_ = true;
    ASSERT_NO_FATAL_FAILURE(relay->OnPointerEvent(cooperateContext, event));
}

/**
 * @tc.name: cooperateIn_test084
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, cooperateIn_test084, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    auto pointerEvent = MMI::PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    MMI::PointerEvent::PointerItem pointerItem;
    pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem);
    int32_t testDeviceId = 10;
    CooperateEvent event(
        CooperateEventType::INPUT_POINTER_EVENT,
        InputPointerEvent {
            .deviceId = testDeviceId,
            .pointerAction = pointerEvent->GetPointerAction(),
            .sourceType = pointerEvent->GetSourceType(),
            .position = Coordinate {
                .x = pointerItem.GetDisplayX(),
                .y = pointerItem.GetDisplayY(),
            }
        });
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_IN;
    g_stateMachine->isCooperateEnable_ = true;
    ASSERT_NO_FATAL_FAILURE(relay->OnPointerEvent(cooperateContext, event));
}

/**
 * @tc.name: cooperateIn_test085
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent085, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_INPUT_DEV_SYNC,
        UpdateCooperateFlagEvent {
            .mask = 10,
            .flag = 1,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnUpdateCooperateFlag(cooperateContext, event);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: cooperateIn_test086
 * @tc.desc: Test OnSwitchChanged interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent086, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DDM_BOARD_OFFLINE,
        DDMBoardOfflineEvent {
            .networkId = REMOTE_NETWORKID
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnSwitchChanged(cooperateContext, event);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    relay->OnSwitchChanged(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: cooperateOut_test088
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, cooperateOut_test088, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    int32_t testErrCode = 0;
    CooperateEvent event (
        CooperateEventType::DSOFTBUS_SESSION_OPENED,
        DDMBoardOnlineEvent {
            .networkId = REMOTE_NETWORKID,
            .normal = true,
            .errCode = testErrCode,
    });
    g_stateMachine->isCooperateEnable_ = true;
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_OUT;
    ASSERT_NO_FATAL_FAILURE(relay->OnBoardOffline(cooperateContext, event));
}

/**
 * @tc.name: cooperateOut_test089
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, cooperateOut_test089, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    int32_t testErrCode = 0;
    CooperateEvent event (
        CooperateEventType::DSOFTBUS_SESSION_OPENED,
        DDMBoardOnlineEvent {
            .networkId = REMOTE_NETWORKID,
            .normal = false,
            .errCode = testErrCode,
    });
    g_stateMachine->isCooperateEnable_ = true;
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_OUT;
    ASSERT_NO_FATAL_FAILURE(relay->OnSwitchChanged(cooperateContext, event));
}

/**
 * @tc.name: cooperateOut_test090
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, cooperateOut_test090, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StopCooperateEvent stopEvent {
        .pid = IPCSkeleton::GetCallingPid(),
        .userData = 1,
        .isUnchained = false,
    };
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut cooperateOut(*g_stateMachine, env);
    ASSERT_NO_FATAL_FAILURE(cooperateOut.UnchainConnections(cooperateContext, stopEvent));
}

/**
 * @tc.name: cooperateFree_test091
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent91, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_INPUT_DEV_SYNC,
        StartCooperateEvent {
        .pid = IPCSkeleton::GetCallingPid(),
        .userData = 1,
        .remoteNetworkId = "test",
        .startDeviceId = 1,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    Cooperate::CooperateFree stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateFree::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnStart(cooperateContext, event);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: stateMachine_test092
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent092, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent closeEvent(
        CooperateEventType::DSOFTBUS_INPUT_DEV_HOT_PLUG,
        DSoftbusHotPlugEvent {
            .networkId = LOCAL_NETWORKID,
            .type = InputHotplugType::PLUG,
            .device = std::make_shared<Device>(VREMOTE_NETWORKID),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = LOCAL_NETWORKID;
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnRemoteHotPlug(cooperateContext, closeEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: stateMachine_test093
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent093, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent startEvent(
        CooperateEventType::DSOFTBUS_START_COOPERATE,
        DSoftbusStartCooperate {
            .networkId = LOCAL_NETWORKID
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    stateIn.initial_->OnRemoteStart(cooperateContext, startEvent);
    relay->OnRemoteStart(cooperateContext, startEvent);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.initial_->OnRemoteStart(cooperateContext, startEvent);

    cooperateContext.remoteNetworkId_ = LOCAL_NETWORKID;
    stateIn.initial_->OnRemoteStart(cooperateContext, startEvent);
    relay->OnRemoteStart(cooperateContext, startEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnStart in the RelayConfirmation class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent094, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent startEvent(
        CooperateEventType::START,
        StartCooperateEvent{
        .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnStart(cooperateContext, startEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnSwitchChanged interface
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent095, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DDM_BOARD_OFFLINE,
        DDMBoardOfflineEvent {
            .networkId = REMOTE_NETWORKID
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnSwitchChanged(cooperateContext, event);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    relay->OnSwitchChanged(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: cooperateFree_test096
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent96, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_INPUT_DEV_SYNC,
        StartWithOptionsEvent {
        .pid = IPCSkeleton::GetCallingPid(),
        .userData = 1,
        .remoteNetworkId = "test",
        .startDeviceId = 1,
        .displayX = 500,
        .displayY = 500,
        .displayId = 0,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    Cooperate::CooperateFree stateIn(*g_stateMachine, env);
    ASSERT_NE(stateIn.initial_, nullptr);
    auto relay = std::make_shared<Cooperate::CooperateFree::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnStartWithOptions(cooperateContext, event);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: cooperateIn_test097
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_OnEvent097, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::WITH_OPTIONS_START,
        StartWithOptionsEvent{
        .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: stateMachine_test098
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test098, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    CooperateEvent event (
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        DSoftbusCooperateOptions {
            .networkId = LOCAL_NETWORKID
    });
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnRemoteStartWithOptions(cooperateContext, event));
}

/**
 * @tc.name: stateMachine_test099
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test099, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    CooperateEvent event (
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        DSoftbusCooperateOptions {
            .networkId = LOCAL_NETWORKID
    });
    g_stateMachine->isCooperateEnable_ = true;
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnRemoteStartWithOptions(cooperateContext, event));
}

/**
 * @tc.name: StateMachineTest_test100
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test100, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::WITH_OPTIONS_START,
        StartWithOptionsEvent{
            .remoteNetworkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnRelayWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test101
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test101, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::WITH_OPTIONS_START,
        StartWithOptionsEvent{
            .remoteNetworkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnComeBackWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test102
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test102, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        DSoftbusCooperateOptions{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "testtrue", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnRemoteStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test103
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test103, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        DSoftbusCooperateOptions{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnRemoteStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test104
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test104, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::WITH_OPTIONS_START,
        StartWithOptionsEvent{
            .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::Initial>(stateIn);
    ASSERT_NE(relay, nullptr);
    relay->OnProgressWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test105
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test105, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        DSoftbusCooperateOptions{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "testtrue", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnRemoteStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test106
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test106, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        DSoftbusCooperateOptions{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnRemoteStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test107
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test107, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE_WITHOPTIONS_FINISHED,
        DSoftbusRelayCooperateFinished{
            .networkId = "test",
            .normal = true,
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "testtrue", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnResponseWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test108
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test108, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE_WITHOPTIONS_FINISHED,
        DSoftbusRelayCooperateFinished{
            .networkId = "test",
            .normal = true,
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnResponseWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test109
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test109, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE_WITHOPTIONS_FINISHED,
        DSoftbusRelayCooperateFinished{
            .networkId = "test",
            .normal = false,
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnResponseWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test110
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test110, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE_WITHOPTIONS_FINISHED,
        StartWithOptionsEvent{
            .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateIn::RelayConfirmation>(stateIn, stateIn.initial_);
    ASSERT_NE(relay, nullptr);
    relay->OnNormalWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test111
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test111, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::WITH_OPTIONS_START,
        StartWithOptionsEvent{
            .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    relay->OnStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test112
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test112, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        DSoftbusCooperateOptions{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "testtrue", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    relay->OnRemoteStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test113
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test113, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        DSoftbusCooperateOptions{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    relay->OnRemoteStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test114
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test114, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        DSoftbusCooperateOptions{
            .networkId = cooperateContext.Local(),
    });
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    relay->OnRemoteStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test115
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test115, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COME_BACK_WITH_OPTIONS,
        DSoftbusCooperateOptions{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "testtrue", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    relay->OnComeBackWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test116
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test116, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COME_BACK_WITH_OPTIONS,
        DSoftbusCooperateOptions{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    relay->OnComeBackWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test117
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test117, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE_WITHOPTIONS,
        DSoftbusRelayCooperate{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    relay->OnRelayWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test118
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test118, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE_WITHOPTIONS,
        DSoftbusRelayCooperate{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    StartCooperateEvent startEvent {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(),
    };
    cooperateContext.StartCooperate(startEvent);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    relay->OnRelayWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test119
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test119, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_RELAY_COOPERATE_WITHOPTIONS,
        StartWithOptionsEvent{
            .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateOut::Initial>(stateOut);
    ASSERT_NE(relay, nullptr);
    relay->OnProgressWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test120
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test120, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::WITH_OPTIONS_START,
        StartWithOptionsEvent{
            .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateFree::Initial>(stateFree);
    ASSERT_NE(relay, nullptr);
    relay->OnStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test121
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test121, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        DSoftbusCooperateOptions{
            .networkId = "test",
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateFree::Initial>(stateFree);
    ASSERT_NE(relay, nullptr);
    relay->OnRemoteStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test122
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test122, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COOPERATE_WITH_OPTIONS,
        StartWithOptionsEvent{
            .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    auto relay = std::make_shared<Cooperate::CooperateFree::Initial>(stateFree);
    ASSERT_NE(relay, nullptr);
    relay->OnProgressWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: StateMachineTest_test123
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, StateMachineTest_test123, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    CooperateEvent event (
        CooperateEventType::WITH_OPTIONS_START,
        StartWithOptionsEvent {
            .remoteNetworkId = LOCAL_NETWORKID,
            .errCode = std::make_shared<std::promise<int32_t>>(),
    });
    g_stateMachine->isCooperateEnable_ = true;
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->StartCooperateWithOptions(cooperateContext, event));
}

/**
 * @tc.name: stateMachine_test124
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test124, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    StartWithOptionsEvent event{
        .pid = IPCSkeleton::GetCallingPid(),
        .userData = 1,
        .remoteNetworkId = "test",
        .startDeviceId = 1,
        .displayX = 500,
        .displayY = 500,
        .displayId = 0,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    };
    ASSERT_NO_FATAL_FAILURE(g_context->StartCooperateWithOptions(event));
}

/**
 * @tc.name: stateMachine_test125
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test125, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusCooperateWithOptionsFinished result {
        .success = false,
        .errCode = static_cast<int32_t>(CoordinationErrCode::UNEXPECTED_START_CALL)
    };
    ASSERT_NO_FATAL_FAILURE(g_context->OnRemoteStart(result));
}

/**
 * @tc.name: stateMachine_test126
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test126, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.StartCooperateWithOptions("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: stateMachine_test127
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test127, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.ComeBackWithOptions("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: stateMachine_test128
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test128, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.RelayCooperateWithOptions("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: stateMachine_test129
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test129, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket packet(MessageId::DSOFTBUS_START_COOPERATE);
    g_context->dsoftbus_.OnStartCooperateWithOptions("test", packet);
    g_context->dsoftbus_.OnComeBackWithOptions("test", packet);
    g_context->dsoftbus_.OnRelayCooperateWithOptions("test", packet);
    g_context->dsoftbus_.OnRelayCooperateWithOptionsFinish("test", packet);
    int32_t ret = g_context->dsoftbus_.RelayCooperateWithOptionsFinish("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: stateMachine_test130
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test130, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket packet(MessageId::DSOFTBUS_START_COOPERATE);
    g_context->dsoftbus_.OnStartCooperateWithOptions("test", packet);
    g_context->dsoftbus_.OnComeBackWithOptions("test", packet);
    g_context->dsoftbus_.OnRelayCooperateWithOptions("test", packet);
    g_context->dsoftbus_.OnRelayCooperateWithOptionsFinish("test", packet);
    int32_t ret = g_context->dsoftbus_.RelayCooperateWithOptionsFinish("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: stateMachine_test131
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test131, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    StartWithOptionsEvent result {
        .pid = IPCSkeleton::GetCallingPid(),
        .userData = 1,
        .remoteNetworkId = "test",
        .startDeviceId = 1,
        .displayX = 500,
        .displayY = 500,
        .displayId = 1,
        .errCode = std::make_shared<std::promise<int32_t>>()
    };
    ASSERT_NO_FATAL_FAILURE(g_context->eventMgr_.StartCooperateWithOptions(result));
}

/**
 * @tc.name: stateMachine_test132
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test132, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusCooperateOptions result {
        .networkId = LOCAL_NETWORKID
    };
    ASSERT_NO_FATAL_FAILURE(g_context->eventMgr_.StartCooperateWithOptionsFinish(result));
}

/**
 * @tc.name: stateMachine_test133
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test133, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusCooperateOptions result {
        .networkId = LOCAL_NETWORKID
    };
    ASSERT_NO_FATAL_FAILURE(g_context->eventMgr_.RemoteStartWithOptions(result));
}

/**
 * @tc.name: stateMachine_test134
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test134, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusCooperateWithOptionsFinished result {
        .success = false,
        .errCode = static_cast<int32_t>(CoordinationErrCode::UNEXPECTED_START_CALL)
    };
    ASSERT_NO_FATAL_FAILURE(g_context->eventMgr_.RemoteStartWithOptionsFinish(result));
}

/**
 * @tc.name: stateMachine_test135
 * @tc.desc: Tcooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test135, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateIn stateIn(*g_stateMachine, env);
    StartWithOptionsEvent event {
        .pid = IPCSkeleton::GetCallingPid(),
        .userData = 1,
        .remoteNetworkId = "test",
        .startDeviceId = 1,
        .displayX = 500,
        .displayY = 500,
        .displayId = 0,
        .errCode = std::make_shared<std::promise<int32_t>>(),
    };
    ASSERT_NO_FATAL_FAILURE(stateIn.process_.StartCooperateWithOptions(cooperateContext, event));
}

/**
 * @tc.name: stateMachine_test136
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test136, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    DSoftbusCooperateOptions result {
        .networkId = "test",
        .originNetworkId = "test",
        .success = true,
        .cooperateOptions = CooperateOptions {
            .displayX = 500,
            .displayY = 500,
            .displayId = -500
        }
    };
    ASSERT_NO_FATAL_FAILURE(g_context->AdjustPointerPos(result));
}

/**
 * @tc.name: stateMachine_test137
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test137, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusCooperateOptions result {
        .networkId = "test",
        .originNetworkId = "test",
        .success = true,
        .cooperateOptions = CooperateOptions {
            .displayX = -50000,
            .displayY = 500,
            .displayId = 5
        }
    };
    ASSERT_NO_FATAL_FAILURE(g_context->AdjustPointerPos(result));
}

/**
 * @tc.name: stateMachine_test138
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperatePluginTest, stateMachine_test138, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusCooperateOptions result {
        .networkId = "test",
        .originNetworkId = "test",
        .success = true,
        .cooperateOptions = CooperateOptions {
            .displayX = 500,
            .displayY = -5000,
            .displayId = 5
        }
    };
    ASSERT_NO_FATAL_FAILURE(g_context->AdjustPointerPos(result));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
