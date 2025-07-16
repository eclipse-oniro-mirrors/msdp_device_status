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
#include "mouse_location_test.h"

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
const std::string TEST_DEV_NODE { "/dev/input/TestDeviceNode" };
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
constexpr int32_t HOTAREA_500 { 500 };
constexpr int32_t HOTAREA_NEGATIVE_500 { -500 };
constexpr int32_t HOTAREA_NEGATIVE_200 { -200 };
constexpr int32_t HOTAREA_250 { 250 };
constexpr int32_t HOTAREA_200 { 200 };
constexpr int32_t HOTAREA_150 { 150 };
constexpr int32_t HOTAREA_50 { 50 };
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

MMI::PointerEvent::PointerItem MouseLocationTest::CreatePointerItem(int32_t pointerId, int32_t deviceId,
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

void MouseLocationTest::NotifyCooperate()
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

void MouseLocationTest::CheckInHot()
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

void MouseLocationTest::SetUpTestCase() {}

void MouseLocationTest::SetUp()
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
    int32_t sockFds[2] { -1, -1 };
    g_session = std::make_shared<SocketSession>("test", moduleType, tokenType, sockFds[0], uid, pid);
}

void MouseLocationTest::TearDown()
{
    g_context = nullptr;
    g_contextOne = nullptr;
    g_session = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void MouseLocationTest::OnThreeStates(const CooperateEvent &event)
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
    virtual void OnTransitionOut(const std::string &remoteNetworkId, const CooperateInfo &cooperateInfo) {}
    virtual void OnTransitionIn(const std::string &remoteNetworkId, const CooperateInfo &cooperateInfo) {}
    virtual void OnBack(const std::string &remoteNetworkId, const CooperateInfo &cooperateInfo) {}
    virtual void OnRelay(const std::string &remoteNetworkId, const CooperateInfo &cooperateInfo) {}
    virtual void OnReset() {}
    virtual void CloseDistributedFileConnection(const std::string &remoteNetworkId) {}
};

/**
 * @tc.name: MouseLocationTest1
 * @tc.desc: MouseLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationTest, MouseLocationTest001, TestSize.Level1)
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
 * @tc.name: MouseLocationTest2
 * @tc.desc: MouseLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationTest, MouseLocationTest002, TestSize.Level1)
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
 * @tc.name: MouseLocationTest3
 * @tc.desc: MouseLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationTest, MouseLocationTest003, TestSize.Level1)
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
 * @tc.name: MouseLocationTest4
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationTest, MouseLocationTest004, TestSize.Level1)
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
 * @tc.name: MouseLocationTest5
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationTest, MouseLocationTest005, TestSize.Level1)
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
 * @tc.name: MouseLocationTest6
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationTest, MouseLocationTest006, TestSize.Level1)
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
 * @tc.name: MouseLocationTest7
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseLocationTest, MouseLocationTest007, TestSize.Level1)
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

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS