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
#include "event_manager_test.h"

#include "cooperate_context.h"
#include "cooperate_free.h"
#include "cooperate_in.h"
#include "cooperate_out.h"
#include "ddm_adapter.h"
#include "device.h"
#include "dsoftbus_adapter.h"
#include "event_manager.h"
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

void EventManagerTest::NotifyCooperate()
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

void EventManagerTest::CheckInHot()
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

void EventManagerTest::SetUpTestCase() {}

void EventManagerTest::SetUp()
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

void EventManagerTest::TearDown()
{
    g_context = nullptr;
    g_contextOne = nullptr;
    g_session = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void EventManagerTest::OnThreeStates(const CooperateEvent &event)
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
 * @tc.name: stateMachine_test136
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventManagerTest, stateMachine_test136, TestSize.Level1)
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
 * @tc.name: EventManagerTest1
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventManagerTest, EventManagerTest001, TestSize.Level1)
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
 * @tc.name: EventManagerTest002
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventManagerTest, EventManagerTest002, TestSize.Level1)
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
 * @tc.name: EventManagerTest003
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventManagerTest, EventManagerTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusCooperateOptions result {
        .networkId = LOCAL_NETWORKID
    };
    ASSERT_NO_FATAL_FAILURE(g_context->eventMgr_.StartCooperateWithOptionsFinish(result));
}

/**
 * @tc.name: EventManagerTest004
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventManagerTest, EventManagerTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusCooperateOptions result {
        .networkId = LOCAL_NETWORKID
    };
    ASSERT_NO_FATAL_FAILURE(g_context->eventMgr_.RemoteStartWithOptions(result));
}

/**
 * @tc.name: EventManagerTest005
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventManagerTest, EventManagerTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusCooperateWithOptionsFinished result {
        .success = false,
        .errCode = static_cast<int32_t>(CoordinationErrCode::UNEXPECTED_START_CALL)
    };
    ASSERT_NO_FATAL_FAILURE(g_context->eventMgr_.RemoteStartWithOptionsFinish(result));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
