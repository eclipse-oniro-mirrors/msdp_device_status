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
#include "cooperate_in_test.h"

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

void CooperateInTest::NotifyCooperate()
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

void CooperateInTest::CheckInHot()
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

void CooperateInTest::SetUpTestCase() {}

void CooperateInTest::SetUp()
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

void CooperateInTest::TearDown()
{
    g_context = nullptr;
    g_contextOne = nullptr;
    g_session = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void CooperateInTest::OnThreeStates(const CooperateEvent &event)
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
 * @tc.name: CooperateInTest001
 * @tc.desc: Test OnProgress and OnReset in the RelayConfirmation class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest001, TestSize.Level1)
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
 * @tc.name: CooperateInTest002
 * @tc.desc: Test OnBoardOffline in the Initial class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest002, TestSize.Level1)
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
 * @tc.name: CooperateInTest003
 * @tc.desc: Test OnBoardOffline in the Initial class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest003, TestSize.Level1)
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
 * @tc.name: CooperateInTest004
 * @tc.desc: Test OnRelay in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest004, TestSize.Level1)
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
 * @tc.name: CooperateInTest005
 * @tc.desc: Test OnComeBack in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COME_BACK,
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
    stateIn.initial_->OnComeBack(cooperateContext, event);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    stateIn.initial_->OnComeBack(cooperateContext, event);
    stateIn.initial_->relay_ = nullptr;
    stateIn.initial_->OnComeBack(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateInTest006
 * @tc.desc: Test OnResponse in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest006, TestSize.Level1)
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
 * @tc.name: CooperateInTest007
 * @tc.desc: Test OnComeBack in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest007, TestSize.Level1)
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
 * @tc.name: CooperateInTest008
 * @tc.desc: Test OnDisable in the RelayConfirmation class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest008, TestSize.Level1)
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
 * @tc.name: CooperateInTest009
 * @tc.desc: Test OnStop in the RelayConfirmation class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest009, TestSize.Level1)
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
 * @tc.name: CooperateInTest010
 * @tc.desc: Test OnRemoteStart
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest010, TestSize.Level1)
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
    CooperateEvent bothLocalEventStop(
        CooperateEventType::DSOFTBUS_STOP_COOPERATE,
        DDMBoardOnlineEvent {
            .networkId = localNetworkId
        });
    stateIn.initial_->OnRemoteStop(cooperateContext, bothLocalEventStop);
    relay->OnRemoteStop(cooperateContext, bothLocalEventStop);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateInTest011
 * @tc.desc: Test OnRemoteStart
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest011, TestSize.Level1)
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
 * @tc.name: CooperateInTest012
 * @tc.desc: Test OnRemoteStart
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest012, TestSize.Level1)
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
 * @tc.name: CooperateInTest013
 * @tc.desc: Test OnRemoteStop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest013, TestSize.Level1)
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
 * @tc.name: CooperateInTest014
 * @tc.desc: Test OnSoftbusSessionClosed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest014, TestSize.Level1)
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
 * @tc.name: CooperateInTest015
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest015, TestSize.Level1)
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
 * @tc.name: CooperateInTest016
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest016, TestSize.Level1)
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
 * @tc.name: CooperateInTest017
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest017, TestSize.Level1)
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
 * @tc.name: CooperateInTest018
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest018, TestSize.Level1)
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
 * @tc.name: CooperateInTest019
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest019, TestSize.Level1)
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
 * @tc.name: CooperateInTest020
 * @tc.desc: Test OnSwitchChanged interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest020, TestSize.Level1)
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
 * @tc.name: CooperateInTest021
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest021, TestSize.Level1)
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
 * @tc.name: CooperateInTest022
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest022, TestSize.Level1)
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
 * @tc.name: CooperateInTest023
 * @tc.desc: Test OnStart in the RelayConfirmation class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest023, TestSize.Level1)
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
 * @tc.name: CooperateInTest024
 * @tc.desc: Test OnSwitchChanged interface
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(CooperateInTest, CooperateInTest024, TestSize.Level1)
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
 * @tc.name: CooperateInTest025
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest025, TestSize.Level0)
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
 * @tc.name: CooperateInTest026
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest026, TestSize.Level0)
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
 * @tc.name: CooperateInTest027
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest027, TestSize.Level1)
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
 * @tc.name: CooperateInTest028
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest028, TestSize.Level1)
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
 * @tc.name: CooperateInTest029
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest029, TestSize.Level1)
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
 * @tc.name: CooperateInTest030
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest030, TestSize.Level1)
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
 * @tc.name: CooperateInTest031
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest031, TestSize.Level1)
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
 * @tc.name: CooperateInTest032
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest032, TestSize.Level1)
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
 * @tc.name: CooperateInTest033
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest033, TestSize.Level1)
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
 * @tc.name: CooperateInTest034
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest034, TestSize.Level1)
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
 * @tc.name: CooperateInTest035
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest035, TestSize.Level1)
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
 * @tc.name: CooperateInTest036
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest036, TestSize.Level1)
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
 * @tc.name: CooperateInTest037
 * @tc.desc: Tcooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest037, TestSize.Level1)
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
 * @tc.name: CooperateInTest038
 * @tc.desc: Test OnRelay in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest038, TestSize.Level1)
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
            .uid = 20020135,
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
 * @tc.name: CooperateInTest039
 * @tc.desc: Test OnComeBack in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest039, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DSOFTBUS_COME_BACK,
        StartCooperateEvent{
            .pid = IPCSkeleton::GetCallingPid(),
            .userData = 1,
            .remoteNetworkId = "test",
            .startDeviceId = 1,
            .errCode = std::make_shared<std::promise<int32_t>>(),
            .uid = 20020135,
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
 * @tc.name: CooperateInTest040
 * @tc.desc: Test OnComeBack in the CooperateIn class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateInTest, CooperateInTest040, TestSize.Level1)
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
        .uid = 20020135,
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
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS