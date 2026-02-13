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
#include "cooperate_out_test.h"

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

void CooperateOutTest::NotifyCooperate()
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

void CooperateOutTest::CheckInHot()
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

void CooperateOutTest::SetUpTestCase() {}

void CooperateOutTest::SetUp()
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

void CooperateOutTest::TearDown()
{
    g_context = nullptr;
    g_contextOne = nullptr;
    g_session = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void CooperateOutTest::OnThreeStates(const CooperateEvent &event)
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
 * @tc.name: CooperateOutTest001
 * @tc.desc: Test OnRelay in the CooperateOut class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest001, TestSize.Level1)
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
 * @tc.name: CooperateOutTest002
 * @tc.desc: Test OnComeBack in the CooperateOut class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest002, TestSize.Level1)
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
 * @tc.name: CooperateOutTest003
 * @tc.desc: Test OnRemoteStart
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest003, TestSize.Level1)
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
    cooperateContext.remoteNetworkId_ = localNetworkId;
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.initial_->OnRemoteStart(cooperateContext, bothLocalEvent);
    CooperateEvent bothLocalEventStop(
        CooperateEventType::DSOFTBUS_STOP_COOPERATE,
        DDMBoardOnlineEvent {
            .networkId = localNetworkId
        });
    stateOut.initial_->OnRemoteStop(cooperateContext, bothLocalEventStop);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateOutTest005
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest005, TestSize.Level1)
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
 * @tc.name: CooperateOutTest006
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest006, TestSize.Level1)
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
 * @tc.name: CooperateOutTest007
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest007, TestSize.Level1)
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
 * @tc.name: CooperateOutTest008
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest008, TestSize.Level1)
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
 * @tc.name: CooperateOutTest009
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest009, TestSize.Level1)
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
 * @tc.name: CooperateOutTest010
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest010, TestSize.Level1)
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
 * @tc.name: CooperateOutTest011
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest011, TestSize.Level1)
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
 * @tc.name: CooperateOutTest012
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest012, TestSize.Level1)
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
 * @tc.name: CooperateOutTest013
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest013, TestSize.Level1)
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
 * @tc.name: CooperateOutTest014
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest014, TestSize.Level1)
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
 * @tc.name: CooperateOutTest015
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest015, TestSize.Level1)
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
 * @tc.name: CooperateOutTest016
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest016, TestSize.Level1)
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
 * @tc.name: CooperateOutTest017
 * @tc.desc: Test CooperateOut constructor and initial_ initialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest017, TestSize.Level1)
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
    auto cooperateOut = std::make_shared<Cooperate::CooperateOut>(*g_stateMachine, env);
    ASSERT_NO_FATAL_FAILURE(cooperateOut->SimulateShowPointerEvent());
}

/**
 * @tc.name: CooperateOutTest018
 * @tc.desc: Test simulate event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest018, TestSize.Level1)
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
    auto cooperateOut = std::make_shared<Cooperate::CooperateOut>(*g_stateMachine, env);
    cooperateOut->pressedButtons_ = {1, 2, 3};
    ASSERT_NO_FATAL_FAILURE(cooperateOut->SimulateShowPointerEvent());
}

/**
 * @tc.name: CooperateOutTest017
 * @tc.desc: Test CooperateOut constructor and initial_ initialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest017, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
}

/**
 * @tc.name: CooperateOutTest018
 * @tc.desc: Test OnEvent with DISABLE event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest018, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DISABLE,
        DisableCooperateEvent {
            .pid = IPCSkeleton::GetCallingPid(),
            .userData = 1,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.OnEvent(cooperateContext, event);
}

/**
 * @tc.name: CooperateOutTest019
 * @tc.desc: Test Initial OnStopAboutVirtualTrackpad
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest019, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::STOP,
        StopCooperateEvent {
            .pid = IPCSkeleton::GetCallingPid(),
            .userData = 1,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.initial_->OnStopAboutVirtualTrackpad(cooperateContext, event);
}

/**
 * @tc.name: CooperateOutTest020
 * @tc.desc: Test OnEvent with APP_CLOSED event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest020, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::APP_CLOSED,
        ClientDiedEvent {
            .pid = IPCSkeleton::GetCallingPid(),
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateOut stateOut(*g_stateMachine, env);
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.OnEvent(cooperateContext, event);
}

/**
 * @tc.name: CooperateOutTest021
 * @tc.desc: Test Initial OnRelayWithOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateOutTest, CooperateOutTest021, TestSize.Level1)
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
    ASSERT_NE(stateOut.initial_, nullptr);
    stateOut.initial_->OnRelayWithOptions(cooperateContext, event);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS