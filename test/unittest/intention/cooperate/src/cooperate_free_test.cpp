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
#include "cooperate_free_test.h"

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

void CooperateFreeTest::NotifyCooperate()
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

void CooperateFreeTest::CheckInHot()
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

void CooperateFreeTest::SetUpTestCase() {}

void CooperateFreeTest::SetUp()
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

void CooperateFreeTest::TearDown()
{
    g_context = nullptr;
    g_contextOne = nullptr;
    g_session = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void CooperateFreeTest::OnThreeStates(const CooperateEvent &event)
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
 * @tc.name: stateMachine_test136
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, stateMachine_test136, TestSize.Level1)
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
HWTEST_F(CooperateFreeTest, stateMachine_test137, TestSize.Level1)
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
 * @tc.name: CooperateFreeTest001
 * @tc.desc: Test OnProgress and OnReset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest001, TestSize.Level1)
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
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest002
 * @tc.desc: Test OnRemoteStart
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest002, TestSize.Level1)
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
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    stateFree.initial_->OnRemoteStart(cooperateContext, bothLocalEvent);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest003
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest003, TestSize.Level1)
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
 * @tc.name: CooperateFreeTest004
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest004, TestSize.Level1)
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
 * @tc.name: CooperateFreeTest005
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest005, TestSize.Level1)
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
 * @tc.name: CooperateFreeTest006
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest006, TestSize.Level1)
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
 * @tc.name: CooperateFreeTest007
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest007, TestSize.Level1)
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
        .uid = 20020135,
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
 * @tc.name: CooperateFreeTest008
 * @tc.desc: Test simulate event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    auto pointerEvent = OHOS::MMI::PointerEvent::Create();
    OHOS::MMI::PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetRawDx(0);
    item.SetRawDy(0);
    CHKPV(pointerEvent);
    pointerEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(OHOS::MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(item);
    g_context->inputEventBuilder_.pointerEvent_ = pointerEvent;
    auto cooperateFree = std::make_shared<Cooperate::CooperateFree>(*g_stateMachine, env);
    ASSERT_NO_FATAL_FAILURE(CooperateFree->SimulateShowPointerEvent(cooperateContext));
}

/**
 * @tc.name: CooperateFreeTest009
 * @tc.desc: Test simulate event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::set<int32_t> pressedButtons = {1, 2, 3};
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    auto pointerEvent = OHOS::MMI::PointerEvent::Create();
    OHOS::MMI::PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetRawDx(0);
    item.SetRawDy(0);
    CHKPV(pointerEvent);
    pointerEvent->SetPointerAction(OHOS::MMI::PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(OHOS::MMI::PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(item);
    for (auto buttonId : pressedButtons) {
        pointerEvent->SetButtonPressed(buttonId);
    }
    g_context->inputEventBuilder_.pointerEvent_ = pointerEvent;
    auto cooperateFree = std::make_shared<Cooperate::CooperateFree>(*g_stateMachine, env);
    ASSERT_NO_FATAL_FAILURE(CooperateFree->SimulateShowPointerEvent(cooperateContext));
}

/**
 * @tc.name: CooperateFreeTest010
 * @tc.desc: Test CooperateFree constructor and initial_ initialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);
}

/**
 * @tc.name: CooperateFreeTest011
 * @tc.desc: Test OnEvent with DISABLE event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest011, TestSize.Level1)
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
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);
    stateFree.OnEvent(cooperateContext, event);
}

/**
 * @tc.name: CooperateFreeTest012
 * @tc.desc: Test OnEvent with APP_CLOSED event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest012, TestSize.Level1)
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
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);
    stateFree.OnEvent(cooperateContext, event);
}

/**
 * @tc.name: CooperateFreeTest013
 * @tc.desc: Test OnEvent with UPDATE_COOPERATE_FLAG event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::UPDATE_COOPERATE_FLAG,
        UpdateCooperateFlagEvent {
            .mask = COOPERATE_FLAG_HIDE_CURSOR,
            .flag = COOPERATE_FLAG_HIDE_CURSOR,
        });
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);
    stateFree.OnEvent(cooperateContext, event);
}

/**
 * @tc.name: CooperateFreeTest014
 * @tc.desc: Test OnEnterState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);
    stateFree.OnEnterState(cooperateContext);
}

/**
 * @tc.name: CooperateFreeTest015
 * @tc.desc: Test OnLeaveState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);
    stateFree.OnLeaveState(cooperateContext);
}

/**
 * @tc.name: CooperateFreeTest016
 * @tc.desc: Test GetDeviceManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest016, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(env, nullptr);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
