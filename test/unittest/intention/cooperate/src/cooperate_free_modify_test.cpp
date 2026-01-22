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
 * @tc.name: CooperateFreeTest_SetPointerVisible_001
 * @tc.desc: Test SetPointerVisible function with visible pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_SetPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);

    stateFree.SetPointerVisible(cooperateContext);

    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest_OnStart_001
 * @tc.desc: Test OnStart function with normal start event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_OnStart_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::START,
        StartCooperateEvent {
            .pid = IPCSkeleton::GetCallingPid(),
            .userData = 1,
            .remoteNetworkId = REMOTE_NETWORKID,
            .startDeviceId = 1,
            .errCode = std::make_shared<std::promise<int32_t>>(),
            .uid = 20020135,
        });
    
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);

    cooperateContext.StartCooperate(std::get<StartCooperateEvent>(event.event));
    
    stateFree.initial_->OnStart(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest_OnStart_002
 * @tc.desc: Test OnStart function when drag state is MOTION_DRAGGING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_OnStart_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::START,
        StartCooperateEvent {
            .pid = IPCSkeleton::GetCallingPid(),
            .userData = 2,
            .remoteNetworkId = REMOTE_NETWORKID,
            .startDeviceId = 2,
            .errCode = std::make_shared<std::promise<int32_t>>(),
            .uid = 20020136,
        });
    
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);

    cooperateContext.StartCooperate(std::get<StartCooperateEvent>(event.event));

    g_dragMgr.SetDragState(DragState::MOTION_DRAGGING);
    
    stateFree.initial_->OnStart(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest_InitiatorPointerVisible_001
 * @tc.desc: Test InitiatorPointerVisible function with visible true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_InitiatorPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);

    stateFree.initial_->InitiatorPointerVisible(true);

    stateFree.initial_->InitiatorPointerVisible(false);

    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest_OnStartWithOptions_001
 * @tc.desc: Test OnStartWithOptions function with normal options
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_OnStartWithOptions_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::WITH_OPTIONS_START,
        StartWithOptionsEvent {
            .pid = IPCSkeleton::GetCallingPid(),
            .userData = 3,
            .remoteNetworkId = REMOTE_NETWORKID,
            .displayX = 100,
            .displayY = 200,
            .displayId = 1,
            .errCode = std::make_shared<std::promise<int32_t>>(),
        });
    
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);
    
    cooperateContext.StartCooperateWithOptions(std::get<StartWithOptionsEvent>(event.event));
    
    stateFree.initial_->OnStartWithOptions(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest_OnDisable_001
 * @tc.desc: Test OnDisable function when drag state is not START
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_OnDisable_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DISABLE,
        StopCooperateEvent {
            .pid = IPCSkeleton::GetCallingPid(),
            .userData = 4,
            .networkId = REMOTE_NETWORKID,
        });
    
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);

    g_dragMgr.SetDragState(DragState::MOTION_DRAGGING);
    
    stateFree.initial_->OnDisable(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest_OnDisable_002
 * @tc.desc: Test OnDisable function when drag state is START
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_OnDisable_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateEvent event(
        CooperateEventType::DISABLE,
        StopCooperateEvent {
            .pid = IPCSkeleton::GetCallingPid(),
            .userData = 5,
            .networkId = REMOTE_NETWORKID,
        });
    
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);
    
    g_dragMgr.SetDragState(DragState::START);
    
    stateFree.initial_->OnDisable(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest_OnPointerEvent_001
 * @tc.desc: Test OnPointerEvent function with pointer event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_OnPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPointerEvent pointerEvent;
    pointerEvent.deviceId = 1;
    
    CooperateEvent event(
        CooperateEventType::INPUT_POINTER_EVENT,
        pointerEvent);
    
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);

    g_dragMgr.SetDragState(DragState::MOTION_DRAGGING);
    
    stateFree.initial_->OnPointerEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest_OnPointerEvent_002
 * @tc.desc: Test OnPointerEvent function when drag state is START
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_OnPointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPointerEvent pointerEvent;
    pointerEvent.deviceId = 2;
    
    CooperateEvent event(
        CooperateEventType::INPUT_POINTER_EVENT,
        pointerEvent);
    
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);

    g_dragMgr.SetDragState(DragState::START);
    
    stateFree.initial_->OnPointerEvent(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest_OnUpdateCooperateFlag_001
 * @tc.desc: Test OnUpdateCooperateFlag function with HIDE_CURSOR flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_OnUpdateCooperateFlag_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UpdateCooperateFlagEvent flagEvent {
        .mask = COOPERATE_FLAG_HIDE_CURSOR,
    };
    
    CooperateEvent event(
        CooperateEventType::UPDATE_COOPERATE_FLAG,
        flagEvent);
    
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);
    
    stateFree.initial_->OnUpdateCooperateFlag(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CooperateFreeTest_OnUpdateCooperateFlag_002
 * @tc.desc: Test OnUpdateCooperateFlag function with FREEZE_CURSOR flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateFreeTest, CooperateFreeTest_OnUpdateCooperateFlag_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UpdateCooperateFlagEvent flagEvent {
        .mask = COOPERATE_FLAG_FREEZE_CURSOR,
    };
    
    CooperateEvent event(
        CooperateEventType::UPDATE_COOPERATE_FLAG,
        flagEvent);
    
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    
    g_stateMachine = std::make_shared<Cooperate::StateMachine>(env);
    Cooperate::CooperateFree stateFree(*g_stateMachine, env);
    ASSERT_NE(stateFree.initial_, nullptr);
    
    stateFree.initial_->OnUpdateCooperateFlag(cooperateContext, event);
    bool ret = g_context->mouseLocation_.HasLocalListener();
    EXPECT_FALSE(ret);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS