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
#include "state_machine_test.h"

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

MMI::PointerEvent::PointerItem StateMachineTest::CreatePointerItem(int32_t pointerId, int32_t deviceId,
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

void StateMachineTest::NotifyCooperate()
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

void StateMachineTest::CheckInHot()
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

void StateMachineTest::SetUpTestCase() {}

void StateMachineTest::SetUp()
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

void StateMachineTest::TearDown()
{
    g_context = nullptr;
    g_contextOne = nullptr;
    g_session = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void StateMachineTest::OnThreeStates(const CooperateEvent &event)
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
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent001, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent002, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent003, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent004, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent005, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent006, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent007, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent008, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent009, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent010, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent011, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent012, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent013, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent014, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent015, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent016, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent017, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent018, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent019, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent020, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent021, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent022, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent023, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent024, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent025, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent026, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent027, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent028, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent029, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent030, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent031, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent032, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent033, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent034, TestSize.Level1)
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
 * @tc.desc: Test OnQuit in the StateMachine class
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent035, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent036, TestSize.Level1)
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent037, TestSize.Level1)
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
 * @tc.name: stateMachine_test067
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StateMachineTest, stateMachine_test067, TestSize.Level1)
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
HWTEST_F(StateMachineTest, stateMachine_test068, TestSize.Level1)
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
HWTEST_F(StateMachineTest, stateMachine_test069, TestSize.Level1)
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
HWTEST_F(StateMachineTest, stateMachine_test070, TestSize.Level1)
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
HWTEST_F(StateMachineTest, stateMachine_test071, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    std::string commonEvent = "-1";
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnCommonEvent(cooperateContext, commonEvent));
}
/**
 * @tc.name: stateMachine_test078
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StateMachineTest, stateMachine_test078, TestSize.Level1)
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
HWTEST_F(StateMachineTest, stateMachine_test079, TestSize.Level1)
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
HWTEST_F(StateMachineTest, stateMachine_test080, TestSize.Level1)
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
 * @tc.name: stateMachine_test098
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StateMachineTest, stateMachine_test098, TestSize.Level0)
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
HWTEST_F(StateMachineTest, stateMachine_test099, TestSize.Level0)
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
 * @tc.name: stateMachine_test100
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StateMachineTest, stateMachine_test100, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    CooperateEvent startEvent (
        CooperateEventType::DSOFTBUS_START_COOPERATE,
        DSoftbusStartCooperate {
            .networkId = LOCAL_NETWORKID,
            .uid = 20020135,
    });
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnRemoteStart(cooperateContext, startEvent));
}

/**
 * @tc.name: stateMachine_test101
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StateMachineTest, stateMachine_test101, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    Context cooperateContext(env);
    cooperateContext.remoteNetworkId_ = REMOTE_NETWORKID;
    CooperateEvent startEvent (
        CooperateEventType::DSOFTBUS_START_COOPERATE,
        DSoftbusStartCooperate {
            .networkId = LOCAL_NETWORKID,
            .uid = 20020135,
    });
    g_stateMachine->isCooperateEnable_ = true;
    ASSERT_NO_FATAL_FAILURE(g_stateMachine->OnRemoteStart(cooperateContext, startEvent));
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent038, TestSize.Level1)
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
        .uid = 20020135,
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
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent039, TestSize.Level1)
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
        .uid = 20020135,
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
        .uid = 20020135,
    });
    CooperateEvent stopRemoteEvent = stopEvent;
    g_stateMachine->current_ = CooperateState::COOPERATE_STATE_OUT;
    g_stateMachine->OnEvent(cooperateContext, startRemoteEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    g_stateMachine->OnEvent(cooperateContext, stopRemoteEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    EXPECT_FALSE(g_context->mouseLocation_.HasLocalListener());
}

/**
 * @tc.name: StateMachineTest_OnEvent
 * @tc.desc: Test OnReset interface
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(StateMachineTest, StateMachineTest_OnEvent040, TestSize.Level1)
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
        .uid = 20020135,
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
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
