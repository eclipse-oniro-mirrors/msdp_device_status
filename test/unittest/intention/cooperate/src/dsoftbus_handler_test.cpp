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
#include "dsoftbus_handler_test.h"

#include "cooperate_context.h"
#include "cooperate_free.h"
#include "cooperate_in.h"
#include "cooperate_out.h"
#include "ddm_adapter.h"
#include "device.h"
#include "dsoftbus_adapter.h"
#include "dsoftbus_handler.h"
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

void DsoftbusHanderTest::NotifyCooperate()
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

void DsoftbusHanderTest::CheckInHot()
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

void DsoftbusHanderTest::SetUpTestCase() {}

void DsoftbusHanderTest::SetUp()
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

void DsoftbusHanderTest::TearDown()
{
    g_context = nullptr;
    g_contextOne = nullptr;
    g_session = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void DsoftbusHanderTest::OnThreeStates(const CooperateEvent &event)
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
 * @tc.name: DsoftbusHanderTest001
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest001, TestSize.Level1)
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
 * @tc.name: DsoftbusHanderTest002
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.StartCooperate("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DsoftbusHanderTest003
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.StopCooperate("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DsoftbusHanderTest004
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.ComeBack("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DsoftbusHanderTest005
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.RelayCooperate("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DsoftbusHanderTest006
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_context->dsoftbus_.GetLocalNetworkId();
    g_context->dsoftbus_.OnBind("test");
    g_context->dsoftbus_.OnShutdown("test");
    int32_t ret = g_context->dsoftbus_.RelayCooperateFinish("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DsoftbusHanderTest007
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest007, TestSize.Level1)
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
 * @tc.name: DsoftbusHanderTest008
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    ASSERT_NO_FATAL_FAILURE(g_context->dsoftbus_.OnConnected(localNetworkId));
}

/**
 * @tc.name: DsoftbusHanderTest009
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MessageId::DSOFTBUS_START_COOPERATE);
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    ASSERT_NO_FATAL_FAILURE(g_context->dsoftbus_.OnRemoteInputDevice(localNetworkId, pkt));
}

/**
 * @tc.name: DsoftbusHanderTest010
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MessageId::DSOFTBUS_START_COOPERATE);
    int32_t testData = 10;
    pkt << testData;
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    ASSERT_NO_FATAL_FAILURE(g_context->dsoftbus_.OnRemoteInputDevice(localNetworkId, pkt));
}

/**
 * @tc.name: DsoftbusHanderTest011
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MessageId::DSOFTBUS_START_COOPERATE);
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    ASSERT_NO_FATAL_FAILURE(g_context->dsoftbus_.OnRemoteHotPlug(localNetworkId, pkt));
}

/**
 * @tc.name: DsoftbusHanderTest012
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MessageId::DSOFTBUS_START_COOPERATE);
    std::string localNetworkId = g_context->dsoftbus_.GetLocalNetworkId();
    ASSERT_NO_FATAL_FAILURE(g_context->dsoftbus_.OnRemoteHotPlug(localNetworkId, pkt));
}

/**
 * @tc.name: DsoftbusHanderTest013
 * @tc.name: StateMachineTest_ResetCooperate
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest013, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.StartCooperateWithOptions("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DsoftbusHanderTest014
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.ComeBackWithOptions("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DsoftbusHanderTest015
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest015, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->dsoftbus_.RelayCooperateWithOptions("test", {});
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DsoftbusHanderTest016
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest016, TestSize.Level1)
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
 * @tc.name: DsoftbusHanderTest017
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DsoftbusHanderTest, DsoftbusHanderTest017, TestSize.Level1)
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
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS