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
#include "input_device_mgr_test.h"

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
#include "input_device_mgr.h"
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

void InputDeviceMgrTest::NotifyCooperate()
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

void InputDeviceMgrTest::CheckInHot()
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

void InputDeviceMgrTest::SetUpTestCase() {}

void InputDeviceMgrTest::SetUp()
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

void InputDeviceMgrTest::TearDown()
{
    g_context = nullptr;
    g_contextOne = nullptr;
    g_session = nullptr;
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void InputDeviceMgrTest::OnThreeStates(const CooperateEvent &event)
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
 * @tc.name: inputDevcieMgr_test001
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, inputDevcieMgr_test001, TestSize.Level1)
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
 * @tc.name: inputDevcieMgr_test002
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, inputDevcieMgr_test002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusSyncInputDevice dSoftbusSyncInputDevice {};
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.OnRemoteInputDevice(dSoftbusSyncInputDevice));
    DSoftbusHotPlugEvent dSoftbusHotPlugEvent {};
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.OnRemoteHotPlug(dSoftbusHotPlugEvent));
}

/**
 * @tc.name: inputDevcieMgr_test003
 * @tc.desc: Test cooperate plugin HandleRemoteHotPlug
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, inputDevcieMgr_test003, TestSize.Level1)
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
 * @tc.name: inputDevcieMgr_test004
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, inputDevcieMgr_test004, TestSize.Level1)
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
 * @tc.name: inputDevcieMgr_test005
 * @tc.desc: Test cooperate plugin HandleRemoteHotPlug
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, inputDevcieMgr_test005, TestSize.Level1)
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
 * @tc.name: inputDevcieMgr_test006
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, inputDevcieMgr_test006, TestSize.Level1)
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
 * @tc.name: inputDevcieMgr_test007
 * @tc.desc: Test cooperate plugin GetRemoteDeviceById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, inputDevcieMgr_test007, TestSize.Level1)
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
 * @tc.name: inputDevcieMgr_test008
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, inputDevcieMgr_test008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    std::string TEST_DEV_NODE { "/dev/input/TestDeviceNode" };
    env->devMgr_.AddDevice(TEST_DEV_NODE);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.NotifyInputDeviceToRemote(REMOTE_NETWORKID));
}

/**
 * @tc.name: inputDevcieMgr_test009
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, inputDevcieMgr_test009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceStatus::InputHotplugEvent inputHotplugEvent;
    inputHotplugEvent.isKeyboard = true;
    inputHotplugEvent.deviceId = 1;
    inputHotplugEvent.type = InputHotplugType::UNPLUG;
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.BroadcastHotPlugToRemote(inputHotplugEvent));
}

/**
 * @tc.name: inputDevcieMgr_test010
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, inputDevcieMgr_test010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceStatus::InputHotplugEvent inputHotplugEvent;
    inputHotplugEvent.isKeyboard = true;
    inputHotplugEvent.deviceId = 1;
    inputHotplugEvent.type = InputHotplugType::PLUG;
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.BroadcastHotPlugToRemote(inputHotplugEvent));
}

/**
 * @tc.name: stateMachine_test011
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceMgrTest, stateMachine_test011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_context->inputDevMgr_.enable_ = true;
    auto [sender, receiver] = Channel<CooperateEvent>::OpenChannel();
    g_context->AttachSender(sender);
    ASSERT_NO_FATAL_FAILURE(g_context->inputDevMgr_.Enable(sender));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS