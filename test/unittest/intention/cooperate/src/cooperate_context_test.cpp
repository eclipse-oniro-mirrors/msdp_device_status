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
#include "cooperate_context_test.h"

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
std::shared_ptr<Context> g_context { nullptr };
std::shared_ptr<HotplugObserver> g_observer { nullptr };
ContextService *g_instance = nullptr;
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

void CooperateContextTest::SetUpTestCase() {}

void CooperateContextTest::SetUp()
{
    g_ddm = std::make_unique<DDMAdapter>();
    g_input = std::make_unique<InputAdapter>();
    g_dsoftbus = std::make_unique<DSoftbusAdapter>();
    auto env = ContextService::GetInstance();
    g_context = std::make_shared<Context>(env);
}

void CooperateContextTest::TearDown()
{
    g_context = nullptr;
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
 * @tc.name: CooperateContextTest1
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest001, TestSize.Level1)
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
 * @tc.name: CooperateContextTest2
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest002, TestSize.Level1)
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
 * @tc.name: CooperateContextTest003
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest003, TestSize.Level1)
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

/**
 * @tc.name: CooperateContextTest4
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    g_context->EnableDDM();
    g_context->boardObserver_->OnBoardOnline("test");
    g_context->boardObserver_->OnBoardOffline("test");
    ASSERT_NO_FATAL_FAILURE(g_context->DisableDDM());
}

/**
 * @tc.name: CooperateContextTest5
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest005, TestSize.Level1)
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
 * @tc.name: CooperateContextTest6
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = g_context->EnableDevMgr();
    EXPECT_EQ(ret, RET_OK);
    g_context->DisableDevMgr();
    g_context->NormalizedCursorPosition();
}

/**
 * @tc.name: CooperateContextTest7
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest007, TestSize.Level1)
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
 * @tc.name: CooperateContextTest8
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest008, TestSize.Level1)
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
 * @tc.name: CooperateContextTest009
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    auto dev = g_devMgr.AddDevice(TEST_DEV_NODE);
    EXPECT_EQ(dev, nullptr);
    g_observer->OnDeviceRemoved(dev);
}

/**
 * @tc.name: CooperateContextTest010
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest010, TestSize.Level1)
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
 * @tc.name: CooperateContextTest012
 * @tc.desc: Test cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DSoftbusCooperateWithOptionsFinished result {
        .success = false,
        .errCode = static_cast<int32_t>(CoordinationErrCode::UNEXPECTED_START_CALL)
    };
    ASSERT_NO_FATAL_FAILURE(g_context->OnRemoteStart(result));
}

/**
 * @tc.name: CooperateContextTest13
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest013, TestSize.Level1)
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
        .uid = 20020135,
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
        .targetNetworkId = "test1",
        .uid = 20020135,
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
 * @tc.name: CooperateContextTest14
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateContextTest, CooperateContextTest014, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<ICooperateObserver> observer = std::make_shared<CooperateObserver>();
    g_context->AddObserver(observer);
    EnableCooperateEvent enableCooperateEvent{1, 1, 1};
    RegisterListenerEvent registerListenerEvent{IPCSkeleton::GetCallingPid(), 1};
    g_context->EnableCooperate(enableCooperateEvent);
    g_context->DisableCooperate(registerListenerEvent);
    StartCooperateEvent event {IPCSkeleton::GetCallingPid(), 1, "test", 1,
        std::make_shared<std::promise<int32_t>>(), 20020135,
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
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS