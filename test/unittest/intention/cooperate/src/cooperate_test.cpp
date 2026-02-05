/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include "cooperate_test.h"

#include "cooperate.h"
#include "ddm_adapter.h"
#include "input_adapter.h"
#include "i_cooperate.h"
#include "ipc_skeleton.h"
#include "dsoftbus_adapter.h"
#include "plugin_manager.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace Cooperate;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };

std::shared_ptr<Context> g_context { nullptr };
std::shared_ptr<Context> g_contextOne { nullptr };
std::shared_ptr<HotplugObserver> g_observer { nullptr };
std::shared_ptr<SocketSession> g_session { nullptr };
std::shared_ptr<StateMachine> g_stateMachine { nullptr };
Channel<CooperateEvent>::Sender g_sender;
} // namespace

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

void CooperateTest::SetUpTestCase() {}

void CooperateTest::SetUp()
{
    auto env = TestContext::GetInstance();
    g_cooperate = env->GetPluginManager().LoadCooperate();
}

void CooperateTest::TearDown()
{
}

void CooperateTest::TearDownTestCase()
{
    if (g_cooperate == nullptr) {
        GTEST_LOG_(INFO) << "g_cooperate is nullptr";
        return;
    }
    TestContext::GetInstance()->GetPluginManager().UnloadCooperate();
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: CooperateTest1
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateTest, CooperateTest1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    if (g_cooperate != nullptr) {
        std::shared_ptr<ICooperateObserver> observer = std::make_shared<CooperateObserver>();
        g_cooperate->AddObserver(observer);
        g_cooperate->RemoveObserver(observer);
        ret = g_cooperate->RegisterListener(IPCSkeleton::GetCallingPid());
        EXPECT_EQ(ret, RET_OK);
        ret = g_cooperate->UnregisterListener(IPCSkeleton::GetCallingPid());
        EXPECT_EQ(ret, RET_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    } else {
        GTEST_LOG_(INFO) << "The product does not intention_cooperate so";
        EXPECT_EQ(!ret, RET_OK);
    }
}

/**
 * @tc.name: CooperateTest2
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateTest, CooperateTest2, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    if (g_cooperate != nullptr) {
        int32_t ret = g_cooperate->RegisterHotAreaListener(IPCSkeleton::GetCallingPid());
        EXPECT_EQ(ret, RET_OK);
        ret = g_cooperate->UnregisterHotAreaListener(IPCSkeleton::GetCallingPid());
        EXPECT_EQ(ret, RET_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    } else {
        GTEST_LOG_(INFO) << "The product does not intention_cooperate so";
        EXPECT_EQ(!ret, RET_OK);
    }
}

/**
 * @tc.name: CooperateTest3
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateTest, CooperateTest3, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    if (g_cooperate != nullptr) {
        int32_t ret = g_cooperate->Enable(1, IPCSkeleton::GetCallingPid(), 1);
        EXPECT_EQ(ret, RET_OK);
        ret = g_cooperate->Disable(IPCSkeleton::GetCallingPid(), 1);
        EXPECT_EQ(ret, RET_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    } else {
        GTEST_LOG_(INFO) << "The product does not intention_cooperate so";
        EXPECT_EQ(!ret, RET_OK);
    }
}

/**
 * @tc.name: CooperateTest4
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateTest, CooperateTest4, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    if (g_cooperate != nullptr) {
        int32_t ret = g_cooperate->Start(IPCSkeleton::GetCallingPid(), 1, "test", 1);
        EXPECT_GE(ret, 0);
        ret = g_cooperate->Stop(IPCSkeleton::GetCallingPid(), 1, true);
        EXPECT_EQ(ret, RET_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    } else {
        GTEST_LOG_(INFO) << "The product does not intention_cooperate so";
        EXPECT_EQ(!ret, RET_OK);
    }
}

/**
 * @tc.name: CooperateTest5
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateTest, CooperateTest5, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    if (g_cooperate != nullptr) {
        int32_t ret = g_cooperate->GetCooperateState(IPCSkeleton::GetCallingPid(), 1, "test");
        EXPECT_EQ(ret, RET_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    } else {
        GTEST_LOG_(INFO) << "The product does not intention_cooperate so";
        EXPECT_EQ(!ret, RET_OK);
    }
}

/**
 * @tc.name: CooperateTest6
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateTest, CooperateTest6, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    if (g_cooperate != nullptr) {
        int32_t ret = g_cooperate->RegisterEventListener(1, "test");
        EXPECT_EQ(ret, RET_OK);
        ret = g_cooperate->UnregisterEventListener(1, "test");
        EXPECT_EQ(ret, RET_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    } else {
        GTEST_LOG_(INFO) << "The product does not intention_cooperate so";
        EXPECT_EQ(!ret, RET_OK);
    }
}

/**
 * @tc.name: CooperateTest7
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateTest, CooperateTest7, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    if (g_cooperate != nullptr) {
        g_cooperate->Dump(1);
        std::string udId { "default" };
        bool state { false };
        int32_t ret = g_cooperate->GetCooperateState(udId, state);
        EXPECT_EQ(ret, RET_OK);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    } else {
        GTEST_LOG_(INFO) << "The product does not intention_cooperate so";
        EXPECT_EQ(!ret, RET_OK);
    }
}

/**
 * @tc.name: CooperateTest8
 * @tc.desc: cooperate plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateTest, CooperateTest8, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t ret = RET_ERR;
    if (g_cooperate != nullptr) {
        CooperateOptions withOptions;
        withOptions.displayX = 500;
        withOptions.displayY = 500;
        withOptions.displayId = 1;
        int32_t pid = IPCSkeleton::GetCallingPid();
        int32_t userData = 1;
        int32_t startDeviceId = 0;
        const std::string &remoteNetworkId = "test";
        ret = g_cooperate->StartWithOptions(pid, userData, remoteNetworkId,
        startDeviceId, withOptions);
        EXPECT_EQ(ret, RET_OK);
    } else {
        GTEST_LOG_(INFO) << "The product does not intention_cooperate so";
        EXPECT_EQ(!ret, RET_OK);
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
