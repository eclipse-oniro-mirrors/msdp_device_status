/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <future>
#include <optional>

#include <unistd.h>
#include <utility>

#include <gtest/gtest.h>

#include "cooperate_client.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "i_hotarea_listener.h"
#include "i_event_listener.h"


#undef LOG_TAG
#define LOG_TAG "CooperateClientTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace testing;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string SYSTEM_BASIC { "system_basic" };
#ifdef OHOS_BUILD_ENABLE_COORDINATION
int32_t PERMISSION_EXCEPTION { 201 };
#endif // OHOS_BUILD_ENABLE_COORDINATION
} // namespace

class CooperateClientTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void CooperateClientTest::SetUpTestCase() {}

void CooperateClientTest::TearDownTestCase() {}

void CooperateClientTest::SetUp() {}

void CooperateClientTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

class CoordinationListenerTest : public ICoordinationListener {
public:
    CoordinationListenerTest() : ICoordinationListener() {}
    void OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg) override
    {
        FI_HILOGD("Register coordination listener test");
        (void) networkId;
    };
};

class TestEventListener final : public IEventListener {
public:
    TestEventListener() : IEventListener() {};
    ~TestEventListener() = default;

    void OnMouseLocationEvent(const std::string &networkId, const Event &event) override
    {
        (void) networkId;
        (void) event;
    };
};

class TestHotAreaListener final : public IHotAreaListener {
public:
    TestHotAreaListener() : IHotAreaListener() {};
    ~TestHotAreaListener() = default;

    void OnHotAreaMessage(int32_t displayX, int32_t displayY, HotAreaType msg, bool isEdge) override
    {
        return;
    };
};

class StreamClientTest : public StreamClient {
public:
    StreamClientTest() = default;
    void Stop() override
    {}
    int32_t Socket() override
    {
        return RET_ERR;
    }
};

#ifdef OHOS_BUILD_ENABLE_COORDINATION
/**
 * @tc.name: CooperateClientTest_RegisterListener
 * @tc.desc: On Coordination Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_RegisterListener, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCheckPermission = true;
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.RegisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
    ret = cooperateClient.UnregisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    cooperateClient.isListeningProcess_ = true;
    ret = cooperateClient.RegisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    cooperateClient.isListeningProcess_ = false;
    ret = cooperateClient.RegisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, RET_ERR);
    ret = cooperateClient.UnregisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_UnregisterListener
 * @tc.desc: On Coordination Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_UnregisterListener, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isCheckPermission = true;
    CooperateClient cooperateClient;
    std::shared_ptr<CoordinationListenerTest> consumer = nullptr;
    cooperateClient.isListeningProcess_ = true;
    int32_t ret = cooperateClient.UnregisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
    cooperateClient.isListeningProcess_ = false;
    ret = cooperateClient.UnregisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    consumer = std::make_shared<CoordinationListenerTest>();
    ret = cooperateClient.UnregisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    cooperateClient.isListeningProcess_ = true;
    ret = cooperateClient.RegisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    std::shared_ptr<CoordinationListenerTest> consumer1 = std::make_shared<CoordinationListenerTest>();
    ret = cooperateClient.RegisterListener(consumer1, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    ret = cooperateClient.UnregisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    ret = cooperateClient.RegisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    cooperateClient.isListeningProcess_ = false;
    ret = cooperateClient.UnregisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_Enable_001
 * @tc.desc: Enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_Enable_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    bool isCheckPermission = true;
    CooperateClient::CooperateMessageCallback callback;
    int32_t ret = cooperateClient.Enable(callback, isCheckPermission);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: CooperateClientTest_Disable_001
 * @tc.desc: Disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_Disable_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    bool isCheckPermission = true;
    CooperateClient::CooperateMessageCallback callback;
    int32_t ret = cooperateClient.Disable(callback, isCheckPermission);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: CooperateClientTest_Start_001
 * @tc.desc: Start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_Start_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    std::string remoteNetworkId = "networkid";
    int32_t startDeviceId = 0;
    bool isCheckPermission = true;
    CooperateClient::CooperateMessageCallback callback;
    int32_t ret = cooperateClient.Start(remoteNetworkId, startDeviceId, callback, isCheckPermission);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: CooperateClientTest_Start_001
 * @tc.desc: Start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_StartWithOptions_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    std::string remoteNetworkId = "networkid";
    int32_t startDeviceId = 0;
    CooperateOptions options {
            .displayX = 500,
            .displayY = 500,
            .displayId = 1
    };
    CooperateClient::CooperateMessageCallback callback;
    int32_t ret = cooperateClient.StartWithOptions(remoteNetworkId, startDeviceId, callback, options);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: CooperateClientTest_Stop_001
 * @tc.desc: Stop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_Stop_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    std::string remoteNetworkId = "networkid";
    bool isUnchained = true;
    bool isCheckPermission = true;
    CooperateClient::CooperateMessageCallback callback;
    int32_t ret = cooperateClient.Stop(isUnchained, callback, isCheckPermission);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: CooperateClientTest_GetCooperateState_001
 * @tc.desc: GetCooperateState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_GetCooperateState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    std::string networkId = "networkid";
    bool isCheckPermission = true;
    CooperateClient::CooperateStateCallback callback;
    int32_t ret = cooperateClient.GetCooperateState(networkId, callback, isCheckPermission);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: CooperateClientTest_GetCooperateState_002
 * @tc.desc: GetCooperateState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_GetCooperateState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    std::string udid = "udid";
    bool state = true;
    int32_t ret = cooperateClient.GetCooperateState(udid, state);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientTest_RegisterEventListener_001
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_RegisterEventListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestEventListener> listenerPtr = std::make_shared<TestEventListener>();
    CooperateClient cooperateClient;
    std::string networkId = "networkId";
    int32_t ret = cooperateClient.RegisterEventListener(networkId, listenerPtr);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
    ret = cooperateClient.RegisterEventListener(networkId, listenerPtr);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
    networkId = "networkId2";
    ret = cooperateClient.RegisterEventListener(networkId, listenerPtr);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: CooperateClientTest_UnregisterEventListener_001
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_UnregisterEventListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestEventListener> listenerPtr = std::make_shared<TestEventListener>();
    CooperateClient cooperateClient;
    std::string networkId = "networkId";
    int32_t ret = cooperateClient.UnregisterEventListener(networkId, listenerPtr);
    ASSERT_EQ(ret, RET_ERR);
    ret = cooperateClient.RegisterEventListener(networkId, listenerPtr);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
    ret = cooperateClient.UnregisterEventListener(networkId, listenerPtr);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientTest_SetDamplingCoefficient_002
 * @tc.desc: GetCooperateState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_SetDamplingCoefficient_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    uint32_t direction = 0;
    double coefficient = 0;
    int32_t ret = cooperateClient.SetDamplingCoefficient(direction, coefficient);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
}

/**
 * @tc.name: CooperateClientTest_AddHotAreaListener_001
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_AddHotAreaListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestHotAreaListener> listenerPtr = std::make_shared<TestHotAreaListener>();
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.RemoveHotAreaListener(listenerPtr);
    ASSERT_EQ(ret, RET_ERR);
    ret = cooperateClient.AddHotAreaListener(listenerPtr);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
    ret = cooperateClient.RemoveHotAreaListener(listenerPtr);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientTest_GenerateRequestID_001
 * @tc.desc: GetCooperateState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_GenerateRequestID_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.GenerateRequestID();
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_OnCoordinationListener_001
 * @tc.desc: OnCoordinationListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnCoordinationListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    std::string networkId = "networkId";
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    int32_t userData = 0;
    int32_t nType = 0;
    pkt << userData << networkId << nType;
    StreamClientTest client;
    int32_t ret = cooperateClient.OnCoordinationListener(client, pkt);
    ASSERT_EQ(ret, RET_OK);
}
/**
 * @tc.name: CooperateClientTest_OnMouseLocationListener_001
 * @tc.desc: OnMouseLocationListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnMouseLocationListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    Event event;
    std::string networkId = "networkId";
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << networkId << event.displayX << event.displayY << event.displayWidth << event.displayHeight;
    StreamClientTest client;
    int32_t ret = cooperateClient.OnMouseLocationListener(client, pkt);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_OnMouseLocationListener_002
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnMouseLocationListener_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCheckPermission = true;
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.RegisterListener(consumer, isCheckPermission);
    ASSERT_EQ(ret, PERMISSION_EXCEPTION);
    std::string networkId = "networkId";
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    StreamClientTest client;
    ret = cooperateClient.OnMouseLocationListener(client, pkt);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientTest_OnCoordinationMessage_01
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnCoordinationMessage_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientTest client;
    int32_t userData = 1;
    std::string networkId = "networkId";
    int32_t nType = static_cast<int32_t>(CoordinationMessage::ACTIVATE_SUCCESS);
    int32_t errCode = 0;
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << userData << networkId << nType << errCode;
    int32_t ret = cooperateClient.OnCoordinationMessage(client, pkt);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_DumpPerformanceInfo_01
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_DumpPerformanceInfo_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
#ifdef ENABLE_PERFORMANCE_CHECK
    CooperateClient cooperateClient;
    int32_t COOPERATENUM { 100 };
    for (int32_t  userData = 0; userData < COOPERATENUM; userData++) {
        cooperateClient.StartTrace(userData);
        cooperateClient.FinishTrace(userData, CoordinationMessage::ACTIVATE_SUCCESS);
        userData++;
        cooperateClient.StartTrace(userData);
        cooperateClient.FinishTrace(userData, CoordinationMessage::ACTIVATE_FAIL);
    }
    int32_t ret = cooperateClient.GetFirstSuccessIndex();
    ASSERT_NE(ret, INVALID_INDEX);
    cooperateClient.DumpPerformanceInfo();
#endif // ENABLE_PERFORMANCE_CHECK
}
#endif // OHOS_BUILD_ENABLE_COORDINATION
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
