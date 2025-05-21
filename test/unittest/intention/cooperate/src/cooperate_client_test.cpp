/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>

#include "cooperate_client_test_mock.h"
#define private public
#include "cooperate_client.h"
#undef private
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "i_hotarea_listener.h"
#include "i_event_listener.h"
#include "tunnel_client.h"

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
    bool isCompatible = true;
    TunnelClient tunnel;
    CooperateClient cooperateClient;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(cooperateClientMock, RemoveWatch).WillRepeatedly(Return(RET_OK));
    ret = cooperateClient.UnregisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    cooperateClient.isListeningProcess_ = true;
    ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_ERR);
    ret = cooperateClient.UnregisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    cooperateClient.isListeningProcess_ = false;
    EXPECT_CALL(cooperateClientMock, AddWatch).WillOnce(Return(RET_ERR));
    ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_ERR);
    ret = cooperateClient.UnregisterListener(tunnel, consumer, isCompatible);
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
    bool isCompatible = true;
    TunnelClient tunnel;
    CooperateClient cooperateClient;
    std::shared_ptr<CoordinationListenerTest> consumer = nullptr;
    cooperateClient.isListeningProcess_ = true;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, RemoveWatch).WillOnce(Return(RET_ERR));
    int32_t ret = cooperateClient.UnregisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_ERR);
    cooperateClient.isListeningProcess_ = false;
    ret = cooperateClient.UnregisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    consumer = std::make_shared<CoordinationListenerTest>();
    ret = cooperateClient.UnregisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    cooperateClient.isListeningProcess_ = true;
    ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    std::shared_ptr<CoordinationListenerTest> consumer1 = std::make_shared<CoordinationListenerTest>();
    ret = cooperateClient.RegisterListener(tunnel, consumer1, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    ret = cooperateClient.UnregisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    cooperateClient.isListeningProcess_ = false;
    ret = cooperateClient.UnregisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_errbranch
 * @tc.desc: On Coordination Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_errbranch, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isCheckPermission = true;
    TunnelClient tunnel;
    CooperateClient::CooperateMessageCallback callback;
    CooperateClient cooperateClient;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, Enable).WillOnce(Return(RET_ERR));
    int32_t ret = cooperateClient.Enable(tunnel, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_ERR);
    EXPECT_CALL(cooperateClientMock, Disable).WillOnce(Return(RET_ERR));
    ret = cooperateClient.Disable(tunnel, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_ERR);
    EXPECT_CALL(cooperateClientMock, Start).WillOnce(Return(RET_ERR));
    ret = cooperateClient.Start(tunnel, "test", 1, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_ERR);
    EXPECT_CALL(cooperateClientMock, Stop).WillOnce(Return(RET_ERR));
    ret = cooperateClient.Stop(tunnel, true, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientTest_OnCoordinationListener_001
 * @tc.desc: On Coordination Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnCoordinationListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    TunnelClient tunnel;
    CooperateClient cooperateClient;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    StreamClientTest client;
    int32_t userData = 0;
    std::string networkId = "networkId";
    CoordinationMessage msg = CoordinationMessage::ACTIVATE_SUCCESS;
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << userData << networkId << static_cast<int32_t>(msg);
    ret = cooperateClient.OnCoordinationListener(client, pkt);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_OnCoordinationListener_002
 * @tc.desc: On Coordination Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnCoordinationListener_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    TunnelClient tunnel;
    CooperateClient cooperateClient;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    StreamClientTest client;
    CoordinationMessage msg = CoordinationMessage::ACTIVATE_SUCCESS;
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << static_cast<int32_t>(msg);
    ret = cooperateClient.OnCoordinationListener(client, pkt);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientTest_OnMouseLocationListener_001
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnMouseLocationListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<CoordinationListenerTest> consumer =
        std::make_shared<CoordinationListenerTest>();
    bool isCompatible = true;
    TunnelClient tunnel;
    CooperateClient cooperateClient;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    Event event;
    std::string networkId = "networkId";
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << networkId << event.displayX << event.displayY << event.displayWidth << event.displayHeight;
    StreamClientTest client;
    ret = cooperateClient.OnMouseLocationListener(client, pkt);
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
    bool isCompatible = true;
    TunnelClient tunnel;
    CooperateClient cooperateClient;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, AddWatch).WillRepeatedly(Return(RET_OK));
    int32_t ret = cooperateClient.RegisterListener(tunnel, consumer, isCompatible);
    ASSERT_EQ(ret, RET_OK);
    std::string networkId = "networkId";
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    StreamClientTest client;
    ret = cooperateClient.OnMouseLocationListener(client, pkt);
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
    TunnelClient tunnel;
    CooperateClient cooperateClient;
    std::string networkId = "networkId";
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.RegisterEventListener(tunnel, networkId, listenerPtr);
    ASSERT_EQ(ret, RET_OK);
    ret = cooperateClient.RegisterEventListener(tunnel, networkId, listenerPtr);
    ASSERT_EQ(ret, RET_ERR);
    networkId = "networkId2";
    EXPECT_CALL(cooperateClientMock, AddWatch).WillOnce(Return(RET_ERR));
    ret = cooperateClient.RegisterEventListener(tunnel, networkId, listenerPtr);
    ASSERT_EQ(ret, RET_ERR);
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
    TunnelClient tunnel;
    CooperateClient cooperateClient;
    std::string networkId = "networkId";
    int32_t ret = cooperateClient.UnregisterEventListener(tunnel, networkId, listenerPtr);
    ASSERT_EQ(ret, RET_ERR);
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, AddWatch).WillOnce(Return(RET_OK));
    ret = cooperateClient.RegisterEventListener(tunnel, networkId, listenerPtr);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(cooperateClientMock, RemoveWatch).WillOnce(Return(RET_OK));
    ret = cooperateClient.UnregisterEventListener(tunnel, networkId, listenerPtr);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_UnregisterEventListener_002
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_UnregisterEventListener_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestEventListener> listenerPtr = std::make_shared<TestEventListener>();
    TunnelClient tunnel;
    CooperateClient cooperateClient;
    std::string networkId = "networkId";
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, AddWatch).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.RegisterEventListener(tunnel, networkId, listenerPtr);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(cooperateClientMock, RemoveWatch).WillOnce(Return(RET_ERR));
    ret = cooperateClient.UnregisterEventListener(tunnel, networkId, listenerPtr);
    ASSERT_EQ(ret, RET_ERR);
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
    TunnelClient tunnel;
    CooperateClient cooperateClient;
    int32_t ret = cooperateClient.RemoveHotAreaListener(tunnel, listenerPtr);
    ASSERT_EQ(ret, RET_ERR);
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, AddWatch).WillOnce(Return(RET_OK));
    ret = cooperateClient.AddHotAreaListener(tunnel, listenerPtr);
    ASSERT_EQ(ret, RET_OK);
    ret = cooperateClient.AddHotAreaListener(tunnel, listenerPtr);
    ASSERT_EQ(ret, RET_ERR);
    EXPECT_CALL(cooperateClientMock, RemoveWatch).WillOnce(Return(RET_ERR));
    ret = cooperateClient.RemoveHotAreaListener(tunnel, listenerPtr);
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
    TunnelClient tunnel;
    bool isCheckPermission = true;
    CooperateClient::CooperateMessageCallback callback;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, Start).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.Start(tunnel, "test", 1, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    StreamClientTest client;
    int32_t userData = 1;
    std::string networkId = "networkId";
    int32_t nType = static_cast<int32_t>(CoordinationMessage::ACTIVATE_SUCCESS);
    int32_t errCode = 0;
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << userData << networkId << nType << errCode;
    ret = cooperateClient.OnCoordinationMessage(client, pkt);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(cooperateClientMock, Stop).WillOnce(Return(RET_OK));
    ret = cooperateClient.Stop(tunnel, true, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(cooperateClientMock, Disable).WillOnce(Return(RET_OK));
    ret = cooperateClient.Disable(tunnel, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_OnCoordinationMessage_02
 * @tc.desc: On Hot Area Listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_OnCoordinationMessage_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    TunnelClient tunnel;
    bool isCheckPermission = true;
    CooperateClient::CooperateMessageCallback callback;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, Start).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.Start(tunnel, "test", 1, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    StreamClientTest client;
    int32_t userData = 0;
    std::string networkId = "networkId";
    int32_t nType = static_cast<int32_t>(CoordinationMessage::ACTIVATE_SUCCESS);
    int32_t errCode = 0;
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << userData << networkId << nType << errCode;
    ret = cooperateClient.OnCoordinationMessage(client, pkt);
    ASSERT_EQ(ret, RET_OK);
    nType = static_cast<int32_t>(CoordinationMessage::ACTIVATE_FAIL);
    userData = 1;
    pkt << userData << networkId << nType << errCode;
    ret = cooperateClient.OnCoordinationMessage(client, pkt);
    EXPECT_CALL(cooperateClientMock, Disable).WillOnce(Return(RET_OK));
    ret = cooperateClient.Disable(tunnel, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_Enable
 * @tc.desc: On Coordination Enable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_enable, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isCheckPermission = true;
    TunnelClient tunnel;
    CooperateClient::CooperateMessageCallback callback;
    CooperateClient cooperateClient;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, Enable).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.Enable(tunnel, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(cooperateClientMock, Disable).WillOnce(Return(RET_OK));
    ret = cooperateClient.Disable(tunnel, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_GetCooperateState_01
 * @tc.desc: On Coordination GetCooperateState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_GetCooperateState_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isCheckPermission = true;
    TunnelClient tunnel;
    std::string networkId("softbus");
    CooperateClient::CooperateStateCallback callback;
    CooperateClient::CooperateMessageCallback callback1;
    CooperateClient cooperateClient;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, GetParam).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.GetCooperateState(tunnel, networkId, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(cooperateClientMock, Disable).WillOnce(Return(RET_OK));
    ret = cooperateClient.Disable(tunnel, callback1, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_GetCooperateState_02
 * @tc.desc: On Coordination GetCooperateState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_GetCooperateState_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isCheckPermission = true;
    CooperateClient::CooperateMessageCallback callback;
    bool state = true;
    TunnelClient tunnel;
    std::string udId ("softbus");
    CooperateClient cooperateClient;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, GetParam).WillOnce(Return(RET_OK));
    int32_t ret = cooperateClient.GetCooperateState(tunnel, udId, state);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(cooperateClientMock, Disable).WillOnce(Return(RET_OK));
    ret = cooperateClient.Disable(tunnel, callback, isCheckPermission);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientTest_GetCooperateState_03
 * @tc.desc: On Coordination GetCooperateState error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientTest, CooperateClientTest_GetCooperateState_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isCheckPermission = true;
    std::string networkId("softbus");
    CooperateClient::CooperateMessageCallback callback;
    CooperateClient::CooperateStateCallback callback1;
    bool state = true;
    TunnelClient tunnel;
    std::string udId ("softbus");
    CooperateClient cooperateClient;
    NiceMock<CooperateClientMock> cooperateClientMock;
    EXPECT_CALL(cooperateClientMock, GetParam).WillOnce(Return(RET_ERR));
    int32_t ret = cooperateClient.GetCooperateState(tunnel, udId, state);
    ASSERT_EQ(ret, RET_ERR);
    EXPECT_CALL(cooperateClientMock, GetParam).WillOnce(Return(RET_ERR));
    ret = cooperateClient.GetCooperateState(tunnel, networkId, callback1, isCheckPermission);
    ASSERT_EQ(ret, RET_ERR);
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
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
