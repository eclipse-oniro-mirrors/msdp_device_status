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
#include <thread>
#include <set>

#include <unistd.h>
#include <utility>

#include <gtest/gtest.h>

#include "cooperate_client.h"
#include "devicestatus_define.h"
#include "devicestatus_errors.h"
#include "i_hotarea_listener.h"
#include "i_event_listener.h"

#undef LOG_TAG
#define LOG_TAG "CooperateClientModifyTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace ModifyTest {

using namespace testing::ext;
using namespace testing;

constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
const std::string SYSTEM_BASIC { "system_basic" };

class TestCoordinationListener : public ICoordinationListener {
public:
    TestCoordinationListener() : ICoordinationListener() {}
    void OnCoordinationMessage(const std::string &networkId, CoordinationMessage msg) override
    {
        FI_HILOGD("Modified coordination listener");
        (void) networkId;
        (void) msg;
    };
};

class TestEventListenerMod : public IEventListener {
public:
    TestEventListenerMod() : IEventListener() {};
    ~TestEventListenerMod() = default;

    void OnMouseLocationEvent(const std::string &networkId, const Event &event) override
    {
        (void) networkId;
        (void) event;
    };
};

class TestHotAreaListenerMod : public IHotAreaListener {
public:
    TestHotAreaListenerMod() : IHotAreaListener() {};
    ~TestHotAreaListenerMod() = default;

    void OnHotAreaMessage(int32_t displayX, int32_t displayY, HotAreaType msg, bool isEdge) override
    {
        (void) displayX;
        (void) displayY;
        (void) msg;
        (void) isEdge;
        return;
    };
};

class StreamClientModTest : public StreamClient {
public:
    StreamClientModTest() = default;
    void Stop() override {}
    int32_t Socket() override { return RET_ERR; }
};

class CooperateClientModifyTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
    }
};

/**
 * @tc.name: CooperateClientModifyTest_OnCoordinationState_001
 * @tc.desc: Test OnCoordinationState function with valid packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_OnCoordinationState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientModTest client;
    
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    
    int32_t userData = 123;
    bool state = true;
    int32_t errCode = 0;
    
    pkt << userData << state << errCode;
    
    int32_t ret = cooperateClient.OnCoordinationState(client, pkt);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientModifyTest_OnCoordinationState_002
 * @tc.desc: Test OnCoordinationState function with invalid packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_OnCoordinationState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientModTest client;
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << 123;
    int32_t ret = cooperateClient.OnCoordinationState(client, pkt);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientModifyTest_OnCoordinationState_003
 * @tc.desc: Test OnCoordinationState function with state false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_OnCoordinationState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientModTest client;
    
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    
    int32_t userData = 456;
    bool state = false;
    int32_t errCode = 0;
    
    pkt << userData << state << errCode;
    
    int32_t ret = cooperateClient.OnCoordinationState(client, pkt);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientModifyTest_OnHotAreaListener_001
 * @tc.desc: Test OnHotAreaListener function with valid packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_OnHotAreaListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientModTest client;
    
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    
    int32_t positionX = 100;
    int32_t positionY = 200;
    int32_t type = 0;
    bool isEdge = true;
    
    pkt << positionX << positionY << type << isEdge;
    
    int32_t ret = cooperateClient.OnHotAreaListener(client, pkt);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientModifyTest_OnHotAreaListener_002
 * @tc.desc: Test OnHotAreaListener function with different area types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_OnHotAreaListener_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientModTest client;
    
    std::vector<int32_t> testTypes = {0, 1, 2, 3, 4};
    for (const auto& type : testTypes) {
        MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
        NetPacket pkt(msgId);
        pkt << 100 << 200 << type << true;
        int32_t ret = cooperateClient.OnHotAreaListener(client, pkt);
        ASSERT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: CooperateClientModifyTest_OnHotAreaListener_003
 * @tc.desc: Test OnHotAreaListener function with invalid packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_OnHotAreaListener_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientModTest client;
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    pkt << 100 << 200 << 1;
    int32_t ret = cooperateClient.OnHotAreaListener(client, pkt);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientModifyTest_OnConnected_001
 * @tc.desc: Test OnConnected function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_OnConnected_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    cooperateClient.OnConnected();
    SUCCEED();
}

/**
 * @tc.name: CooperateClientModifyTest_OnDisconnected_001
 * @tc.desc: Test OnDisconnected function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_OnDisconnected_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    cooperateClient.OnDisconnected();
    SUCCEED();
}

/**
 * @tc.name: CooperateClientModifyTest_GenerateRequestID_002
 * @tc.desc: Test GenerateRequestID function sequential generation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_GenerateRequestID_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    
    int32_t id1 = cooperateClient.GenerateRequestID();
    int32_t id2 = cooperateClient.GenerateRequestID();
    int32_t id3 = cooperateClient.GenerateRequestID();
    
    ASSERT_EQ(id2, id1 + 1);
    ASSERT_EQ(id3, id2 + 1);
}

/**
 * @tc.name: CooperateClientModifyTest_EmptyCollections_001
 * @tc.desc: Test functions with empty collections
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_EmptyCollections_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    cooperateClient.OnDevCooperateListener("test", CoordinationMessage::ACTIVATE_SUCCESS);
    cooperateClient.OnDevHotAreaListener(100, 200, static_cast<HotAreaType>(0), true);
    cooperateClient.OnConnected();
    cooperateClient.OnDisconnected();
    SUCCEED();
}

/**
 * @tc.name: CooperateClientModifyTest_PerformanceFunctions_001
 * @tc.desc: Test performance-related functions when enabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_PerformanceFunctions_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
#ifdef ENABLE_PERFORMANCE_CHECK
    CooperateClient cooperateClient;
    int32_t userData = 123;
    cooperateClient.StartTrace(userData);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    cooperateClient.FinishTrace(userData, CoordinationMessage::ACTIVATE_SUCCESS);
    constexpr int32_t INVALID_INDEX { -1 };
    int32_t index = cooperateClient.GetFirstSuccessIndex();
    ASSERT_GE(index, INVALID_INDEX);
    cooperateClient.DumpPerformanceInfo();
    
    SUCCEED();
#endif // ENABLE_PERFORMANCE_CHECK
}

/**
 * @tc.name: CooperateClientModifyTest_InternalState_001
 * @tc.desc: Test internal state management
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_InternalState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    int32_t requestId = cooperateClient.GenerateRequestID();
    ASSERT_GE(requestId, 0);
    std::vector<CoordinationMessage> messageTypes = {
        CoordinationMessage::ACTIVATE_SUCCESS,
        CoordinationMessage::ACTIVATE_FAIL,
        CoordinationMessage::DEACTIVATE_SUCCESS,
        CoordinationMessage::DEACTIVATE_FAIL
    };
    
    for (auto msg : messageTypes) {
        cooperateClient.OnDevCooperateListener("test-network", msg);
    }
    
    SUCCEED();
}

/**
 * @tc.name: CooperateClientModifyTest_MessageTypes_001
 * @tc.desc: Test all coordination message types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_MessageTypes_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientModTest client;

    std::vector<int32_t> messageValues = {
        <int32_t>(CoordinationMessage::ACTIVATE_SUCCESS),
        static_cast<int32_t>(CoordinationMessage::ACTIVATE_FAIL),
        static_cast<int32_t>(inationMessage::DEACTIVATE_SUCCESS),
        static_cast<int32_t>(CoordinationMessage::DEACTIVATE_FAIL)
    };
    
    for (int32_t msgValue : messageValues) {
        MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
        NetPacket pkt(msgId);
        
        int32_t userData = 999;
        std::string networkId = "test-network";
        int32_t errCode = 0;
        
        pkt << userData << networkId << msgValue << errCode;
        
        int32_t ret = cooperateClient.OnCoordinationMessage(client, pkt);
        ASSERT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: CooperateClientModifyTest_BoundaryValues_001
 * @tc.desc: Test boundary values for GenerateRequestID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_BoundaryValues_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    
    const int32_t largeNumber = 10000;
    std::set<int32_t> ids;
    
    for (int32_t i = 0; i < largeNumber; ++i) {
        int32_t id = cooperateClient.GenerateRequestID();
        
        ASSERT_TRUE(ids.find(id) == ids.end());
        ids.insert(id);
        
        ASSERT_GE(id, 0);
        ASSERT_LE(id, std::numeric_limits<int32_t>::max());
    }
    
    ASSERT_EQ(ids.size(), largeNumber);
}

/**
 * @tc.name: CooperateClientModifyTest_NetPacketOperations_001
 * @tc.desc: Test NetPacket operations
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_NetPacketOperations_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientModTest client;
    
    std::vector<std::tuple<std::string, int32_t, int32_t, int32_t>> testCases = {
        {"network1", 100, static_cast<int32_t>(CoordinationMessage::ACTIVATE_SUCCESS), 0},
        {"network2", 200, static_cast<int32_t>(CoordinationMessage::ACTIVATE_FAIL), 1},
        {"", 300, static_cast<int32_t>(CoordinationMessage::DEACTIVATE_SUCCESS), 0},
        {"network4", -1, static_cast<int32_t>(CoordinationMessage::DEACTIVATE_FAIL), -1}
    };
    
    for (const auto& [networkId, userData, msgType, errCode] : testCases) {
        MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
        NetPacket pkt(msgId);
        
        pkt << userData << networkId << msgType << errCode;
        
        int32_t ret = cooperateClient.OnCoordinationMessage(client, pkt);
        ASSERT_EQ(ret, RET_OK);
    }
}

/**
 * @tc.name: CooperateClientModifyTest_MouseLocation_001
 * @tc.desc: Test mouse location listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_MouseLocation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientModTest client;
    
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    
    std::string networkId = "test-network";
    Event event;
    event.displayX = 100;
    event.displayY = 200;
    event.displayWidth = 1920;
    event.displayHeight = 1080;
    
    pkt << networkId << event.displayX << event.displayY
        << event.displayWidth << event.displayHeight;
    
    int32_t ret = cooperateClient.OnMouseLocationListener(client, pkt);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CooperateClientModifyTest_MouseLocation_002
 * @tc.desc: Test mouse location with invalid packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_MouseLocation_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CooperateClient cooperateClient;
    StreamClientModTest client;
    
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket pkt(msgId);
    
    pkt << "network-id" << 100;
    
    int32_t ret = cooperateClient.OnMouseLocationListener(client, pkt);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CooperateClientModifyTest_SystemBasic_001
 * @tc.desc: Test SYSTEM_BASIC constant usage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_SystemBasic_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_EQ(SYSTEM_BASIC, "system_basic");
}

/**
 * @tc.name: CooperateClientModifyTest_ResponseCodes_001
 * @tc.desc: Test response codes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CooperateClientModifyTest, CooperateClientModifyTest_ResponseCodes_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_EQ(RET_OK, 0);
    ASSERT_EQ(RET_ERR, -1);
    
    CooperateClient cooperateClient;
    StreamClientModTest client;
    
    MessageId msgId = MessageId::COORDINATION_ADD_LISTENER;
    NetPacket validPkt(msgId);
    validPkt << 123 << true << 0;
    
    int32_t ret = cooperateClient.OnCoordinationState(client, validPkt);
    ASSERT_EQ(ret, RET_OK);
}

} // namespace ModifyTest
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS