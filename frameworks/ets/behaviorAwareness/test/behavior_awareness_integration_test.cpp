/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "behavior_awareness_server.h"
#include "behavior_awareness_data.h"
#include "behavior_awareness_callback_stub.h"
#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessIntegrationTest"

using namespace OHOS;
using namespace OHOS::Msdp::DeviceStatus::BehaviorAwareness;

class BehaviorAwarenessIntegrationTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

class TestCallback : public BehaviorAwarenessCallbackStub {
public:
    void OnBehaviorAwareness(const PerceptionEventData &event) override
    {
        receivedEvents_.push_back(event);
    }
    std::vector<PerceptionEventData> receivedEvents_;
};

/**
 * @tc.name: Restart_ReSubscribe_EventPushed
 * @tc.desc: AC-1.3: on() → simulate restart → SA online → re-subscribe → event push
 * @tc.type: INTEGRATION
 * @tc.require: 20260825320400
 */
HWTEST_F(BehaviorAwarenessIntegrationTest, Restart_ReSubscribe_EventPushed, testing::ext::TestSize.Level3)
{
    BehaviorAwarenessServer server;
    auto callback = sptr<TestCallback>::MakeSptr();

    CallingContext context {
        .fullTokenId = 0x20000000,
        .tokenId = 0x20000000,
        .uid = 1000,
        .pid = 1000,
    };
    SubscribeOptions options {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = {},
    };

    int32_t ret = server.SubscribePerception(context, options, callback);
    EXPECT_EQ(ret, RET_OK);

    PerceptionEventData event {
        .perceptionEventId = "test-event-1",
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .confidence = 80,
        .generateTime = 1000,
        .payload = "",
    };
    server.NotifyClient(event);
    EXPECT_EQ(callback->receivedEvents_.size(), 1u);

    BehaviorAwarenessServer restartedServer;
    PerceptionEventData event2 {
        .perceptionEventId = "test-event-2",
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .confidence = 90,
        .generateTime = 2000,
        .payload = "",
    };
    restartedServer.NotifyClient(event2);
    EXPECT_EQ(callback->receivedEvents_.size(), 1u);

    int32_t ret2 = restartedServer.SubscribePerception(context, options, callback);
    EXPECT_EQ(ret2, RET_OK);

    restartedServer.NotifyClient(event2);
    EXPECT_EQ(callback->receivedEvents_.size(), 2u);
    EXPECT_EQ(callback->receivedEvents_[1].perceptionEventId, "test-event-2");
}
