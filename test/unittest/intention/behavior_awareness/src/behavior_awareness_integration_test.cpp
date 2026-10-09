/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "behavior_awareness_callback_stub.h"
#include "behavior_awareness_data.h"
#include "behavior_awareness_server.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessIntegrationTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
using namespace Security::AccessToken;
using namespace BehaviorAwareness;

namespace {
class TestCallback : public BehaviorAwarenessCallbackStub {
public:
    void OnBehaviorAwareness(const PerceptionEventData &event) override
    {
        receivedEvents_.push_back(event);
    }
    std::vector<PerceptionEventData> receivedEvents_;
};

uint64_t NativeTokenGet()
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = nullptr,
        .acls = nullptr,
        .aplStr = "system_basic",
    };
    infoInstance.processName = "BehaviorAwarenessIntegrationTest";
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    return tokenId;
}

CallingContext MakeSystemContext()
{
    NativeTokenGet();
    return CallingContext {
        .fullTokenId = IPCSkeleton::GetCallingFullTokenID(),
        .tokenId = IPCSkeleton::GetCallingTokenID(),
        .uid = IPCSkeleton::GetCallingUid(),
        .pid = IPCSkeleton::GetCallingPid(),
    };
}
} // namespace

class BehaviorAwarenessIntegrationTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Restart_ReSubscribe_EventPushed
 * @tc.desc: AC-1.3: subscribe → server restart → re-subscribe → event push restored
 * @tc.type: INTEGRATION
 * @tc.require: 20260825320400
 */
HWTEST_F(BehaviorAwarenessIntegrationTest, Restart_ReSubscribe_EventPushed, TestSize.Level3)
{
    auto ctx = MakeSystemContext();
    SubscribeOptions options {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = {},
    };
    auto callback = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);

    BehaviorAwarenessServer server;
    EXPECT_EQ(server.SubscribePerception(ctx, options, callback), RET_OK);

    PerceptionEventData event1 {
        .perceptionEventId = "test-event-1",
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .confidence = 80,
        .generateTime = 1000,
        .payload = "",
    };
    server.NotifyClient(event1);
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

    EXPECT_EQ(restartedServer.SubscribePerception(ctx, options, callback), RET_OK);
    restartedServer.NotifyClient(event2);
    ASSERT_EQ(callback->receivedEvents_.size(), 2u);
    EXPECT_EQ(callback->receivedEvents_[1].perceptionEventId, "test-event-2");
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
