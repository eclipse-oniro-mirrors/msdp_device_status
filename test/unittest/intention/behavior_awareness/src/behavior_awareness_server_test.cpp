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
#include "parameters.h"
#include "token_setproc.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessServerTest"

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
    infoInstance.processName = "BehaviorAwarenessServerTest";
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

CallingContext MakeNonSystemContext()
{
    return CallingContext {
        .fullTokenId = 0,
        .tokenId = 0,
        .uid = 10000,
        .pid = 10000,
    };
}

SubscribeOptions MakeOptions()
{
    return SubscribeOptions {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = {},
    };
}

SubscribeOptions MakeOptionsWithPattern(int32_t pt)
{
    return SubscribeOptions {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = { pt },
    };
}

PerceptionEventData MakeEvent(const std::string &id)
{
    return PerceptionEventData {
        .perceptionEventId = id,
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .confidence = 80,
        .generateTime = 1000,
        .payload = "",
    };
}
} // namespace

class BehaviorAwarenessServerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        std::string deviceType = OHOS::system::GetParameter("const.product.devicetype", "");
        if (deviceType != "phone") {
            GTEST_SKIP() << "BehaviorAwareness only supports phone, current device: " << deviceType;
        }
    }
    void TearDown() override {}
    BehaviorAwarenessServer server_;
};

/* ==================== SubscribePerception ==================== */

HWTEST_F(BehaviorAwarenessServerTest, SubscribePerception001, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto options = MakeOptions();
    auto callback = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);
    int32_t ret = server_.SubscribePerception(ctx, options, callback);
    EXPECT_EQ(ret, RET_OK);
}

HWTEST_F(BehaviorAwarenessServerTest, SubscribePerception002, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto options = MakeOptions();
    auto cb1 = sptr<TestCallback>::MakeSptr();
    auto cb2 = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb1, nullptr);
    ASSERT_NE(cb2, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, options, cb1), RET_OK);
    EXPECT_EQ(server_.SubscribePerception(ctx, options, cb2), RET_OK);
    server_.NotifyClient(MakeEvent("evt-overwrite"));
    EXPECT_EQ(cb1->receivedEvents_.size(), 0u);
    EXPECT_EQ(cb2->receivedEvents_.size(), 1u);
}

HWTEST_F(BehaviorAwarenessServerTest, SubscribePerception003, TestSize.Level1)
{
    auto ctx = MakeNonSystemContext();
    auto options = MakeOptions();
    auto callback = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);
    int32_t ret = server_.SubscribePerception(ctx, options, callback);
    EXPECT_EQ(ret, BehaviorAwareness::COMMON_NOT_SYSTEM_APP);
}

HWTEST_F(BehaviorAwarenessServerTest, SubscribePerception004_MultiKeyCoexist, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto optionsTime = MakeOptionsWithPattern(static_cast<int32_t>(PatternType::TIME_PATTERN));
    auto optionsLocation = MakeOptionsWithPattern(static_cast<int32_t>(PatternType::LOCATION_PATTERN));
    auto cbTime = sptr<TestCallback>::MakeSptr();
    auto cbLocation = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cbTime, nullptr);
    ASSERT_NE(cbLocation, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, optionsTime, cbTime), RET_OK);
    EXPECT_EQ(server_.SubscribePerception(ctx, optionsLocation, cbLocation), RET_OK);
    server_.NotifyClient(MakeEvent("evt-multi"));
    EXPECT_EQ(cbTime->receivedEvents_.size(), 1u);
    EXPECT_EQ(cbLocation->receivedEvents_.size(), 1u);
}

/* ==================== BuildSubscriptionKey ==================== */

HWTEST_F(BehaviorAwarenessServerTest, BuildSubscriptionKey001, TestSize.Level1)
{
    SubscribeOptions options {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = {},
    };
    EXPECT_EQ(BuildSubscriptionKey(options), "0");
}

HWTEST_F(BehaviorAwarenessServerTest, BuildSubscriptionKey002, TestSize.Level1)
{
    SubscribeOptions options {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = { static_cast<int32_t>(PatternType::TIME_PATTERN) },
    };
    EXPECT_EQ(BuildSubscriptionKey(options), "0:0");
}

HWTEST_F(BehaviorAwarenessServerTest, BuildSubscriptionKey003_OrderSensitive, TestSize.Level1)
{
    SubscribeOptions optionsA {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = { static_cast<int32_t>(PatternType::TIME_PATTERN),
                          static_cast<int32_t>(PatternType::LOCATION_PATTERN) },
    };
    SubscribeOptions optionsB {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = { static_cast<int32_t>(PatternType::LOCATION_PATTERN),
                          static_cast<int32_t>(PatternType::TIME_PATTERN) },
    };
    EXPECT_NE(BuildSubscriptionKey(optionsA), BuildSubscriptionKey(optionsB));
}

/* ==================== UnsubscribePerception ==================== */

HWTEST_F(BehaviorAwarenessServerTest, UnsubscribePerception001, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto options = MakeOptions();
    auto callback = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, options, callback), RET_OK);
    EXPECT_EQ(server_.UnsubscribePerception(ctx, callback), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerTest, UnsubscribePerception002, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto options = MakeOptions();
    auto callback = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, options, callback), RET_OK);
    EXPECT_EQ(server_.UnsubscribePerception(ctx, nullptr), RET_OK);
    server_.NotifyClient(MakeEvent("evt-after-unsub"));
    EXPECT_EQ(callback->receivedEvents_.size(), 0u);
}

HWTEST_F(BehaviorAwarenessServerTest, UnsubscribePerception003, TestSize.Level1)
{
    auto ctx = MakeNonSystemContext();
    auto callback = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);
    int32_t ret = server_.UnsubscribePerception(ctx, callback);
    EXPECT_EQ(ret, BehaviorAwareness::COMMON_NOT_SYSTEM_APP);
}

HWTEST_F(BehaviorAwarenessServerTest, UnsubscribePerception004, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto callback = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);
    int32_t ret = server_.UnsubscribePerception(ctx, callback);
    EXPECT_EQ(ret, BehaviorAwareness::UNSUBSCRIBE_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, UnsubscribePerception005, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto options = MakeOptions();
    auto registered = sptr<TestCallback>::MakeSptr();
    auto mismatch = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(registered, nullptr);
    ASSERT_NE(mismatch, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, options, registered), RET_OK);
    int32_t ret = server_.UnsubscribePerception(ctx, mismatch);
    EXPECT_EQ(ret, BehaviorAwareness::UNSUBSCRIBE_EXCEPTION);
}

/* ==================== NotifyClient ==================== */

HWTEST_F(BehaviorAwarenessServerTest, NotifyClient001, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto options = MakeOptions();
    auto callback = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, options, callback), RET_OK);
    server_.NotifyClient(MakeEvent("evt-1"));
    ASSERT_EQ(callback->receivedEvents_.size(), 1u);
    EXPECT_EQ(callback->receivedEvents_[0].perceptionEventId, "evt-1");
}

HWTEST_F(BehaviorAwarenessServerTest, NotifyClient002, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto options = MakeOptions();
    auto callback = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(callback, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, options, callback), RET_OK);
    server_.NotifyClient(MakeEvent("evt-before"));
    EXPECT_EQ(callback->receivedEvents_.size(), 1u);
    EXPECT_EQ(server_.UnsubscribePerception(ctx, callback), RET_OK);
    server_.NotifyClient(MakeEvent("evt-after"));
    EXPECT_EQ(callback->receivedEvents_.size(), 1u);
}

/* ==================== SubmitFeedback ==================== */

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback001, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "fb-001",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    int32_t ret = server_.SubmitFeedback(ctx, feedback);
    EXPECT_EQ(ret, RET_OK);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback002, TestSize.Level1)
{
    auto ctx = MakeNonSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "fb-002",
        .feedbackType = FeedbackType::REJECT,
        .feedbackTime = 2000,
    };
    int32_t ret = server_.SubmitFeedback(ctx, feedback);
    EXPECT_EQ(ret, BehaviorAwareness::COMMON_NOT_SYSTEM_APP);
}

/* ==================== Branch coverage: edge cases ==================== */

HWTEST_F(BehaviorAwarenessServerTest, UnsubscribePerception_Null_EmptyCache_ReturnsError, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    EXPECT_EQ(server_.UnsubscribePerception(ctx, nullptr), BehaviorAwareness::UNSUBSCRIBE_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, NotifyClient_NullCallbackInSubscription_Skipped, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.subscriptions_["other_bundle:0:0"].callback = nullptr;
    server_.NotifyClient(MakeEvent("evt-null-cb"));
    EXPECT_EQ(cb->receivedEvents_.size(), 1u);
}

HWTEST_F(BehaviorAwarenessServerTest, RemoveMatchingSubscription_NullCallbackInCache_Skipped, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.subscriptions_[server_.subscriptions_.begin()->first].callback = nullptr;
    int32_t ret = server_.UnsubscribePerception(ctx, cb);
    EXPECT_EQ(ret, BehaviorAwareness::UNSUBSCRIBE_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, RemoveAllSubscriptions_SkipOtherBundle, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.subscriptions_["other_bundle:0:0"] = { PerceptionDomain::HABIT_AWARENESS, {}, cb };
    EXPECT_EQ(server_.UnsubscribePerception(ctx, nullptr), RET_OK);
    EXPECT_TRUE(server_.subscriptions_.find("other_bundle:0:0") != server_.subscriptions_.end());
}

HWTEST_F(BehaviorAwarenessServerTest, OnRemoteDied_NoMatchingSubscription, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    auto otherCb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(otherCb, nullptr);
    server_.OnRemoteDied(otherCb->AsObject());
    EXPECT_FALSE(server_.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessServerTest, RemoveMatchingSubscription_SkipOtherBundle, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    auto otherCb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(otherCb, nullptr);
    server_.subscriptions_["other_bundle:0:0"] = { PerceptionDomain::HABIT_AWARENESS, {}, otherCb };
    EXPECT_EQ(server_.UnsubscribePerception(ctx, cb), RET_OK);
    EXPECT_TRUE(server_.subscriptions_.find("other_bundle:0:0") != server_.subscriptions_.end());
}

HWTEST_F(BehaviorAwarenessServerTest, OnRemoteDied_MatchingSubscription_Cleaned, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    EXPECT_FALSE(server_.subscriptions_.empty());
    server_.OnRemoteDied(cb->AsObject());
    EXPECT_TRUE(server_.subscriptions_.empty());
}

/* ==================== DeviceType check (801) ==================== */

class BehaviorAwarenessServerDeviceTypeTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        savedTypes_ = BehaviorAwarenessServer::SUPPORT_DEVICE_TYPE_;
        const_cast<std::vector<std::string>&>(BehaviorAwarenessServer::SUPPORT_DEVICE_TYPE_).clear();
    }
    void TearDown() override
    {
        const_cast<std::vector<std::string>&>(BehaviorAwarenessServer::SUPPORT_DEVICE_TYPE_) = savedTypes_;
    }
    BehaviorAwarenessServer server_;
    std::vector<std::string> savedTypes_;
};

HWTEST_F(BehaviorAwarenessServerDeviceTypeTest, SubscribePerception_UnsupportedDevice_Returns801, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), BehaviorAwareness::DEVICE_NOT_SUPPORT);
}

HWTEST_F(BehaviorAwarenessServerDeviceTypeTest, UnsubscribePerception_UnsupportedDevice_Returns801, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.UnsubscribePerception(ctx, cb), BehaviorAwareness::DEVICE_NOT_SUPPORT);
}

HWTEST_F(BehaviorAwarenessServerDeviceTypeTest, SubmitFeedback_UnsupportedDevice_Returns801, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "fb-001",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::DEVICE_NOT_SUPPORT);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
