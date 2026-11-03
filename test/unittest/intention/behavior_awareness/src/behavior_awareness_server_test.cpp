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
#include "feedback_store.h"
#include "fi_log.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "parameters.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "token_setproc.h"
#include "unistd.h"

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
        .perceptionEventId = "habitAwareness_1",
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

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback003_EmptyEventId_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback004_FeedbackTypeOutOfRange_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = static_cast<FeedbackType>(5),
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback005_NegativeFeedbackType_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = static_cast<FeedbackType>(-1),
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback006_ZeroFeedbackTime_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 0,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback007_NegativeFeedbackTime_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = -1,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback008_InvalidEventIdNoUnderscore_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "invalidformat",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback009_InvalidEventIdNonNumericSuffix_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_abc",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback010_ValidParam_ReturnsRetOk, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback012_DbNotExist_Tolerant_ReturnsRetOk, TestSize.Level1)
{
    FeedbackStore::GetInstance().SetDatabasePathForTesting("/data/local/tmp/nonexistent_server_db.db");
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(PERCEPTION_DB_PATH);
}

/* ==================== SubmitFeedback: perceptionEventId format validation (BR-8) ==================== */

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_InvalidDomainPrefix_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "invalidDomain_123",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_EmptyDomainPrefix_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "_123",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_NegativeId_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_-1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_EmptyIdSuffix_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_ZeroId_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_0",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_ValidHabitAwarenessFormat_ReturnsRetOk, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_123",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_CaseSensitivePrefix_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "HabitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_MultipleUnderscores_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1_2",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_LargeId_ReturnsRetOk, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_2147483647",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_SuffixWithLeadingSpace_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_ 123",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_SuffixWithTrailingSpace_Returns401, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_123 ",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_AllFiveFeedbackTypes_ReturnsRetOk, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackType types[] = {
        FeedbackType::ACCEPT,
        FeedbackType::IGNORE,
        FeedbackType::REJECT,
        FeedbackType::EDIT,
        FeedbackType::NOT_PUSHED,
    };
    for (int32_t i = 0; i < static_cast<int32_t>(sizeof(types) / sizeof(types[0])); ++i) {
        FeedbackData feedback {
            .perceptionEventId = "habitAwareness_1",
            .feedbackType = types[i],
            .feedbackTime = 1000 + i,
        };
        EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
    }
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_MaxFeedbackType_ReturnsRetOk, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::NOT_PUSHED,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerTest, SubmitFeedback_MinFeedbackType_ReturnsRetOk, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
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

namespace {
constexpr const char *SERVER_TEST_DB_PATH = "/data/local/tmp/test_server_habit_perceptions.db";
constexpr const char *SERVER_CREATE_TABLE_SQL =
    "CREATE TABLE IF NOT EXISTS habit_perceptions ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "e TEXT NOT NULL, "
    "e_param TEXT DEFAULT '{}', "
    "a TEXT NOT NULL, "
    "a_param TEXT DEFAULT '{}', "
    "score REAL DEFAULT 0, "
    "confidence REAL DEFAULT 0, "
    "lift_degree REAL DEFAULT 0.9, "
    "novelty REAL DEFAULT 0.9, "
    "count INTEGER DEFAULT 0, "
    "pool TEXT DEFAULT 'general', "
    "perception_count INTEGER DEFAULT 0, "
    "feedback TEXT DEFAULT '{}', "
    "created_time INTEGER DEFAULT 0, "
    "update_time INTEGER DEFAULT 0)";

class ServerFeedbackTestCallback : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override
    {
        return rdbStore.ExecuteSql(SERVER_CREATE_TABLE_SQL);
    }
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override
    {
        return NativeRdb::E_OK;
    }
};

void SetupServerTestDatabase(const std::string &path)
{
    unlink(path.c_str());
    NativeRdb::RdbStoreConfig config(path);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    int32_t errCode = NativeRdb::E_OK;
    ServerFeedbackTestCallback callback;
    auto store = NativeRdb::RdbHelper::GetRdbStore(config, 1, callback, errCode);
    if (store == nullptr) {
        return;
    }
    store->ExecuteSql(
        "INSERT INTO habit_perceptions (id, e, a, feedback) VALUES (1, 'time', 'switch', '{}')");
}
} // namespace

class SubmitFeedbackPersistTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        std::string deviceType = OHOS::system::GetParameter("const.product.devicetype", "");
        if (deviceType != "phone") {
            GTEST_SKIP() << "BehaviorAwareness only supports phone, current device: " << deviceType;
        }
        SetupServerTestDatabase(SERVER_TEST_DB_PATH);
        FeedbackStore::GetInstance().SetDatabasePathForTesting(SERVER_TEST_DB_PATH);
        NativeTokenGet();
    }
    void TearDown() override
    {
        FeedbackStore::GetInstance().Clear();
        FeedbackStore::GetInstance().SetDatabasePathForTesting(PERCEPTION_DB_PATH);
        unlink(SERVER_TEST_DB_PATH);
    }
    BehaviorAwarenessServer server_;
};

HWTEST_F(SubmitFeedbackPersistTest, SubmitFeedback008_FiveTypes_SameEventId_UpdatedToLast, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackType types[] = {
        FeedbackType::ACCEPT,
        FeedbackType::IGNORE,
        FeedbackType::REJECT,
        FeedbackType::EDIT,
        FeedbackType::NOT_PUSHED,
    };
    for (int32_t i = 0; i < 5; ++i) {
        FeedbackData feedback {
            .perceptionEventId = "habitAwareness_1",
            .feedbackType = types[i],
            .feedbackTime = 1000 + i,
        };
        EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
    }
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::NOT_PUSHED));
}

HWTEST_F(SubmitFeedbackPersistTest, SubmitFeedback009_Idempotent_SameEventIdSameType, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
    std::vector<FeedbackRecord> records;
    FeedbackStore::GetInstance().QueryAll(records);
    int32_t count = 0;
    for (const auto &r : records) {
        if (r.id == 1) {
            ++count;
        }
    }
    EXPECT_EQ(count, 1);
}

HWTEST_F(SubmitFeedbackPersistTest, SubmitFeedback010_Success_RecordsPersisted, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), RET_OK);
    FeedbackRecord record;
    EXPECT_EQ(FeedbackStore::GetInstance().QueryFeedback("habitAwareness_1", record), RET_OK);
    EXPECT_EQ(record.feedbackType, static_cast<int32_t>(FeedbackType::ACCEPT));
    EXPECT_EQ(record.feedbackTime, 1000);
}

HWTEST_F(SubmitFeedbackPersistTest, SubmitFeedback_Ac1_7_ServiceException_ReturnsServiceException, TestSize.Level1)
{
    const char *invalidDbPath = "/data/local/tmp/invalid_server_habit_perceptions.db";
    FILE *f = fopen(invalidDbPath, "w");
    ASSERT_NE(f, nullptr);
    fputs("not a database", f);
    fclose(f);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(invalidDbPath);
    auto ctx = MakeSystemContext();
    FeedbackData feedback {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, feedback), SERVICE_EXCEPTION);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(SERVER_TEST_DB_PATH);
    unlink(invalidDbPath);
}
/* ==================== Branch Coverage Supplement ==================== */

class BehaviorAwarenessServerBranchTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        savedTypes_ = BehaviorAwarenessServer::SUPPORT_DEVICE_TYPE_;
        std::string deviceType = OHOS::system::GetParameter("const.product.devicetype", "");
        auto &supportTypes = const_cast<std::vector<std::string>&>(
            BehaviorAwarenessServer::SUPPORT_DEVICE_TYPE_);
        if (std::find(supportTypes.begin(), supportTypes.end(), deviceType) == supportTypes.end()) {
            supportTypes.push_back(deviceType);
        }
        FeedbackStore::GetInstance().SetDatabasePathForTesting("/data/local/tmp/nonexistent_branch_db.db");
        NativeTokenGet();
    }
    void TearDown() override
    {
        const_cast<std::vector<std::string>&>(BehaviorAwarenessServer::SUPPORT_DEVICE_TYPE_) = savedTypes_;
        FeedbackStore::GetInstance().SetDatabasePathForTesting(PERCEPTION_DB_PATH);
    }
    BehaviorAwarenessServer server_;
    std::vector<std::string> savedTypes_;
};

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_EmptyEventId, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_NoUnderscore, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "nounderscore",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_UnderscoreAtEnd, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_InvalidPrefix, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "invalidPrefix_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_NonNumericSuffix, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_abc",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_PartialNumericSuffix, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_12abc",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_NegativeId, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_-1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_ZeroId, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_0",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_FeedbackTypeTooLow, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = static_cast<FeedbackType>(-1),
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_FeedbackTypeTooHigh, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = static_cast<FeedbackType>(5),
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_ZeroFeedbackTime, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 0,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_NegativeFeedbackTime, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = -1,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_ValidInput, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_ValidLargeId, TestSize.Level1)
{
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_999999",
        .feedbackType = FeedbackType::NOT_PUSHED,
        .feedbackTime = 1,
    };
    EXPECT_EQ(server_.ValidateFeedback(fb), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, ValidateFeedback_AllFeedbackTypesValid, TestSize.Level1)
{
    FeedbackType types[] = {
        FeedbackType::ACCEPT,
        FeedbackType::IGNORE,
        FeedbackType::REJECT,
        FeedbackType::EDIT,
        FeedbackType::NOT_PUSHED,
    };
    for (auto t : types) {
        FeedbackData fb {
            .perceptionEventId = "habitAwareness_1",
            .feedbackType = t,
            .feedbackTime = 1000,
        };
        EXPECT_EQ(server_.ValidateFeedback(fb), RET_OK);
    }
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubmitFeedback_NonSystemApp, TestSize.Level1)
{
    auto ctx = MakeNonSystemContext();
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, fb), BehaviorAwareness::COMMON_NOT_SYSTEM_APP);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubmitFeedback_SystemApp_InvalidParam, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData fb {
        .perceptionEventId = "",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, fb), BehaviorAwareness::PARAM_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubmitFeedback_SystemApp_Valid_TolerantOk, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, fb), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubscribePerception_SystemApp_Success, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubscribePerception_NonSystemApp, TestSize.Level1)
{
    auto ctx = MakeNonSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), BehaviorAwareness::COMMON_NOT_SYSTEM_APP);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubscribePerception_Overwrite_Existing, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb1 = sptr<TestCallback>::MakeSptr();
    auto cb2 = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb1, nullptr);
    ASSERT_NE(cb2, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb1), RET_OK);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb2), RET_OK);
    server_.NotifyClient(MakeEvent("evt-overwrite"));
    EXPECT_EQ(cb1->receivedEvents_.size(), 0u);
    EXPECT_EQ(cb2->receivedEvents_.size(), 1u);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubscribePerception_MultiKey_Coexist, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cbTime = sptr<TestCallback>::MakeSptr();
    auto cbLoc = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cbTime, nullptr);
    ASSERT_NE(cbLoc, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptionsWithPattern(0), cbTime), RET_OK);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptionsWithPattern(1), cbLoc), RET_OK);
    server_.NotifyClient(MakeEvent("evt-multi"));
    EXPECT_EQ(cbTime->receivedEvents_.size(), 1u);
    EXPECT_EQ(cbLoc->receivedEvents_.size(), 1u);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, UnsubscribePerception_SystemApp_NullCallback, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    EXPECT_EQ(server_.UnsubscribePerception(ctx, nullptr), RET_OK);
    server_.NotifyClient(MakeEvent("evt-after-unsub"));
    EXPECT_EQ(cb->receivedEvents_.size(), 0u);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, UnsubscribePerception_NullCallback_NoSubscription, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    EXPECT_EQ(server_.UnsubscribePerception(ctx, nullptr), BehaviorAwareness::UNSUBSCRIBE_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, UnsubscribePerception_NonSystemApp, TestSize.Level1)
{
    auto ctx = MakeNonSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.UnsubscribePerception(ctx, cb), BehaviorAwareness::COMMON_NOT_SYSTEM_APP);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, UnsubscribePerception_MatchingCallback, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    EXPECT_EQ(server_.UnsubscribePerception(ctx, cb), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, UnsubscribePerception_MismatchCallback, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb1 = sptr<TestCallback>::MakeSptr();
    auto cb2 = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb1, nullptr);
    ASSERT_NE(cb2, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb1), RET_OK);
    EXPECT_EQ(server_.UnsubscribePerception(ctx, cb2), BehaviorAwareness::UNSUBSCRIBE_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, UnsubscribePerception_OtherBundle_Skipped, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.subscriptions_["other_bundle:0"] = { PerceptionDomain::HABIT_AWARENESS, {}, cb };
    EXPECT_EQ(server_.UnsubscribePerception(ctx, nullptr), RET_OK);
    EXPECT_TRUE(server_.subscriptions_.find("other_bundle:0") != server_.subscriptions_.end());
}

HWTEST_F(BehaviorAwarenessServerBranchTest, NotifyClient_NullCallback_Skipped, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.subscriptions_["other:0"].callback = nullptr;
    server_.NotifyClient(MakeEvent("evt-null"));
    EXPECT_EQ(cb->receivedEvents_.size(), 1u);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, OnRemoteDied_NullPromote, TestSize.Level1)
{
    wptr<IRemoteObject> nullObj = nullptr;
    server_.OnRemoteDied(nullObj);
    EXPECT_TRUE(server_.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessServerBranchTest, OnRemoteDied_MatchingSubscription, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.OnRemoteDied(cb->AsObject());
    EXPECT_TRUE(server_.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessServerBranchTest, OnRemoteDied_NoMatchingSubscription, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb1 = sptr<TestCallback>::MakeSptr();
    auto cb2 = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb1, nullptr);
    ASSERT_NE(cb2, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb1), RET_OK);
    server_.OnRemoteDied(cb2->AsObject());
    EXPECT_FALSE(server_.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessServerBranchTest, RemoveMatchingSubscription_NullCallbackInCache, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.subscriptions_.begin()->second.callback = nullptr;
    EXPECT_EQ(server_.UnsubscribePerception(ctx, cb), BehaviorAwareness::UNSUBSCRIBE_EXCEPTION);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, InitDeathRecipient_AlreadyExists, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.InitDeathRecipient();
    EXPECT_NE(server_.deathRecipient_, nullptr);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubscribePerception_Overwrite_OldCallbackNull, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb1 = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb1, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb1), RET_OK);
    server_.subscriptions_.begin()->second.callback = nullptr;
    auto cb2 = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb2, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb2), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubscribePerception_Overwrite_NewCallbackNull, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb1 = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb1, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb1), RET_OK);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), nullptr), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubscribePerception_NewKey_NullCallback, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), nullptr), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, RemoveAllSubscriptions_DeathRecipientNull, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.deathRecipient_ = nullptr;
    EXPECT_EQ(server_.UnsubscribePerception(ctx, nullptr), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, RemoveMatchingSubscription_DeathRecipientNull, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.deathRecipient_ = nullptr;
    EXPECT_EQ(server_.UnsubscribePerception(ctx, cb), RET_OK);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, NotifyClient_NoSubscriptions, TestSize.Level1)
{
    server_.NotifyClient(MakeEvent("evt-empty"));
}

HWTEST_F(BehaviorAwarenessServerBranchTest, OnRemoteDied_NullCallbackInSubscription, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.SubscribePerception(ctx, MakeOptions(), cb), RET_OK);
    server_.subscriptions_.begin()->second.callback = nullptr;
    server_.OnRemoteDied(cb->AsObject());
    EXPECT_FALSE(server_.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessServerBranchTest, SubmitFeedback_InsertFeedbackFails, TestSize.Level1)
{
    const char *invalidDbPath = "/data/local/tmp/invalid_branch_db.db";
    FILE *f = fopen(invalidDbPath, "w");
    ASSERT_NE(f, nullptr);
    fputs("not a database", f);
    fclose(f);
    FeedbackStore::GetInstance().SetDatabasePathForTesting(invalidDbPath);
    auto ctx = MakeSystemContext();
    FeedbackData fb {
        .perceptionEventId = "habitAwareness_1",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(server_.SubmitFeedback(ctx, fb), SERVICE_EXCEPTION);
    FeedbackStore::GetInstance().SetDatabasePathForTesting("/data/local/tmp/nonexistent_branch_db.db");
    unlink(invalidDbPath);
}

HWTEST_F(BehaviorAwarenessServerBranchTest, RemoveMatchingSubscription_EmptySubscriptions, TestSize.Level1)
{
    auto ctx = MakeSystemContext();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(server_.UnsubscribePerception(ctx, cb), BehaviorAwareness::UNSUBSCRIBE_EXCEPTION);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
