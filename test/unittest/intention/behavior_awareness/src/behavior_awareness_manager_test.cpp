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
#include <functional>
#include <memory>
#include <vector>

#include "behavior_awareness_callback_stub.h"
#include "behavior_awareness_data.h"
#include "behavior_awareness_manager.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "intention_client.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessManagerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

using namespace testing::ext;

class MockIntentionClient : public IntentionClient {
public:
    int32_t subscribeRet { RET_OK };
    int32_t unsubscribeRet { RET_OK };
    int32_t submitFeedbackRet { RET_OK };

    int32_t subscribeCallCount { 0 };
    int32_t unsubscribeCallCount { 0 };
    int32_t submitFeedbackCallCount { 0 };

    std::function<void()> saReviveCallback {};

    int32_t SubscribePerception(const BehaviorAwareness::SubscribeOptions &options,
        const sptr<BehaviorAwareness::IRemoteBehaviorAwarenessCallback> &callback) override
    {
        ++subscribeCallCount;
        lastSubscribeOptions = options;
        return subscribeRet;
    }

    int32_t UnsubscribePerception(
        const sptr<BehaviorAwareness::IRemoteBehaviorAwarenessCallback> &callback) override
    {
        ++unsubscribeCallCount;
        return unsubscribeRet;
    }

    int32_t SubmitFeedback(const BehaviorAwareness::FeedbackData &feedback) override
    {
        ++submitFeedbackCallCount;
        return submitFeedbackRet;
    }

    void SetSaReviveCallback(std::function<void()> callback) override
    {
        saReviveCallback = std::move(callback);
    }

    void Reset()
    {
        subscribeRet = RET_OK;
        unsubscribeRet = RET_OK;
        submitFeedbackRet = RET_OK;
        subscribeCallCount = 0;
        unsubscribeCallCount = 0;
        submitFeedbackCallCount = 0;
    }

    BehaviorAwareness::SubscribeOptions lastSubscribeOptions {};
};

static std::shared_ptr<MockIntentionClient> g_mock = std::make_shared<MockIntentionClient>();

namespace BehaviorAwareness {

class TestCallback : public BehaviorAwarenessCallbackStub {
public:
    void OnBehaviorAwareness(const PerceptionEventData &event) override {}
};

class BehaviorAwarenessManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        IntentionClient::SetInstance(g_mock);
    }
    static void TearDownTestCase() {}
    void SetUp() override
    {
        g_mock->Reset();
        auto &mgr = BehaviorAwarenessManager::GetInstance();
        std::lock_guard<std::mutex> lk(mgr.mtx_);
        mgr.subscriptions_.clear();
    }
    void TearDown() override {}
};

SubscribeOptions MakeOptions(int32_t pt = -1)
{
    if (pt < 0) {
        return SubscribeOptions {
            .domain = PerceptionDomain::HABIT_AWARENESS,
            .patternTypes = {},
        };
    }
    return SubscribeOptions {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = { pt },
    };
}

/* ==================== SubscribePerception ==================== */

HWTEST_F(BehaviorAwarenessManagerTest, SubscribePerception_IpcError_ReturnsError, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    g_mock->subscribeRet = SERVICE_EXCEPTION;
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(mgr.SubscribePerception(MakeOptions(), cb), SERVICE_EXCEPTION);
    EXPECT_EQ(g_mock->subscribeCallCount, 1);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_TRUE(mgr.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessManagerTest, SubscribePerception_NewKey_Cached, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb), RET_OK);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_EQ(mgr.subscriptions_.size(), 1u);
    EXPECT_TRUE(mgr.subscriptions_.find("0:0") != mgr.subscriptions_.end());
}

HWTEST_F(BehaviorAwarenessManagerTest, SubscribePerception_SameKey_Updated, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb1 = sptr<TestCallback>::MakeSptr();
    auto cb2 = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb1, nullptr);
    ASSERT_NE(cb2, nullptr);
    EXPECT_EQ(mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb1), RET_OK);
    EXPECT_EQ(mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb2), RET_OK);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_EQ(mgr.subscriptions_.size(), 1u);
    EXPECT_TRUE(mgr.subscriptions_["0:0"].callback->AsObject() == cb2->AsObject());
}

HWTEST_F(BehaviorAwarenessManagerTest, SubscribePerception_MultiKey_Coexist, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cbTime = sptr<TestCallback>::MakeSptr();
    auto cbLocation = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cbTime, nullptr);
    ASSERT_NE(cbLocation, nullptr);
    EXPECT_EQ(mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cbTime), RET_OK);
    EXPECT_EQ(mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::LOCATION_PATTERN)), cbLocation),
        RET_OK);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_EQ(mgr.subscriptions_.size(), 2u);
    EXPECT_TRUE(mgr.subscriptions_.find("0:0") != mgr.subscriptions_.end());
    EXPECT_TRUE(mgr.subscriptions_.find("0:1") != mgr.subscriptions_.end());
}

/* ==================== UnsubscribePerception (nullptr = all) ==================== */

HWTEST_F(BehaviorAwarenessManagerTest, UnsubscribePerception_Null_ClearsAll, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb1 = sptr<TestCallback>::MakeSptr();
    auto cb2 = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb1, nullptr);
    ASSERT_NE(cb2, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb1);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::LOCATION_PATTERN)), cb2);
    EXPECT_EQ(mgr.UnsubscribePerception(nullptr), RET_OK);
    EXPECT_EQ(g_mock->unsubscribeCallCount, 2);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_TRUE(mgr.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessManagerTest, UnsubscribePerception_Null_SkipsNullCallback, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb);
    {
        std::lock_guard<std::mutex> lk(mgr.mtx_);
        mgr.subscriptions_["0:1"].callback = nullptr;
    }
    EXPECT_EQ(mgr.UnsubscribePerception(nullptr), RET_OK);
    EXPECT_EQ(g_mock->unsubscribeCallCount, 1);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_TRUE(mgr.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessManagerTest, UnsubscribePerception_Null_OneIpcFails, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb1 = sptr<TestCallback>::MakeSptr();
    auto cb2 = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb1, nullptr);
    ASSERT_NE(cb2, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb1);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::LOCATION_PATTERN)), cb2);
    g_mock->unsubscribeRet = UNSUBSCRIBE_EXCEPTION;
    EXPECT_EQ(mgr.UnsubscribePerception(nullptr), UNSUBSCRIBE_EXCEPTION);
    EXPECT_EQ(g_mock->unsubscribeCallCount, 2);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_TRUE(mgr.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessManagerTest, UnsubscribePerception_Null_EmptyCache, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    EXPECT_EQ(mgr.UnsubscribePerception(nullptr), RET_OK);
    EXPECT_EQ(g_mock->unsubscribeCallCount, 0);
}

/* ==================== UnsubscribePerception (non-null) ==================== */

HWTEST_F(BehaviorAwarenessManagerTest, UnsubscribePerception_IpcError, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb);
    g_mock->unsubscribeRet = SERVICE_EXCEPTION;
    EXPECT_EQ(mgr.UnsubscribePerception(cb), SERVICE_EXCEPTION);
    EXPECT_EQ(g_mock->unsubscribeCallCount, 1);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_EQ(mgr.subscriptions_.size(), 1u);
}

HWTEST_F(BehaviorAwarenessManagerTest, UnsubscribePerception_FoundInCache_Erased, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb);
    EXPECT_EQ(mgr.UnsubscribePerception(cb), RET_OK);
    EXPECT_EQ(g_mock->unsubscribeCallCount, 1);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_TRUE(mgr.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessManagerTest, UnsubscribePerception_NotFoundInCache, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(mgr.UnsubscribePerception(cb), RET_OK);
    EXPECT_EQ(g_mock->unsubscribeCallCount, 1);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_TRUE(mgr.subscriptions_.empty());
}

HWTEST_F(BehaviorAwarenessManagerTest, UnsubscribePerception_CacheNotEmpty_CbNotMatched, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cbRegistered = sptr<TestCallback>::MakeSptr();
    auto cbOther = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cbRegistered, nullptr);
    ASSERT_NE(cbOther, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cbRegistered);
    EXPECT_EQ(mgr.UnsubscribePerception(cbOther), RET_OK);
    EXPECT_EQ(g_mock->unsubscribeCallCount, 1);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_EQ(mgr.subscriptions_.size(), 1u);
}

HWTEST_F(BehaviorAwarenessManagerTest, UnsubscribePerception_MultiKeySameCb_RemovesFirst, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::LOCATION_PATTERN)), cb);
    EXPECT_EQ(mgr.UnsubscribePerception(cb), RET_OK);
    EXPECT_EQ(g_mock->unsubscribeCallCount, 1);
    std::lock_guard<std::mutex> lk(mgr.mtx_);
    EXPECT_EQ(mgr.subscriptions_.size(), 1u);
}

/* ==================== SubmitFeedback ==================== */

HWTEST_F(BehaviorAwarenessManagerTest, SubmitFeedback_DelegatesToIpc, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    FeedbackData feedback {
        .perceptionEventId = "fb-001",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    EXPECT_EQ(mgr.SubmitFeedback(feedback), RET_OK);
    EXPECT_EQ(g_mock->submitFeedbackCallCount, 1);
}

HWTEST_F(BehaviorAwarenessManagerTest, SubmitFeedback_IpcError, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    g_mock->submitFeedbackRet = SERVICE_EXCEPTION;
    FeedbackData feedback {
        .perceptionEventId = "fb-002",
        .feedbackType = FeedbackType::REJECT,
        .feedbackTime = 2000,
    };
    EXPECT_EQ(mgr.SubmitFeedback(feedback), SERVICE_EXCEPTION);
    EXPECT_EQ(g_mock->submitFeedbackCallCount, 1);
}

/* ==================== ReSubscribe ==================== */

HWTEST_F(BehaviorAwarenessManagerTest, ReSubscribe_EmptyCache_NoRestore, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    mgr.ReSubscribe();
    EXPECT_EQ(g_mock->subscribeCallCount, 0);
}

HWTEST_F(BehaviorAwarenessManagerTest, ReSubscribe_AllRestored, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cbTime = sptr<TestCallback>::MakeSptr();
    auto cbLocation = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cbTime, nullptr);
    ASSERT_NE(cbLocation, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cbTime);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::LOCATION_PATTERN)), cbLocation);
    g_mock->subscribeCallCount = 0;
    mgr.ReSubscribe();
    EXPECT_EQ(g_mock->subscribeCallCount, 2);
}

HWTEST_F(BehaviorAwarenessManagerTest, ReSubscribe_OneIpcFails_Continues, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cbTime = sptr<TestCallback>::MakeSptr();
    auto cbLocation = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cbTime, nullptr);
    ASSERT_NE(cbLocation, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cbTime);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::LOCATION_PATTERN)), cbLocation);
    g_mock->subscribeRet = SERVICE_EXCEPTION;
    g_mock->subscribeCallCount = 0;
    mgr.ReSubscribe();
    EXPECT_EQ(g_mock->subscribeCallCount, 2);
}

HWTEST_F(BehaviorAwarenessManagerTest, ReSubscribe_NullCallbackInCache_Skipped, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb);
    {
        std::lock_guard<std::mutex> lk(mgr.mtx_);
        mgr.subscriptions_["0:1"].callback = nullptr;
        mgr.subscriptions_["0:1"].options = MakeOptions(static_cast<int32_t>(PatternType::LOCATION_PATTERN));
    }
    g_mock->subscribeCallCount = 0;
    mgr.ReSubscribe();
    EXPECT_EQ(g_mock->subscribeCallCount, 1);
}

/* ==================== SaReviveCallback wiring ==================== */

HWTEST_F(BehaviorAwarenessManagerTest, SaReviveCallback_TriggersReSubscribe, TestSize.Level1)
{
    auto &mgr = BehaviorAwarenessManager::GetInstance();
    auto cb = sptr<TestCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    mgr.SubscribePerception(MakeOptions(static_cast<int32_t>(PatternType::TIME_PATTERN)), cb);
    g_mock->subscribeCallCount = 0;
    ASSERT_TRUE(g_mock->saReviveCallback);
    g_mock->saReviveCallback();
    EXPECT_EQ(g_mock->subscribeCallCount, 1);
}

} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
