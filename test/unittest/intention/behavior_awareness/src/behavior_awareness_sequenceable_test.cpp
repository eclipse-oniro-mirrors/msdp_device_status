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

#include "behavior_awareness_data.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "message_parcel.h"
#include "sequenceable_feedback_data.h"
#include "sequenceable_subscribe_options.h"

#undef LOG_TAG
#define LOG_TAG "BehaviorAwarenessSequenceableTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace BehaviorAwareness {

using namespace testing::ext;

/* ==================== SequenceableFeedbackData ==================== */

class SequenceableFeedbackDataTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(SequenceableFeedbackDataTest, Marshalling_Success, TestSize.Level1)
{
    FeedbackData data {
        .perceptionEventId = "fb-001",
        .feedbackType = FeedbackType::ACCEPT,
        .feedbackTime = 1000,
    };
    SequenceableFeedbackData seq(data);
    MessageParcel parcel;
    EXPECT_TRUE(seq.Marshalling(parcel));
}

HWTEST_F(SequenceableFeedbackDataTest, ReadFromParcel_Success, TestSize.Level1)
{
    FeedbackData data {
        .perceptionEventId = "fb-002",
        .feedbackType = FeedbackType::REJECT,
        .feedbackTime = 2000,
    };
    SequenceableFeedbackData seq(data);
    MessageParcel parcel;
    ASSERT_TRUE(seq.Marshalling(parcel));

    SequenceableFeedbackData result;
    EXPECT_TRUE(result.ReadFromParcel(parcel));
    EXPECT_EQ(result.data_.perceptionEventId, "fb-002");
    EXPECT_EQ(result.data_.feedbackType, FeedbackType::REJECT);
    EXPECT_EQ(result.data_.feedbackTime, 2000);
}

HWTEST_F(SequenceableFeedbackDataTest, Unmarshalling_Success, TestSize.Level1)
{
    FeedbackData data {
        .perceptionEventId = "fb-003",
        .feedbackType = FeedbackType::EDIT,
        .feedbackTime = 3000,
    };
    SequenceableFeedbackData seq(data);
    MessageParcel parcel;
    ASSERT_TRUE(seq.Marshalling(parcel));

    auto *result = SequenceableFeedbackData::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->data_.perceptionEventId, "fb-003");
    EXPECT_EQ(result->data_.feedbackType, FeedbackType::EDIT);
    EXPECT_EQ(result->data_.feedbackTime, 3000);
    delete result;
}

HWTEST_F(SequenceableFeedbackDataTest, Unmarshalling_EmptyParcel_ReturnsNull, TestSize.Level1)
{
    MessageParcel empty;
    auto *result = SequenceableFeedbackData::Unmarshalling(empty);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(SequenceableFeedbackDataTest, Marshalling_EmptyEventId, TestSize.Level1)
{
    FeedbackData data {
        .perceptionEventId = "",
        .feedbackType = FeedbackType::IGNORE,
        .feedbackTime = 0,
    };
    SequenceableFeedbackData seq(data);
    MessageParcel parcel;
    EXPECT_TRUE(seq.Marshalling(parcel));

    auto *result = SequenceableFeedbackData::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->data_.perceptionEventId, "");
    EXPECT_EQ(result->data_.feedbackType, FeedbackType::IGNORE);
    EXPECT_EQ(result->data_.feedbackTime, 0);
    delete result;
}

HWTEST_F(SequenceableFeedbackDataTest, ReadFromParcel_PartialData_ReadInt32Fails, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteString("fb-partial");
    SequenceableFeedbackData result;
    EXPECT_FALSE(result.ReadFromParcel(parcel));
}

HWTEST_F(SequenceableFeedbackDataTest, ReadFromParcel_PartialData_ReadInt64Fails, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteString("fb-partial");
    parcel.WriteInt32(static_cast<int32_t>(FeedbackType::REJECT));
    SequenceableFeedbackData result;
    EXPECT_FALSE(result.ReadFromParcel(parcel));
}

class SequenceableSubscribeOptionsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(SequenceableSubscribeOptionsTest, Marshalling_Success, TestSize.Level1)
{
    SubscribeOptions options {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = { static_cast<int32_t>(PatternType::TIME_PATTERN) },
    };
    SequenceableSubscribeOptions seq(options);
    MessageParcel parcel;
    EXPECT_TRUE(seq.Marshalling(parcel));
}

HWTEST_F(SequenceableSubscribeOptionsTest, ReadFromParcel_Success, TestSize.Level1)
{
    SubscribeOptions options {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = { static_cast<int32_t>(PatternType::TIME_PATTERN),
                          static_cast<int32_t>(PatternType::LOCATION_PATTERN) },
    };
    SequenceableSubscribeOptions seq(options);
    MessageParcel parcel;
    ASSERT_TRUE(seq.Marshalling(parcel));

    SequenceableSubscribeOptions result;
    EXPECT_TRUE(result.ReadFromParcel(parcel));
    EXPECT_EQ(result.options_.domain, PerceptionDomain::HABIT_AWARENESS);
    EXPECT_EQ(result.options_.patternTypes.size(), 2u);
    EXPECT_EQ(result.options_.patternTypes[0], static_cast<int32_t>(PatternType::TIME_PATTERN));
    EXPECT_EQ(result.options_.patternTypes[1], static_cast<int32_t>(PatternType::LOCATION_PATTERN));
}

HWTEST_F(SequenceableSubscribeOptionsTest, Unmarshalling_Success, TestSize.Level1)
{
    SubscribeOptions options {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = { static_cast<int32_t>(PatternType::EVENT_PATTERN) },
    };
    SequenceableSubscribeOptions seq(options);
    MessageParcel parcel;
    ASSERT_TRUE(seq.Marshalling(parcel));

    auto *result = SequenceableSubscribeOptions::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->options_.domain, PerceptionDomain::HABIT_AWARENESS);
    EXPECT_EQ(result->options_.patternTypes.size(), 1u);
    EXPECT_EQ(result->options_.patternTypes[0], static_cast<int32_t>(PatternType::EVENT_PATTERN));
    delete result;
}

HWTEST_F(SequenceableSubscribeOptionsTest, Unmarshalling_EmptyParcel_ReturnsNull, TestSize.Level1)
{
    MessageParcel empty;
    auto *result = SequenceableSubscribeOptions::Unmarshalling(empty);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(SequenceableSubscribeOptionsTest, ReadFromParcel_PartialData_NoVector, TestSize.Level1)
{
    MessageParcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(PerceptionDomain::HABIT_AWARENESS));
    SequenceableSubscribeOptions result;
    EXPECT_TRUE(result.ReadFromParcel(parcel));
    EXPECT_EQ(result.options_.domain, PerceptionDomain::HABIT_AWARENESS);
    EXPECT_TRUE(result.options_.patternTypes.empty());
}

HWTEST_F(SequenceableSubscribeOptionsTest, Marshalling_EmptyPatternTypes, TestSize.Level1)
{
    SubscribeOptions options {
        .domain = PerceptionDomain::HABIT_AWARENESS,
        .patternTypes = {},
    };
    SequenceableSubscribeOptions seq(options);
    MessageParcel parcel;
    EXPECT_TRUE(seq.Marshalling(parcel));

    auto *result = SequenceableSubscribeOptions::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->options_.domain, PerceptionDomain::HABIT_AWARENESS);
    EXPECT_TRUE(result->options_.patternTypes.empty());
    delete result;
}

} // namespace BehaviorAwareness
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
