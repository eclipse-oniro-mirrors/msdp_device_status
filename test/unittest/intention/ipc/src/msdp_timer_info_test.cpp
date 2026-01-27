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
#include <ctime>
#include <string>
#include <limits>
#include "msdp_timer_info.h"

namespace OHOS {
namespace Msdp {
using namespace testing::ext;

namespace {
    const uint64_t VALID_TIMESTAMP = 1672531199;
    const uint64_t INVALID_LARGE_TIMESTAMP = static_cast<uint64_t>(std::numeric_limits<time_t>::max()) + 1;
    const uint64_t ZERO_TIMESTAMP = 0;
} // namespace

class MsdpTimerInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static int callbackCount;
    static void TestCallback()
    {
        callbackCount++;
    }
};

int MsdpTimerInfoTest::callbackCount = 0;

void MsdpTimerInfoTest::SetUpTestCase() {}

void MsdpTimerInfoTest::TearDownTestCase() {}

void MsdpTimerInfoTest::SetUp()
{
    callbackCount = 0;
}

void MsdpTimerInfoTest::TearDown() {}

/**
 * @tc.name: Ts2Str_ValidTimestamp_001
 * @tc.desc: Test Ts2Str function with valid timestamp
 * @tc.type: FUNC
 * @tc.require: AR000H8MNE
 */
HWTEST_F(MsdpTimerInfoTest, Ts2Str_ValidTimestamp_001, TestSize.Level1)
{
    MsdpTimerInfo timerInfo;
    std::string result = timerInfo.Ts2Str(VALID_TIMESTAMP);
    EXPECT_NE(result, "Invalid time");
    EXPECT_NE(result, "Invalid time format");
    EXPECT_TRUE(result.find("-") != std::string::npos);
    EXPECT_TRUE(result.find(":") != std::string::npos);
}

/**
 * @tc.name: Ts2Str_ZeroTimestamp_002
 * @tc.desc: Test Ts2Str function with zero timestamp (1970-01-01)
 * @tc.type: FUNC
 * @tc.require: AR000H8MNE
 */
HWTEST_F(MsdpTimerInfoTest, Ts2Str_ZeroTimestamp_002, TestSize.Level1)
{
    MsdpTimerInfo timerInfo;
    std::string result = timerInfo.Ts2Str(ZERO_TIMESTAMP);
    EXPECT_NE(result, "Invalid time");
    EXPECT_NE(result, "Invalid time format");
    EXPECT_TRUE(result.find("1970") != std::string::npos);
}

/**
 * @tc.name: Ts2Str_InvalidLargeTimestamp_003
 * @tc.desc: Test Ts2Str function with timestamp exceeding time_t max
 * @tc.type: FUNC
 * @tc.require: AR000H8MNE
 */
HWTEST_F(MsdpTimerInfoTest, Ts2Str_InvalidLargeTimestamp_003, TestSize.Level1)
{
    MsdpTimerInfo timerInfo;
    std::string result = timerInfo.Ts2Str(INVALID_LARGE_TIMESTAMP);
    EXPECT_EQ(result, "Invalid time");
}

/**
 * @tc.name: Ts2Str_CurrentTime_004
 * @tc.desc: Test Ts2Str function with current time
 * @tc.type: FUNC
 * @tc.require: AR000H8MNE
 */
HWTEST_F(MsdpTimerInfoTest, Ts2Str_CurrentTime_004, TestSize.Level1)
{
    MsdpTimerInfo timerInfo;
    time_t currentTime = std::time(nullptr);
    std::string result = timerInfo.Ts2Str(static_cast<uint64_t>(currentTime));
    EXPECT_NE(result, "Invalid time");
    EXPECT_NE(result, "Invalid time format");
    struct tm tmTime;
    localtime_r(&currentTime, &tmTime);
    char yearBuffer[5];
    std::strftime(yearBuffer, sizeof(yearBuffer), "%Y", &tmTime);
    EXPECT_TRUE(result.find(yearBuffer) != std::string::npos);
}

/**
 * @tc.name: OnTrigger_WithCallback_005
 * @tc.desc: Test OnTrigger function when callback is set
 * @tc.type: FUNC
 * @tc.require: AR000H8MNE
 */
HWTEST_F(MsdpTimerInfoTest, OnTrigger_WithCallback_005, TestSize.Level1)
{
    MsdpTimerInfo timerInfo;
    timerInfo.callback_ = MsdpTimerInfoTest::TestCallback;
    EXPECT_EQ(callbackCount, 0);
    timerInfo.OnTrigger();
    EXPECT_EQ(callbackCount, 1);
    timerInfo.OnTrigger();
    EXPECT_EQ(callbackCount, 2);
}

/**
 * @tc.name: OnTrigger_WithoutCallback_006
 * @tc.desc: Test OnTrigger function when callback is not set
 * @tc.type: FUNC
 * @tc.require: AR000H8MNE
 */
HWTEST_F(MsdpTimerInfoTest, OnTrigger_WithoutCallback_006, TestSize.Level1)
{
    MsdpTimerInfo timerInfo;
    timerInfo.callback_ = nullptr;
    EXPECT_NO_THROW(timerInfo.OnTrigger());
    timerInfo.callback_ = MsdpTimerInfoTest::TestCallback;
    timerInfo.callback_ = nullptr;
    callbackCount = 0;
    timerInfo.OnTrigger();
    EXPECT_EQ(callbackCount, 0);
}

/**
 * @tc.name: Ts2Str_FormatValidation_007
 * @tc.desc: Test Ts2Str function format validation
 * @tc.type: FUNC
 * @tc.require: AR000H8MNE
 */
HWTEST_F(MsdpTimerInfoTest, Ts2Str_FormatValidation_007, TestSize.Level1)
{
    MsdpTimerInfo timerInfo;
    uint64_t testTimestamp = 1672531200;
    std::string result = timerInfo.Ts2Str(testTimestamp);
    EXPECT_EQ(result.length(), 19);
    EXPECT_EQ(result[4], '-');
    EXPECT_EQ(result[7], '-');
    EXPECT_EQ(result[10], ' ');
    EXPECT_EQ(result[13], ':');
    EXPECT_EQ(result[16], ':');
}

/**
 * @tc.name: MsdpTimerInfo_Constructor_008
 * @tc.desc: Test MsdpTimerInfo default constructor
 * @tc.type: FUNC
 * @tc.require: AR000H8MNE
 */
HWTEST_F(MsdpTimerInfoTest, MsdpTimerInfo_Constructor_010, TestSize.Level1)
{
    MsdpTimerInfo timerInfo;
    EXPECT_FALSE(timerInfo.callback_);
    std::string result = timerInfo.Ts2Str(VALID_TIMESTAMP);
    EXPECT_FALSE(result.empty());
    timerInfo.OnTrigger();
}
}  // namespace Msdp
}  // namespace OHOS
