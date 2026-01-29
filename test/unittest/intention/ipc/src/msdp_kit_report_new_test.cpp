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

#include <cstdint>
#include <gtest/gtest.h>
#include <ctime>
#include <limits>
#include <string>
#include <functional>
#include "msdp_timer_info.h"

#undef LOG_TAG
#define LOG_TAG "MsdpTimerUnitTest"

namespace OHOS {
namespace Msdp {
using namespace testing::ext;
namespace {
constexpr int32_t TIMER_TYPE_WAKEUP = 1 << 1;
constexpr int32_t TIMER_TYPE_EXACT = 1 << 2;
constexpr int64_t INTERVAL_HOUR = 12 * 60 * 60;
constexpr int64_t INTERVAL_12_HOURS = 12 * 60 * 60 * 1000;
constexpr int64_t MS_PER_SEC = 1000;
constexpr int32_t ONE_HOUR_SECONDS = 3600;
} // namespace

class TimerUtilTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: TimeStamp_To_String_Normal_Test_001
 * @tc.desc: Test normal timestamp conversion
 * @tc.type: FUNC
 */
HWTEST_F(TimerUtilTest, TimeStamp_To_String_Normal_Test_001, TestSize.Level1)
{
    constexpr uint64_t validTimestamp = 1700000000;
    MsdpTimerInfo timer;
    auto timeStr = timer.Ts2Str(validTimestamp);
    EXPECT_FALSE(timeStr.empty());
    EXPECT_NE(timeStr, "Invalid time");
    EXPECT_NE(timeStr, "Invalid time format");
}

/**
 * @tc.name: TimeStamp_To_String_Zero_Test_002
 * @tc.desc: Test zero timestamp conversion
 * @tc.type: FUNC
 */
HWTEST_F(TimerUtilTest, TimeStamp_To_String_Zero_Test_002, TestSize.Level1)
{
    MsdpTimerInfo timer;
    auto timeStr = timer.Ts2Str(0);
    EXPECT_FALSE(timeStr.empty());
    EXPECT_NE(timeStr, "Invalid time");
    EXPECT_NE(timeStr, "Invalid time format");
}

/**
 * @tc.name: TimeStamp_To_String_Recent_Test_003
 * @tc.desc: Test recent timestamp conversion
 * @tc.type: FUNC
 */
HWTEST_F(TimerUtilTest, TimeStamp_To_String_Recent_Test_003, TestSize.Level1)
{
    MsdpTimerInfo timer;
    time_t current = time(nullptr);
    auto timeStr = timer.Ts2Str(current);
    EXPECT_FALSE(timeStr.empty());
    EXPECT_NE(timeStr, "Invalid time");

    auto futureTime = current + ONE_HOUR_SECONDS;
    timeStr = timer.Ts2Str(futureTime);
    EXPECT_FALSE(timeStr.empty());
}

/**
 * @tc.name: Timer_Constants_Test_004
 * @tc.desc: Test timer constant values
 * @tc.type: FUNC
 */
HWTEST_F(TimerUtilTest, Timer_Constants_Test_004, TestSize.Level1)
{
    EXPECT_EQ(TIMER_TYPE_WAKEUP, 2);
    EXPECT_EQ(TIMER_TYPE_EXACT, 4);
    EXPECT_EQ(INTERVAL_HOUR, 43200);
    EXPECT_EQ(MS_PER_SEC, 1000);
    EXPECT_EQ(TIMER_TYPE_WAKEUP | TIMER_TYPE_EXACT, 6);
}

/**
 * @tc.name: Timer_Type_Settings_Test_006
 * @tc.desc: Test timer type settings
 * @tc.type: FUNC
 */
HWTEST_F(TimerUtilTest, Timer_Type_Settings_Test_006, TestSize.Level1)
{
    MsdpTimerInfo timer;

    EXPECT_NO_FATAL_FAILURE(timer.SetType(TIMER_TYPE_WAKEUP));
    EXPECT_NO_FATAL_FAILURE(timer.SetType(TIMER_TYPE_EXACT));
    EXPECT_NO_FATAL_FAILURE(timer.SetType(TIMER_TYPE_WAKEUP | TIMER_TYPE_EXACT));
    EXPECT_NO_FATAL_FAILURE(timer.SetRepeat(true));
    EXPECT_NO_FATAL_FAILURE(timer.SetRepeat(false));
    EXPECT_NO_FATAL_FAILURE(timer.SetInterval(INTERVAL_12_HOURS));
    EXPECT_NO_FATAL_FAILURE(timer.SetInterval(0));
    EXPECT_NO_FATAL_FAILURE(timer.SetInterval(1000));
}

/**
 * @tc.name: Timer_Invalid_Timestamp_Test_007
 * @tc.desc: Test invalid timestamp conversion
 * @tc.type: FUNC
 */
HWTEST_F(TimerUtilTest, Timer_Invalid_Timestamp_Test_007, TestSize.Level1)
{
    MsdpTimerInfo timer;
    constexpr uint64_t invalidTimestamp = 0xFFFFFFFFFFFFFFFF;
    auto timeStr = timer.Ts2Str(invalidTimestamp);
    EXPECT_TRUE(timeStr == "Invalid time" || timeStr == "Invalid time format");
}

/**
 * @tc.name: Timer_Multiple_Instances_Test_008
 * @tc.desc: Test multiple timer instances
 * @tc.type: FUNC
 */
HWTEST_F(TimerUtilTest, Timer_Multiple_Instances_Test_008, TestSize.Level1)
{
    MsdpTimerInfo timer1;
    MsdpTimerInfo timer2;
    
    bool timer1CallbackCalled = false;
    bool timer2CallbackCalled = false;
    
    timer1.SetCallback([&timer1CallbackCalled]() {
        timer1CallbackCalled = true;
    });
    
    timer2.SetCallback([&timer2CallbackCalled]() {
        timer2CallbackCalled = true;
    });
    
    timer1.OnTrigger();
    EXPECT_TRUE(timer1CallbackCalled);
    EXPECT_FALSE(timer2CallbackCalled);
    
    timer2.OnTrigger();
    EXPECT_TRUE(timer2CallbackCalled);
}

/**
 * @tc.name: Timer_Same_Timestamp_Test_009
 * @tc.desc: Test same timestamp conversion
 * @tc.type: FUNC
 */
HWTEST_F(TimerUtilTest, Timer_Same_Timestamp_Test_009, TestSize.Level1)
{
    MsdpTimerInfo timer1;
    MsdpTimerInfo timer2;
    constexpr uint64_t testTimestamp = 1609459200;
    
    auto timeStr1 = timer1.Ts2Str(testTimestamp);
    auto timeStr2 = timer2.Ts2Str(testTimestamp);
    
    EXPECT_EQ(timeStr1, timeStr2);
    EXPECT_FALSE(timeStr1.empty());
}

/**
 * @tc.name: Timer_Max_Timestamp_Test_010
 * @tc.desc: Test max timestamp conversion
 * @tc.type: FUNC
 */
HWTEST_F(TimerUtilTest, Timer_Max_Timestamp_Test_010, TestSize.Level1)
{
    MsdpTimerInfo timer;
    auto maxTimeT = std::numeric_limits<time_t>::max();
    auto timeStr = timer.Ts2Str(static_cast<uint64_t>(maxTimeT));
    EXPECT_TRUE(timeStr == "Invalid time" || !timeStr.empty());
}
}  // namespace Msdp
}  // namespace OHOS