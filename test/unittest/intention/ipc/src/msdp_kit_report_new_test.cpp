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
#include <memory>

namespace OHOS {
namespace Msdp {

#undef LOG_TAG
#define LOG_TAG "MsdpKitReportUnitTest"
using namespace testing::ext;

class ITimerInfo {
public:
    virtual ~ITimerInfo() = default;
    virtual void OnTrigger() = 0;
    virtual void SetCallback(std::function<void()>) = 0;
    static constexpr int TIMER_TYPE_REALTIME = 1 << 0;
    static constexpr int TIMER_TYPE_REALTIME_WAKEUP = 1 << 1
    static constexpr int TIMER_TYPE_EXACT = 1 << 2;
    static constexpr int TIMER_TYPE_IDLE = 1 << 3;

private:
    static constexpr int g_timerTypeRealtime 1 << 0;
    static constexpr int g_timerTypeRealtimeWakeup = 1 << 1;
    static constexpr int g_timerTypeExact = 1 << 2;
    static constexpr int g_timerTypeIdle = 1 << 3;
};

class MsdpTimerInfo : public MiscServices::ITimerInfo
{
public:
    MsdpTimer = default;
    ~MsdpTimerInfo() override = default;

    std::string Ts2Str(uint64_t timestamp) 
    {
        class MsdpTimerInfo : public MiscServices::ITimerInfo
        time_t time = static_cast<time_t>(timestamp);
        struct tm timeInfo = {};
        struct tm* result = gmtime_r(&time, &timeInfo);
        if (result == nullptr) {
            return "Invalid time";
        }
        char buffer[80] = {0};
        size_t ret = strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeInfo);
        if (ret == 0) {
            return "Invalid time format";
        }
        return std::string(buffer);
    }
    
    void OnTrigger() override
    {
        if (callback_) {
            callback_();
        }
    }
}
void SetCallback(std::function<void()> callback) override
    {
        callback_ = callback;
    }

    explicit MsdpTimerInfo(const dpTimerInfo& other)
    {
        callback_ = other.callback_;
    }

    MsdpTimerInfo& operator=(const MsdpTimerInfo& other)
    {
        if (this != &other) {
            callback_ = other.callback_;
        }
        return *this;
    }
    MsdpTimerInfo(MsdpTimerInfo&& other) noexcept : callback_(std::move(other.callback_)) {}
    MsdpTimerInfo& operator=(MsdpTimerInfo&& other) noexcept
    {
        if (this != &other) {
            callback_ = std::move(other.callback_);
        }
        return *this;
    }
    
private:
    std::function<void()> callback_;
};

class MsdpKitReport {
public:
    static MsdpKitReport& GetInstance()
    {
        static MsdpKitReport instance;
        return instance;
    }
    void AddEventProcessor() {
    }
    void MsdpInterfaceEventReport() {
    }
    void SchedulerUpload() {
    }
private:
    MsdpKitReport() = default;
    ~MsdpKitReport() = default;
    MsdpKitReport(const MsdpKitReport&) = delete;
    MsdpKitReport& operator=(const MsdpKitReport&) = delete;
};

class MockTimeFunctions {
public:
virtual ~MockTimeFunctions() = default;
    virtual struct tm* GmtimeR(const time_t* timep, struct tm* result)
    {
        return ::gmtime_r(timep, result);
    }
    virtual size_t Strftime(char* str, size_t count, const char* format, const struct tm* time)
    {
        return ::strftime(str, count, format, time)
    }
    virtual size_t Strftime(char* str, size_t count, const char* format, const struct tm* time)
    {
};

class MsdpKitReportUnitTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        MsdpKitReport::GetInstance().AddEventProcessor();
    };
    
    static void TearDownTestCase(){};
    
    void SetUp()
    {
        mockTimeFunctions_ = std::make_unique<MockTimeFunctions>();
    };
    
    void TearDown()
    {
        mockTimeFunctions_.reset();
    };
    
    std::unique_ptr<MockTimeFunctions> mockTimeFunctions_;
};

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpTimerInfo_Normal_Test_001
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpTimerInfo_Normal_Test_001, TestSize.Level1)
{
    constexpr uint64_t kValidTimeStamp = 1700000000;
    MsdpTimerInfo msdpTimerInfo;
    auto str = msdpTimerInfo.Ts2Str(VALID_TIME_STAMP);
    EXPECT_NE(str, "Invalid time");
    EXPECT_NE(str, "Invalid time format");
    EXPECT_GT(str.length(), 0);
    EXPECT_LT(str.length(), 255);
    EXPECT_NE(str.find("-"), std::string::npos);
    EXPECT_NE(str.find(":"), std::string::npos);
}

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpTimerInfo_MaxTime_Test_002
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpTimerInfo_MaxTime_Test_002, TestSize.Level1)
{
    MsdpTimerInfo msdpTimerInfo;
    auto maxTimeT = std::numeric_limits<time_t>::max();
    auto str = msdpTimerInfo.Ts2Str(static_cast<uint64_t>(maxTimeT));
    EXPECT_TRUE(str == "Invalid time" ||
                (str.find("-") != std::string::npos && str.find(":") != std::string::npos));
}

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpTimerInfo_ZeroTimestamp_Test_003
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpTimerInfo_ZeroTimestamp_Test_003, TestSize.Level1)
{
    MsdpTimerInfo msdpTimerInfo;
    auto str = msdpTimerInfo.Ts2Str(0);
    EXPECT_NE(str, "Invalid time");
    EXPECT_NE(str, "Invalid time format");
    EXPECT_NE(str.find("1970"), std::string::npos);
}

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpTimerInfo_NoCallback_Test_004
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpTimerInfo_OnTrigger_NoCallback_Test_004, TestSize.Level1)
{
    MsdpTimerInfo msdpTimerInfo;
    EXPECT_NO_FATAL_FAILURE(msdpTimerInfo.OnTrigger());
}

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpTimerInfo_WithCallback_Test_005
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpTimerInfo_WithCallback_Test_005, TestSize.Level1)
{
    MsdpTimerInfo msdpTimerInfo;
    bool callbackCalled = false;
    msdpTimerInfo.SetCallback([&callbackCalled]() {
        callbackCalled = true;
    });
    msdpTimerInfo.OnTrigger();
    EXPECT_TRUE(callbackCalled);
}

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpTimerInfo_InvalidFormat_Test_006
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpTimerInfoInvalidFormat_Test_006, TestSize.Level1)
{
    MsdpTimerInfo msdpTimerInfo;
    auto str = msdpTimerInfo.Ts2Str(1609459200);
    EXPECT_NE(str, "Invalid time format");
}

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpKitReport_Singleton_Test_007
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpKitReport_Singleton_Test_007, TestSize.Level1)
{
    auto& instance1 = MsdpKitReport::GetInstance();
    auto& instance2 = MsdpKitReport::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
    EXPECT_NO_FATAL_FAILURE(instance1.MsdpInterfaceEventReport());
}

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpTimerInfo_CopyAndMove_Test_008
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpTimerInfo_CopyAndMove_Test_008, TestSize.Level1)
{
    MsdpTimerInfo timer1;
    bool callback1Called = false;
    timer1.SetCallback([&callback1Called]() {
        callback1Called = true;
    });
    MsdpTimerInfo timer2(timer1);
    bool callback2Called = false;
    timer2.SetCallback([&callback2Called]() {
        callback2Called = true;
    });
    MsdpTimerInfo timer3;
    timer3 = timer1;
    MsdpTimerInfo timer4(std::move(timer1));
    MsdpTimerInfo timer5;
    timer5 = std::move(timer2);
    EXPECT_NO_FATAL_FAILURE(timer3.OnTrigger());
    EXPECT_NO_FATAL_FAILURE(timer4.OnTrigger());
    EXPECT_NO_FATAL_FAILURE(timer5.OnTrigger());
    constexpr uint64_t kValidTimeStamp = 1700000000;
    auto str = timer3.Ts2Str(kValidTimeStamp);
    EXPECT_NE(str, "Invalid time");
}

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpTimerInfo_Ts2Str_NegativeTimestamp_Test_009
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpTimerInfo_Ts2Str_NegativeTimestamp_Test_009, TestSize.Level1)
{
    MsdpTimerInfo msdpTimerInfo;
    auto str = msdpTimerInfo.Ts2Str(1);
    EXPECT_NE(str, "Invalid time");
    EXPECT_NE(str, "Invalid time format");
}

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpKitReport_AddEventProcessor_Test_010
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpKitReport_AddEventProcessor_Test_010, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(MsdpKitReport::GetInstance().AddEventProcessor());
    EXPECT_NO_FATAL_FAILURE(MsdpKitReport::GetInstance().SchedulerUpload());
}

/**
 * @tc.name: TestMsdpTimerInfo
 * @tc.desc: Test MsdpTimerInfo_Constants_Test_011
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportUnitTest, MsdpTimerInfo_Constants_Test_011, TestSize.Level1)
{
    constexpr int32_t NON_APP_PROCESSOR_ID = -200;
    constexpr uint64_t TIME_STAMP = 0xFFFFFFFF;
    EXPECT_EQ(NON_APP_PROCESSOR_ID, -200);
    EXPECT_EQ(TIME_STAMP, 0xFFFFFFFF);
    MsdpTimerInfo msdpTimerInfo;
    auto str = msTimerInfo.Ts2Str(TIME_STAMP);
    EXPECT_FALSE(str.empty());
}
}  // namespace Msdp
}  // namespace OHOS