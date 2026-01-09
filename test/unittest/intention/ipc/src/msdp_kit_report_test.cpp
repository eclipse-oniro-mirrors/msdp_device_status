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

#include "msdp_kit_report.h"
#include "msdp_timer_info.h"

#undef LOG_TAG
#define LOG_TAG "MsdpKitReportTest"

namespace OHOS {
namespace Msdp {
using namespace testing::ext;
constexpr int32_t NON_APP_PROCESSOR_ID = -200;
constexpr uint64_t TIME_STAMP = 0xFFFFFFFFFFFFFFFF;
class MsdpKitReportTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        MsdpKitReport::GetInstance().AddEventProcessor();
    };
    static void TearDownTestCase(){};
    void SetUp(){};
    void TearDown(){};
};

/**
 * @tc.name: MsdpInterfaceEventReport_Test_001
 * @tc.desc: test for MsdpInterfaceEventReport
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportTest, MsdpInterfaceEventReport_Test_001, TestSize.Level1)
{
    MsdpTimerInfo msdpTimerInfo;
    msdpTimerInfo.SetCallback([]() { MsdpKitReport::GetInstance().SchedulerUpload(); });
    msdpTimerInfo.OnTrigger();

    MsdpInterfaceEventInfo msdpInterfaceEventInfo;
    auto result = MsdpKitReport::GetInstance().UpdateMsdpInterfaceEvent(msdpInterfaceEventInfo);
    EXPECT_FALSE(result);
    MsdpKitReport::GetInstance().MsdpInterfaceEventReport();
    EXPECT_EQ(MsdpKitReport::GetInstance().msdpInterfaceEventInfos_.size(), 0);
    msdpInterfaceEventInfo.apiName = "apiName test";
    result = MsdpKitReport::GetInstance().UpdateMsdpInterfaceEvent(msdpInterfaceEventInfo);
    EXPECT_FALSE(result);
    EXPECT_EQ(MsdpKitReport::GetInstance().msdpInterfaceEventInfos_.size(), 0);

    MsdpKitReport::GetInstance().MsdpInterfaceEventReport();
    EXPECT_TRUE(MsdpKitReport::GetInstance().isWatching_);
}

/**
 * @tc.name: SchedulerUpload_Test_002
 * @tc.desc: test for SchedulerUpload
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportTest, SchedulerUpload_Test_002, TestSize.Level1)
{
    MsdpInterfaceEventInfo msdpInterfaceEventInfo;
    msdpInterfaceEventInfo.apiName = "apiName test";
    msdpInterfaceEventInfo.sdkName = "sdkName test";
    auto result = MsdpKitReport::GetInstance().UpdateMsdpInterfaceEvent(msdpInterfaceEventInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(MsdpKitReport::GetInstance().msdpInterfaceEventInfos_.size(), 1);

    msdpInterfaceEventInfo.sdkName = "sdkName";
    result = MsdpKitReport::GetInstance().UpdateMsdpInterfaceEvent(msdpInterfaceEventInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(MsdpKitReport::GetInstance().msdpInterfaceEventInfos_.size(), 1);

    msdpInterfaceEventInfo.apiName = "apiName";
    result = MsdpKitReport::GetInstance().UpdateMsdpInterfaceEvent(msdpInterfaceEventInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(MsdpKitReport::GetInstance().msdpInterfaceEventInfos_.size(), 2);

    MsdpKitReport::GetInstance().MsdpInterfaceEventReport();
    EXPECT_TRUE(MsdpKitReport::GetInstance().isWatching_);
}

/**
 * @tc.name: SchedulerUpload_Test_003
 * @tc.desc: test for SchedulerUpload
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportTest, SchedulerUpload_Test_003, TestSize.Level1)
{
    MsdpKitReport::GetInstance().processorId_ = -1;
    MsdpKitReport::GetInstance().SchedulerUpload();
    EXPECT_NE(MsdpKitReport::GetInstance().processorId_, -1);

    MsdpKitReport::GetInstance().processorId_ = NON_APP_PROCESSOR_ID;
    MsdpKitReport::GetInstance().SchedulerUpload();
    EXPECT_NE(MsdpKitReport::GetInstance().processorId_, -1);

    MsdpKitReport::GetInstance().processorId_ = 1;
    MsdpKitReport::GetInstance().SchedulerUpload();
    EXPECT_NE(MsdpKitReport::GetInstance().processorId_, -1);
}

/**
 * @tc.name: MsdpTimerInfo_Test_004
 * @tc.desc: test for SchedulerUpload
 * @tc.type: FUNC
 */
HWTEST_F(MsdpKitReportTest, MsdpTimerInfo_Test_004, TestSize.Level1)
{
    MsdpTimerInfo msdpTimerInfo;
    auto str = msdpTimerInfo.Ts2Str(TIME_STAMP);
    EXPECT_EQ(str, "Invalid time");
}
}  // namespace Msdp
}  // namespace OHOS