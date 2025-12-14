/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#include "sequenceable_onscreen_awareness_info.h"
#include "parcel.h"
#include "fi_log.h"
#include "on_screen_data.h"
 
#undef LOG_TAG
#define LOG_TAG "SequenceableOnscreenAwarenessInfoTest"
using namespace testing::ext;
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SequenceableOnscreenAwarenessInfoTest : public testing::Test {
public:
    void SetUp(){};
    void TearDown(){};
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
};
 
/**
 * @tc.name: SequenceableOnscreenAwarenessInfoTest_Marshalling
 * @tc.desc: Check RegisterAwarenessCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableOnscreenAwarenessInfoTest, SequenceableOnscreenAwarenessInfoTest_Marshalling, TestSize.Level1)
{
    auto sequenceableOnscreenAwarenessInfo = std::make_shared<OnScreen::SequenceableOnscreenAwarenessInfo>();
    EXPECT_NE(sequenceableOnscreenAwarenessInfo, nullptr);
    OnScreen::OnscreenEntityInfo entityInfos;
    entityInfos.entityName = "test";
    entityInfos.entityInfo.emplace("test", "test");
    sequenceableOnscreenAwarenessInfo->info_.entityInfo.emplace_back(entityInfos);
    Parcel parcel;
    bool result = sequenceableOnscreenAwarenessInfo->Marshalling(parcel);
    EXPECT_TRUE(result);
}
 
/**
 * @tc.name: SequenceableOnscreenAwarenessCapTest_Unmarshalling
 * @tc.desc: Check Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableOnscreenAwarenessInfoTest, SequenceableOnscreenAwarenessCapTest_Unmarshalling, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    parcel.WriteInt32(1);
    auto sequenceableOnscreenAwarenessInfo = std::make_shared<OnScreen::SequenceableOnscreenAwarenessInfo>();
    EXPECT_NE(sequenceableOnscreenAwarenessInfo, nullptr);
    auto result = sequenceableOnscreenAwarenessInfo->Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS