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
#include "fi_log.h"
#include "sequenceable_onscreen_awareness_cap.h"
#include "parcel.h"
#include "on_screen_data.h"
 
#undef LOG_TAG
#define LOG_TAG "SequenceableOnscreenAwarenessCapTest"
using namespace testing::ext;
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t MAX_PARA_LEN = 21;
}  // namespace
class SequenceableOnscreenAwarenessCapTest : public testing::Test {
public:
    void SetUp(){};
    void TearDown(){};
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
};
 
/**
 * @tc.name: SequenceableOnscreenAwarenessCapTest_Marshalling01
 * @tc.desc: Check RegisterAwarenessCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableOnscreenAwarenessCapTest, SequenceableOnscreenAwarenessCapTest_Marshalling01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    OnScreen::AwarenessCap cap;
    cap.capList.resize(MAX_PARA_LEN);
    std::shared_ptr<OnScreen::SequenceableOnscreenAwarenessCap> sequenceableOnscreenAwarenessCap =
        std::make_shared<OnScreen::SequenceableOnscreenAwarenessCap>(cap);
    EXPECT_NE(sequenceableOnscreenAwarenessCap, nullptr);
    bool result = sequenceableOnscreenAwarenessCap->Marshalling(parcel);
    EXPECT_FALSE(result);
}
 
/**
 * @tc.name: SequenceableOnscreenAwarenessCapTest_Marshalling02
 * @tc.desc: Check RegisterAwarenessCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableOnscreenAwarenessCapTest, SequenceableOnscreenAwarenessCapTest_Marshalling02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    OnScreen::AwarenessCap cap;
    std::shared_ptr<OnScreen::SequenceableOnscreenAwarenessCap> sequenceableOnscreenAwarenessCap =
        std::make_shared<OnScreen::SequenceableOnscreenAwarenessCap>(cap);
    EXPECT_NE(sequenceableOnscreenAwarenessCap, nullptr);
    cap.capList.emplace_back("Marshalling test");
    bool result = sequenceableOnscreenAwarenessCap->Marshalling(parcel);
    EXPECT_TRUE(result);
}
 
/**
 * @tc.name: SequenceableOnscreenAwarenessCapTest_Unmarshalling01
 * @tc.desc: Check Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableOnscreenAwarenessCapTest, SequenceableOnscreenAwarenessCapTest_Unmarshalling01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    parcel.WriteInt32(MAX_PARA_LEN);
    OnScreen::AwarenessCap cap;
    std::shared_ptr<OnScreen::SequenceableOnscreenAwarenessCap> sequenceableOnscreenAwarenessCap =
        std::make_shared<OnScreen::SequenceableOnscreenAwarenessCap>();
    EXPECT_NE(sequenceableOnscreenAwarenessCap, nullptr);
    auto result = sequenceableOnscreenAwarenessCap->Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}
 
/**
 * @tc.name: SequenceableOnscreenAwarenessCapTest_Unmarshalling02
 * @tc.desc: Check Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableOnscreenAwarenessCapTest, SequenceableOnscreenAwarenessCapTest_Unmarshalling02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    OnScreen::AwarenessCap cap;
    std::shared_ptr<OnScreen::SequenceableOnscreenAwarenessCap> sequenceableOnscreenAwarenessCap =
        std::make_shared<OnScreen::SequenceableOnscreenAwarenessCap>();
    EXPECT_NE(sequenceableOnscreenAwarenessCap, nullptr);
    parcel.WriteInt32(-1);
    auto result = sequenceableOnscreenAwarenessCap->Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}
 
/**
 * @tc.name: SequenceableOnscreenAwarenessCapTest_Unmarshalling03
 * @tc.desc: Check Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableOnscreenAwarenessCapTest, SequenceableOnscreenAwarenessCapTest_Unmarshalling03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    OnScreen::AwarenessCap cap;
    std::shared_ptr<OnScreen::SequenceableOnscreenAwarenessCap> sequenceableOnscreenAwarenessCap =
        std::make_shared<OnScreen::SequenceableOnscreenAwarenessCap>();
    EXPECT_NE(sequenceableOnscreenAwarenessCap, nullptr);
    parcel.WriteInt32(1);
    std::string str = "Unmarshalling test";
    parcel.WriteString(str);
    auto resultLast = sequenceableOnscreenAwarenessCap->Unmarshalling(parcel);
    EXPECT_NE(resultLast, nullptr);
}
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS