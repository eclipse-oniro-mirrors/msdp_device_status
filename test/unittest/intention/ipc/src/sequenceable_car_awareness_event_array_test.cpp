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

#include "sequenceable_car_awareness_event_array.h"
#include "parcel.h"
#include "fi_log.h"
#include "car_awareness_type.h"

#undef LOG_TAG
#define LOG_TAG "SequenceableCarAwarenessEventArrayTest"
using namespace testing::ext;
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SequenceableCarAwarenessEventArrayTest : public testing::Test {
public:
    void SetUp(){};
    void TearDown(){};
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
};

/**
 * @tc.name: SequenceableCarAwarenessEventArrayTest_Marshalling
 * @tc.desc: Check Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessEventArrayTest, SequenceableCarAwarenessEventArrayTest_Marshalling, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    std::vector<CarAwarenessEvent> events = {
        {1, "eventData1"},
        {2, "eventData2"}
    };
    auto sequenceableCarAwarenessEventArray = std::make_shared<SequenceableCarAwarenessEventArray>(events);
    EXPECT_NE(sequenceableCarAwarenessEventArray, nullptr);
    bool result = sequenceableCarAwarenessEventArray->Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SequenceableCarAwarenessEventArrayTest_Unmarshalling
 * @tc.desc: Check Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(
    SequenceableCarAwarenessEventArrayTest, SequenceableCarAwarenessEventArrayTest_Unmarshalling, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    auto result = SequenceableCarAwarenessEventArray::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SequenceableCarAwarenessEventArrayTest_Unmarshalling_NegativeSize
 * @tc.desc: Check Unmarshalling with negative size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessEventArrayTest, SequenceableCarAwarenessEventArrayTest_Unmarshalling_NegativeSize, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    parcel.WriteInt32(-1);
    auto result = SequenceableCarAwarenessEventArray::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: SequenceableCarAwarenessEventArrayTest_Unmarshalling_ZeroSize
 * @tc.desc: Check Unmarshalling with zero size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessEventArrayTest, SequenceableCarAwarenessEventArrayTest_Unmarshalling_ZeroSize, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    parcel.WriteInt32(0);
    auto result = SequenceableCarAwarenessEventArray::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SequenceableCarAwarenessEventArrayTest_MarshallingAndUnmarshalling
 * @tc.desc: Check Marshalling and then Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessEventArrayTest, SequenceableCarAwarenessEventArrayTest_MarshallingAndUnmarshalling, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    std::vector<CarAwarenessEvent> events = {
        {1, "eventData1"},
        {2, "eventData2"}
    };
    auto sequenceableCarAwarenessEventArray = std::make_shared<SequenceableCarAwarenessEventArray>(events);
    EXPECT_NE(sequenceableCarAwarenessEventArray, nullptr);
    bool marshallResult = sequenceableCarAwarenessEventArray->Marshalling(parcel);
    EXPECT_TRUE(marshallResult);
    parcel.RewindRead(0);
    auto unmarshallResult = SequenceableCarAwarenessEventArray::Unmarshalling(parcel);
    EXPECT_NE(unmarshallResult, nullptr);
    if (unmarshallResult != nullptr) {
        EXPECT_EQ(unmarshallResult->events_.size(), events.size());
    }
}
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS
