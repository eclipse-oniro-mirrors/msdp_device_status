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

#include "sequenceable_car_awareness_option.h"
#include "parcel.h"
#include "fi_log.h"
#include "car_awareness_type.h"

#undef LOG_TAG
#define LOG_TAG "SequenceableCarAwarenessOptionTest"
using namespace testing::ext;
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SequenceableCarAwarenessOptionTest : public testing::Test {
public:
    void SetUp() {};
    void TearDown() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
};

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_Marshalling
 * @tc.desc: Check Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_Marshalling, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    auto sequenceableCarAwarenessOption = std::make_shared<SequenceableCarAwarenessOption>();
    EXPECT_NE(sequenceableCarAwarenessOption, nullptr);
    sequenceableCarAwarenessOption->option_.entityInfo.emplace("test", "key=1");
    sequenceableCarAwarenessOption->option_.entityInfo.emplace("test1", "key=true");
    bool result = sequenceableCarAwarenessOption->Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_Unmarshalling
 * @tc.desc: Check Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_Unmarshalling, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    auto sequenceableCarAwarenessOption = std::make_shared<SequenceableCarAwarenessOption>();
    EXPECT_NE(sequenceableCarAwarenessOption, nullptr);
    auto result = sequenceableCarAwarenessOption->Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_Marshalling_IntValue
 * @tc.desc: Check Marshalling with int32_t value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_Marshalling_IntValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    auto sequenceableCarAwarenessOption = std::make_shared<SequenceableCarAwarenessOption>();
    EXPECT_NE(sequenceableCarAwarenessOption, nullptr);
    sequenceableCarAwarenessOption->option_.entityInfo.emplace("intKey", "intField=12345");
    bool result = sequenceableCarAwarenessOption->Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_Marshalling_StringValue
 * @tc.desc: Check Marshalling with string value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_Marshalling_StringValue,
         TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    auto sequenceableCarAwarenessOption = std::make_shared<SequenceableCarAwarenessOption>();
    EXPECT_NE(sequenceableCarAwarenessOption, nullptr);
    sequenceableCarAwarenessOption->option_.entityInfo.emplace("strKey", "strField=test_string_value");
    bool result = sequenceableCarAwarenessOption->Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_Marshalling_BoolValue
 * @tc.desc: Check Marshalling with bool value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_Marshalling_BoolValue, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    auto sequenceableCarAwarenessOption = std::make_shared<SequenceableCarAwarenessOption>();
    EXPECT_NE(sequenceableCarAwarenessOption, nullptr);
    sequenceableCarAwarenessOption->option_.entityInfo.emplace("boolKey", "boolField=true");
    bool result = sequenceableCarAwarenessOption->Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_Unmarshalling002
 * @tc.desc: Check Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_Unmarshalling002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    auto result = SequenceableCarAwarenessOption::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_Unmarshalling_ZeroSize
 * @tc.desc: Check Unmarshalling with zero size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_Unmarshalling_ZeroSize, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    parcel.WriteInt32(0);
    auto result = SequenceableCarAwarenessOption::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_ReadValueObj_DefaultBranch
 * @tc.desc: Test ReadValueObj default branch by directly setting up read order
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_ReadValueObj_DefaultBranch,
         TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto sequenceableCarAwarenessOption = std::make_shared<SequenceableCarAwarenessOption>();
    EXPECT_NE(sequenceableCarAwarenessOption, nullptr);
    Parcel parcel;

    sequenceableCarAwarenessOption->option_.entityInfo.emplace("test", "key=1");
    sequenceableCarAwarenessOption->option_.entityInfo.emplace("test1", "key=true");
    sequenceableCarAwarenessOption->option_.entityInfo.emplace("test2", "key=test");

    sequenceableCarAwarenessOption->Marshalling(parcel);

    auto result = SequenceableCarAwarenessOption::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_Unmarshalling_BoolType
 * @tc.desc: Check Unmarshalling with bool type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_Unmarshalling_BoolType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    parcel.WriteBool(true);
    parcel.WriteInt32(0);
    parcel.WriteString("innerKey");
    parcel.WriteInt32(1);
    parcel.WriteString("key1");
    parcel.WriteInt32(1);
    auto result = SequenceableCarAwarenessOption::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_Unmarshalling_Int32Type
 * @tc.desc: Check Unmarshalling with int32 type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_Unmarshalling_Int32Type,
         TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    parcel.WriteInt32(999);
    parcel.WriteInt32(1);
    parcel.WriteString("innerKey");
    parcel.WriteInt32(1);
    parcel.WriteString("key1");
    parcel.WriteInt32(1);
    auto result = SequenceableCarAwarenessOption::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: SequenceableCarAwarenessOptionTest_Unmarshalling_StringType
 * @tc.desc: Check Unmarshalling with string type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableCarAwarenessOptionTest, SequenceableCarAwarenessOptionTest_Unmarshalling_StringType,
         TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    parcel.WriteString("testString");
    parcel.WriteInt32(2);
    parcel.WriteString("innerKey");
    parcel.WriteInt32(1);
    parcel.WriteString("key1");
    parcel.WriteInt32(1);
    auto result = SequenceableCarAwarenessOption::Unmarshalling(parcel);
    EXPECT_NE(result, nullptr);
}

}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS
