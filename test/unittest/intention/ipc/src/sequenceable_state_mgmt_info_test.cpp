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

#include "fi_log.h"
#include "mock/mock_parcel_control.h"
#include "on_screen_data.h"
#include "parcel.h"
#include "sequenceable_state_mgmt_info.h"
 
#undef LOG_TAG
#define LOG_TAG "SequenceableStateMgmtInfoTest"
using namespace testing::ext;
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace OnScreen {
class SequenceableStateMgmtInfoTest : public testing::Test {
public:
    void SetUp()
    {
        ResetMockFlags();
    }
    void TearDown()
    {
        ResetMockFlags();
    }
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
};

/**
 * @tc.name: SequenceableStateMgmtInfoTest_Marshalling_001
 * @tc.desc: Marshalling success
 * @tc.type: FUNC
 */
HWTEST_F(SequenceableStateMgmtInfoTest, SequenceableStateMgmtInfoTest_Marshalling_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    StateMgmtInfo info;
    info.componentName = "component";
    info.propertyName = "property";
    info.jsonPath = "path";
    info.onlyVisible = true;
    SequenceableStateMgmtInfo sequenceableInfo(info);
    EXPECT_TRUE(sequenceableInfo.Marshalling(parcel));
}

/**
 * @tc.name: SequenceableStateMgmtInfoTest_Marshalling_002
 * @tc.desc: Marshalling fails when writing componentName
 * @tc.type: FUNC
 */
HWTEST_F(SequenceableStateMgmtInfoTest, SequenceableStateMgmtInfoTest_Marshalling_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    SequenceableStateMgmtInfo sequenceableInfo;
    SetWriteStringFail(true);
    EXPECT_FALSE(sequenceableInfo.Marshalling(parcel));
}

/**
 * @tc.name: SequenceableStateMgmtInfoTest_Marshalling_003
 * @tc.desc: Marshalling fails when writing onlyVisible
 * @tc.type: FUNC
 */
HWTEST_F(SequenceableStateMgmtInfoTest, SequenceableStateMgmtInfoTest_Marshalling_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    SequenceableStateMgmtInfo sequenceableInfo;
    SetWriteBoolFail(true);
    EXPECT_FALSE(sequenceableInfo.Marshalling(parcel));
}

/**
 * @tc.name: SequenceableStateMgmtInfoTest_Unmarshalling_001
 * @tc.desc: Unmarshalling success
 * @tc.type: FUNC
 */
HWTEST_F(SequenceableStateMgmtInfoTest, SequenceableStateMgmtInfoTest_Unmarshalling_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    StateMgmtInfo info;
    info.componentName = "component";
    info.propertyName = "property";
    info.jsonPath = "path";
    info.onlyVisible = true;
    SequenceableStateMgmtInfo sequenceableInfo(info);
    EXPECT_TRUE(sequenceableInfo.Marshalling(parcel));

    auto result = SequenceableStateMgmtInfo::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->stateMgmtInfo_.jsonPath, info.jsonPath);
    EXPECT_EQ(result->stateMgmtInfo_.onlyVisible, info.onlyVisible);
    delete result;
}

/**
 * @tc.name: SequenceableStateMgmtInfoTest_Unmarshalling_002
 * @tc.desc: Unmarshalling fails when reading string
 * @tc.type: FUNC
 */
HWTEST_F(SequenceableStateMgmtInfoTest, SequenceableStateMgmtInfoTest_Unmarshalling_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    SetReadStringFail(true);
    auto result = SequenceableStateMgmtInfo::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: SequenceableStateMgmtInfoTest_Unmarshalling_003
 * @tc.desc: Unmarshalling fails when reading onlyVisible
 * @tc.type: FUNC
 */
HWTEST_F(SequenceableStateMgmtInfoTest, SequenceableStateMgmtInfoTest_Unmarshalling_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    SetReadBoolFail(true);
    auto result = SequenceableStateMgmtInfo::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: SequenceableStateMgmtInfoTest_ReadFromParcel_001
 * @tc.desc: ReadFromParcel success
 * @tc.type: FUNC
 */
HWTEST_F(SequenceableStateMgmtInfoTest, SequenceableStateMgmtInfoTest_ReadFromParcel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    SequenceableStateMgmtInfo sequenceableInfo;
    EXPECT_TRUE(sequenceableInfo.ReadFromParcel(parcel));
}

/**
 * @tc.name: SequenceableStateMgmtInfoTest_ReadFromParcel_002
 * @tc.desc: ReadFromParcel fails when reading string
 * @tc.type: FUNC
 */
HWTEST_F(SequenceableStateMgmtInfoTest, SequenceableStateMgmtInfoTest_ReadFromParcel_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    SequenceableStateMgmtInfo sequenceableInfo;
    SetReadStringFail(true);
    EXPECT_FALSE(sequenceableInfo.ReadFromParcel(parcel));
}

/**
 * @tc.name: SequenceableStateMgmtInfoTest_ReadFromParcel_003
 * @tc.desc: ReadFromParcel fails when reading onlyVisible
 * @tc.type: FUNC
 */
HWTEST_F(SequenceableStateMgmtInfoTest, SequenceableStateMgmtInfoTest_ReadFromParcel_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Parcel parcel;
    SequenceableStateMgmtInfo sequenceableInfo;
    SetReadBoolFail(true);
    EXPECT_FALSE(sequenceableInfo.ReadFromParcel(parcel));
}
}  // namespace OnScreen
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS