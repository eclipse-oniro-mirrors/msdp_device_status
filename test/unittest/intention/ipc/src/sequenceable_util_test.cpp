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
 
#include "sequenceable_util.h"
#include "pixel_map.h"
#include "on_screen_data.h"
 
#undef LOG_TAG
#define LOG_TAG "SequenceableUtilTest"
using namespace testing::ext;
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SequenceableUtilTest : public testing::Test {
public:
    void SetUp(){};
    void TearDown(){};
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
};
 
/**
 * @tc.name: SequenceableUtilTest_WriteImageId
 * @tc.desc: Check WriteImageId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableUtilTest, SequenceableUtilTest_WriteImageId, TestSize.Level1)
{
    Parcel parcel;
    OnScreen::AwarenessInfoImageId awarenessInfoImageId;
    awarenessInfoImageId.compId = "compIdTest";
    awarenessInfoImageId.arkDataId = "arkDataIdTest";
    std::vector<OnScreen::AwarenessInfoImageId> imageIdArr;
    imageIdArr.emplace_back(awarenessInfoImageId);
 
    auto sequenceableUtil = std::make_shared<SequenceableUtil>();
    EXPECT_NE(sequenceableUtil, nullptr);
    bool result = sequenceableUtil->WriteImageId(parcel, imageIdArr);
    EXPECT_TRUE(result);
}
 
/**
 * @tc.name: SequenceableUtilTest_Marshalling01
 * @tc.desc: Check Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableUtilTest, SequenceableUtilTest_Marshalling01, TestSize.Level1)
{
    Parcel parcel;
    auto sequenceableUtil = std::make_shared<SequenceableUtil>();
    EXPECT_NE(sequenceableUtil, nullptr);
    std::map<std::string, OnScreen::ValueObj> entityInfo;
    bool result = sequenceableUtil->Marshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
 
    bool boolTest = true;
    entityInfo.emplace("boolTest", boolTest);
    result = sequenceableUtil->Marshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
 
    entityInfo.clear();
    int64_t int32Test = 1;
    entityInfo.emplace("int32Test", int32Test);
    result = sequenceableUtil->Marshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
 
    entityInfo.clear();
    int64_t int64Test = 1;
    entityInfo.emplace("int64Test", int64Test);
    result = sequenceableUtil->Marshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
 
    entityInfo.clear();
    std::string strTest = "strTest";
    entityInfo.emplace("strTest", strTest);
    result = sequenceableUtil->Marshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
}
 
/**
 * @tc.name: SequenceableUtilTest_Marshalling02
 * @tc.desc: Check Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableUtilTest, SequenceableUtilTest_Marshalling02, TestSize.Level1)
{
    Parcel parcel;
    std::map<std::string, OnScreen::ValueObj> entityInfo;
    auto sequenceableUtil = std::make_shared<SequenceableUtil>();
    EXPECT_NE(sequenceableUtil, nullptr);
    OnScreen::AwarenessInfoPageLink awarenessInfoPageLink;
    entityInfo.emplace("AwarenessInfoPageLinkTest", awarenessInfoPageLink);
    bool result = sequenceableUtil->Marshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
 
    entityInfo.clear();
    std::shared_ptr<Media::PixelMap> pixelMapPtr = std::make_shared<Media::PixelMap>();
    EXPECT_NE(pixelMapPtr, nullptr);
    entityInfo.emplace("pixelMapTest", pixelMapPtr);
    result = sequenceableUtil->Marshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
 
    entityInfo.clear();
    std::vector<std::string> vectorTest;
    vectorTest.emplace_back("vectorTest");
    entityInfo.emplace("vectorTest", vectorTest);
    result = sequenceableUtil->Marshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
 
    std::vector<OnScreen::AwarenessInfoImageId> awarenessInfoImageIds;
    OnScreen::AwarenessInfoImageId awarenessInfoImageId;
    awarenessInfoImageId.compId = "compIdTest";
    awarenessInfoImageId.arkDataId = "arkDataIdTest";
    awarenessInfoImageIds.emplace_back(awarenessInfoImageId);
    entityInfo.emplace("AwarenessInfoImageIdTest", awarenessInfoImageIds);
    result = sequenceableUtil->Marshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
}
 
/**
 * @tc.name: SequenceableUtilTest_Unmarshalling01
 * @tc.desc: Check Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableUtilTest, SequenceableUtilTest_Unmarshalling01, TestSize.Level1)
{
    Parcel parcel;
    auto sequenceableUtil = std::make_shared<SequenceableUtil>();
    EXPECT_NE(sequenceableUtil, nullptr);
 
    parcel.WriteString("test");
    parcel.WriteInt32(OnScreen::BOOL_INDEX);
    std::map<std::string, OnScreen::ValueObj> entityInfo;
    bool result = sequenceableUtil->Unmarshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
 
    entityInfo.clear();
    parcel.WriteInt32(OnScreen::INT32_INDEX);
    result = sequenceableUtil->Unmarshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(entityInfo.size(), 1);
 
    entityInfo.clear();
    parcel.WriteInt32(OnScreen::INT64_INDEX);
    result = sequenceableUtil->Unmarshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(entityInfo.size(), 1);
 
    entityInfo.clear();
    parcel.WriteInt32(OnScreen::STRING_INDEX);
    result = sequenceableUtil->Unmarshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
}
 
/**
 * @tc.name: SequenceableUtilTest_Unmarshalling02
 * @tc.desc: Check Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableUtilTest, SequenceableUtilTest_Unmarshalling02, TestSize.Level1)
{
    Parcel parcel;
    std::map<std::string, OnScreen::ValueObj> entityInfo;
    auto sequenceableUtil = std::make_shared<SequenceableUtil>();
    EXPECT_NE(sequenceableUtil, nullptr);
 
    parcel.WriteString("test");
    parcel.WriteInt32(OnScreen::PAGE_LINK_INDEX);
    bool result = sequenceableUtil->Unmarshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
 
    entityInfo.clear();
    parcel.WriteInt32(OnScreen::PIXEL_MAP_INDEX);
    result = sequenceableUtil->Unmarshalling(parcel, entityInfo);
    EXPECT_FALSE(result);
    EXPECT_EQ(entityInfo.size(), 0);
 
    entityInfo.clear();
    parcel.WriteInt32(OnScreen::STRING_ARRAY_INDEX);
    result = sequenceableUtil->Unmarshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(entityInfo.size(), 1);
 
    entityInfo.clear();
    parcel.WriteInt32(OnScreen::IMAGEID_ARRAY_INDEX);
    result = sequenceableUtil->Unmarshalling(parcel, entityInfo);
    EXPECT_TRUE(result);
    EXPECT_EQ(entityInfo.size(), 1);
}
 
/**
 * @tc.name: SequenceableUtilTest_ReadImageId
 * @tc.desc: Check ReadImageId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableUtilTest, SequenceableUtilTest_ReadImageId, TestSize.Level1)
{
    Parcel parcel;
    parcel.WriteInt32(1);
    auto sequenceableUtil = std::make_shared<SequenceableUtil>();
    EXPECT_NE(sequenceableUtil, nullptr);
    auto result = sequenceableUtil->ReadImageId(parcel);
    EXPECT_EQ(result.size(), 1);
}
}  // namespace DeviceStatus
}  // namespace Msdp
}  // namespace OHOS