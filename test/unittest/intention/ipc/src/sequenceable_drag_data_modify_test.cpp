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
#include "sequenceable_drag_data.h"

#undef LOG_TAG
#define LOG_TAG "SequenceableDragDataTest"

using namespace testing::ext;
namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SequenceableDragDataTest : public testing::Test {
public:
    void SetUp(){};
    void TearDown(){};
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
};

/**
 * @tc.name: SequenceableDragDataTest_ObjectCreation
 * @tc.desc: Test SequenceableDragData object creation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableDragDataTest, SequenceableDragDataTest_ObjectCreation, TestSize.Level1)
{
    SequenceableDragData sequenceableDragData;
    SUCCEED();
}

/**
 * @tc.name: SequenceableDragDataTest_Marshalling_Call
 * @tc.desc: Test calling Marshalling method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableDragDataTest, SequenceableDragDataTest_Marshalling_Call, TestSize.Level1)
{
    SequenceableDragData sequenceableDragData;
    Parcel parcel;
    bool ret = sequenceableDragData.Marshalling(parcel);
    (void)ret;
    SUCCEED();
}

/**
 * @tc.name: SequenceableDragDataTest_Unmarshalling_Empty
 * @tc.desc: Test Unmarshalling with empty parcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableDragDataTest, SequenceableDragDataTest_Unmarshalling_Empty, TestSize.Level1)
{
    Parcel emptyParcel;
    SequenceableDragData* result = SequenceableDragData::Unmarshalling(emptyParcel);
    
    if (result != nullptr) {
        delete result;
    }
    
    SUCCEED();
}

/**
 * @tc.name: SequenceableDragDataTest_Multiple_Objects
 * @tc.desc: Test creating multiple SequenceableDragData objects
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableDragDataTest, SequenceableDragDataTest_Multiple_Objects, TestSize.Level1)
{
    SequenceableDragData obj1;
    SequenceableDragData obj2;
    SequenceableDragData obj3;

    Parcel p1, p2, p3;
    (void)obj1.Marshalling(p1);
    (void)obj2.Marshalling(p2);
    (void)obj3.Marshalling(p3);
    
    SUCCEED();
}

/**
 * @tc.name: SequenceableDragDataTest_Marshalling_Multiple_Calls
 * @tc.desc: Test calling Marshalling multiple times on same object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequenceableDragDataTest, SequenceableDragDataTest_Marshalling_Multiple_Calls, TestSize.Level1)
{
    SequenceableDragData sequenceableDragData;
    Parcel parcel1;
    (void)sequenceableDragData.Marshalling(parcel1);
    Parcel parcel2;
    (void)sequenceableDragData.Marshalling(parcel2);
    Parcel parcel3;
    (void)sequenceableDragData.Marshalling(parcel3);
    
    SUCCEED();
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS