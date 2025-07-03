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

#include "sequenceable_test.h"

#include "ipc_skeleton.h"
#include "message_parcel.h"

#include "devicestatus_define.h"
#include "i_context.h"


namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
using namespace testing::ext;
namespace {
constexpr int32_t TIME_WAIT_FOR_OP_MS { 20 };
} // namespace

void SequencableTest::SetUpTestCase() {}

void SequencableTest::SetUp() {}
void SequencableTest::TearDown()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

/**
 * @tc.name: SequencableTest1
 * @tc.desc: SequencableTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequencableTest, SequencableTest1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyle;
    PreviewAnimation previewAnimation;
    Parcel parcel;
    SequenceablePreviewAnimation sequenceablePreviewAnimation(previewStyle, previewAnimation);
    bool ret = sequenceablePreviewAnimation.Marshalling(parcel);
    EXPECT_TRUE(ret);
    ASSERT_NO_FATAL_FAILURE(sequenceablePreviewAnimation.Unmarshalling(parcel));
}

/**
 * @tc.name: SequencableTest2
 * @tc.desc: SequencableTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequencableTest, SequencableTest2, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyle;
    Parcel parcel;
    SequenceablePreviewStyle sequenceablePreviewStyle(previewStyle);
    bool ret = sequenceablePreviewStyle.Marshalling(parcel);
    EXPECT_TRUE(ret);
    ASSERT_NO_FATAL_FAILURE(sequenceablePreviewStyle.Unmarshalling(parcel));
}

/**
 * @tc.name: SequencableTest3
 * @tc.desc: SequencableTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequencableTest, SequencableTest3, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DragDropResult dropResult;
    Parcel parcel;
    SequenceableDragResult sequenceableDragResult(dropResult);
    bool ret = sequenceableDragResult.Marshalling(parcel);
    EXPECT_TRUE(ret);
    ASSERT_NO_FATAL_FAILURE(sequenceableDragResult.Unmarshalling(parcel));
}

/**
 * @tc.name: SequencableTest4
 * @tc.desc: SequencableTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequencableTest, SequencableTest4, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool visible = true;
    bool isForce = true;
    std::shared_ptr<Rosen::RSTransaction> rsTransaction = nullptr;
    DragVisibleParam dragVisibleParam;
    dragVisibleParam.visible = visible;
    dragVisibleParam.isForce = isForce;
    dragVisibleParam.rsTransaction = rsTransaction;
    SequenceableDragVisible sequenceableDragVisible(dragVisibleParam);
    Parcel parcel;
    bool ret = sequenceableDragVisible.Marshalling(parcel);
    EXPECT_TRUE(ret);
    ASSERT_NO_FATAL_FAILURE(sequenceableDragVisible.Unmarshalling(parcel));
}

/**
 * @tc.name: SequencableTest5
 * @tc.desc: SequencableTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequencableTest, SequencableTest5, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Rosen::RSTransaction> rsTransaction = nullptr;
    Parcel parcel;
    SequenceableRotateWindow sequenceableRotateWindow(rsTransaction);
    bool ret = sequenceableRotateWindow.Marshalling(parcel);
    EXPECT_FALSE(ret);
    ASSERT_NO_FATAL_FAILURE(sequenceableRotateWindow.Unmarshalling(parcel));
}

/**
 * @tc.name: SequencableTest6
 * @tc.desc: SequencableTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SequencableTest, SequencableTest6, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PreviewStyle previewStyle;
    PreviewAnimation animation;
    Parcel parcel;
    SequenceablePreviewAnimation sequenceablePreviewAnimation(previewStyle, animation);
    bool ret = sequenceablePreviewAnimation.Marshalling(parcel);
    EXPECT_TRUE(ret);
    ASSERT_NO_FATAL_FAILURE(sequenceablePreviewAnimation.Unmarshalling(parcel));
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
